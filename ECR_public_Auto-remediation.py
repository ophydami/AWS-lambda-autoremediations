#################################################################################################################
#####################  ECR Repositories must not be publicly accessible - AUTODESTROY                  ##########
#################################################################################################################

import json
import boto3
import logging
import os
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cloudwatch_client = boto3.client('logs')

def assume_role(session, role_arn, role_session_name):
    sts_client = session.client('sts')
    return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)


def log_to_cloudwatch(message, assumed_credentials=None):
    if assumed_credentials:
        cloudwatch_client = boto3.client(
            'logs',
            aws_access_key_id=assumed_credentials["AccessKeyId"],
            aws_secret_access_key=assumed_credentials["SecretAccessKey"],
            aws_session_token=assumed_credentials["SessionToken"]        
        )
    else:
        cloudwatch_client = boto3.client('logs')

    log_group_name = '/aws/security/autoremediation'
    log_stream_name = 'ecr_public'

    # create log group
    try:
        cloudwatch_client.create_log_group(logGroupName=log_group_name)
    except Exception as e:
        logger.debug(str(e))
        pass

    # create log stream
    try:
        cloudwatch_client.create_log_stream(
            logGroupName=log_group_name,
            logStreamName=log_stream_name
        )
    except Exception as e:
        logger.debug(str(e))
        pass

    timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

    try:
        response = cloudwatch_client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[
                {
                    'timestamp': timestamp,
                    'message': message
                }
            ]
        )
    except Exception as e:
        logger.debug(str(e))
        pass

    return

    return len(response.get('Items', [])) > 0

def notify_and_log(remediatedResourceName, remediatedResourceARN, accountID, comment=''):
    # Send to notify cloud sec and log SQS queue
    sqs = boto3.client('sqs', region_name='us-east-1')
    current_time = str(datetime.now())
    session = boto3.session.Session()
    region = session.region_name

    message = {
        "resourceName": remediatedResourceName,
        "resourceId": remediatedResourceARN,
        "accountid": accountID,
        "Timestamp": current_time,
        "functionName": os.environ['FUNCTION_NAME'],
        "region": region,
        "comment": comment
    }

    json_message = json.dumps(message)

    try:
        response = sqs.send_message(
            QueueUrl=os.environ["SQS_QUEUE_URL"],
            MessageBody=json_message
        )

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info("SQS message sent successfully (Received '200')")
            return True
        else:
            logger.warning(str(response))
            return False
    except Exception as e:
        logger.error(str(e))
        return False

def lambda_handler(event, context):
    logger.info(f"Event Received: {json.dumps(event)}")
    # Assume role in the target account
    session = boto3.Session()
    account_id = event.get('detail', {}).get('recipientAccountId', '')
    if not account_id:
        logger.error("account_id not found in the event")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: account_id not found in the event')
        }

    role_arn = f"arn:aws:iam::{account_id}:role/ecr-remediation"
    assumed_role = assume_role(session, role_arn, 'ECRPublicAccessRemediationSession')
    credentials = assumed_role['Credentials']
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]

    # Adaptive retry config
    config = Config(retries={'max_attempts': 10, 'mode': 'adaptive'})
    org = boto3.client(
        'organizations',
        config=config,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )

    # Initiate ECR client with assumed role
    ecr_client = boto3.client('ecr', aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token)

    # Get repository name from event
    repository_name_event = event.get('detail', {}).get('requestParameters', {}).get('repositoryName', '')
    if not repository_name_event:
        logger.error("'repositoryName' not found in the event object.")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: Missing repositoryName in the event object!')
        }

    try:
        # Get the policy of the repository that triggered the event
        policy_text = ecr_client.get_repository_policy(repositoryName=repository_name_event)
        policy_doc = json.loads(policy_text['policyText'])

        is_public = False
        # Check if the policy allows public access
        for statement in policy_doc['Statement']:
            if statement['Effect'] == 'Allow' and 'Principal' in statement and statement['Principal'] == '*':
                is_public = True
                break

        if is_public:
            # If the repository is publicly accessible, delete its policy
            ecr_client.delete_repository_policy(repositoryName=repository_name_event)

            # Notify and log the remediation
            notify_and_log(repository_name_event, repository_name_event, account_id, "Deleted publicly accessible repository")

            log_to_cloudwatch(f"Deleted publicly accessible repository: {repository_name_event}", credentials)

    except ecr_client.exceptions.RepositoryPolicyNotFoundException:
        pass
    except Exception as e:
        # Additional logging to CloudWatch
        log_to_cloudwatch(f"Failed to process repository {repository_name_event}: {e}")
        logger.error(f"Failed to process repository {repository_name_event}: {e}")

    return {
        'statusCode': 200,
        'body': json.dumps(f'Successfully remediated repository: {repository_name_event}!')
    }