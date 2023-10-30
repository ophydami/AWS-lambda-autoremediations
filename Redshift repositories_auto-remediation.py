#################################################################################################################
#####################  AWS Redshift clusters must not be publicly accessible - AUTOREMEDIATE           ##########
#################################################################################################################

import boto3
import json
import logging
import os
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def assume_role(session, role_arn, role_session_name):
    sts_client = session.client('sts')
    return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)

def create_new_session(credentials):
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]        
    )


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
    log_stream_name = 'redshift_not_public'

    # Create log group and log stream
    try:
        cloudwatch_client.create_log_group(logGroupName=log_group_name)
        cloudwatch_client.create_log_stream(
            logGroupName=log_group_name,
            logStreamName=log_stream_name
        )
    except Exception as e:
        logging.debug(e)
        pass

    timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

    # Put log event
    try:
        cloudwatch_client.put_log_events(
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
        logging.debug(e)
        pass

def notify_and_log(remediatedResourceName, remediatedResourceARN, accountID, comment=''):   
    #Send to notify cloud sec and log SQS queue
    sqs = boto3.client('sqs', region_name = 'us-east-1')
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
            QueueUrl = os.environ["SQS_QUEUE_URL"],
            MessageBody= json_message
        )
       
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logging.info("SQS message sent successfully (Received '200')")
            return True
        else:
            logging.warning(str(response))
            return False
    except Exception as e:
        logging.error(str(e))
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
    
    role_arn = f"arn:aws:iam::{account_id}:role/redshift-remediation"
    assumed_role = assume_role(session, role_arn, 'RedshiftRemediationSession')
    credentials = assumed_role['Credentials']
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]

    # Addaptive retry config
    config = Config(retries={'max_attempts': 10, 'mode': 'adaptive'})
    org = boto3.client(
        'organizations',
        config=config,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )

    # Initiate Redshift client with assumed role
    redshift_client = boto3.client('redshift', aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token)
    
    cluster_identifier = event.get('detail', {}).get('requestParameters', {}).get('clusterIdentifier', '')
    if not cluster_identifier:
        logger.error("'clusterIdentifier' not found in the event object.")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: Missing clusterIdentifier in the event object!')
        }
    
    clusters = None
    try:
        # Get all Redshift clusters
        clusters = redshift_client.describe_clusters()
    except Exception as e:
        logger.error(f"Failed to describe Redshift clusters: {e}")
        log_to_cloudwatch(f"Failed to describe Redshift clusters: {e}")  # Log the error to CloudWatch
        raise e
    
    if clusters:
        for cluster in clusters.get('Clusters', []):
            try:
                # Check if the Redshift cluster is publicly accessible
                if cluster['PubliclyAccessible']:
                    logger.warning(f"Redshift cluster {cluster['ClusterIdentifier']} is publicly accessible")
                    log_to_cloudwatch(f"Redshift cluster {cluster['ClusterIdentifier']} is publicly accessible", credentials)  # Log the error to CloudWatch
                    try:
                        # Modify Redshift cluster to be not publicly accessible
                        redshift_client.modify_cluster(
                            ClusterIdentifier=cluster['ClusterIdentifier'],
                            PubliclyAccessible=False
                        )
                        logger.info(f"Modified Redshift cluster {cluster['ClusterIdentifier']} to be not publicly accessible")
                        log_to_cloudwatch(f"Modified Redshift cluster {cluster['ClusterIdentifier']} to be not publicly accessible", credentials)
                        notify_and_log(cluster['ClusterIdentifier'], cluster['ClusterIdentifier'], account_id, "Redshift cluster modified to be not publicly accessible.")  # Notify for modified clusters
                        
                    except Exception as modify_e:
                        logger.error(f"Failed to modify Redshift cluster {cluster['ClusterIdentifier']}: {modify_e}")

            except Exception as e:
                logger.error(f"Failed to process Redshift cluster {cluster['ClusterIdentifier']}: {e}")
                log_to_cloudwatch(f"Failed to process Redshift cluster {cluster['ClusterIdentifier']}: {e}")  # Log the error to CloudWatch
                continue

        return {
            'statusCode': 200,
            'body': json.dumps('Finished checking Redshift clusters public accessibility!')
        }
