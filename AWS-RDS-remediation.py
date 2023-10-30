#################################################################################################################
#####################  AWS RDS instances must not be publicly accessible - AUTOREMEDIATE               ##########
#################################################################################################################

import boto3
import json
import logging
import os
import time
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
    log_stream_name = 'rds_not_public'

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
    
    role_arn = f"arn:aws:iam::{account_id}:role/travrol-rds-remediation"
    assumed_role = assume_role(session, role_arn, 'RDSPublicAccessRemediationSession')
    credentials = assumed_role['Credentials']
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]

    rds_client = boto3.client(
        'rds',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    
    db_instance_identifier = event.get('detail', {}).get('requestParameters', {}).get('dBInstanceIdentifier', '')
    if not db_instance_identifier:
        logger.error("'dBInstanceIdentifier' not found in the event object.")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: Missing dBInstanceIdentifier in the event object!')
        }

    try:
        # Add waiter to wait for the DB instance to become available after modifications
        waiter = rds_client.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=db_instance_identifier)

        # Optional: Add a delay for safe measure, adjust as necessary
        time.sleep(60)  # Sleeps for 60 seconds

        instance = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)['DBInstances'][0]
        if instance['PubliclyAccessible']:
            rds_client.modify_db_instance(
                DBInstanceIdentifier=instance['DBInstanceIdentifier'],
                PubliclyAccessible=False,
                ApplyImmediately=True
            )
            logger.info(f"Modified RDS instance {instance['DBInstanceIdentifier']} to be not publicly accessible")
            log_to_cloudwatch(f"Modified RDS instance {instance['DBInstanceIdentifier']} to be not publicly accessible", credentials)
            notify_and_log(instance['DBInstanceIdentifier'], instance['DBInstanceArn'], account_id, "Modified to not be publicly accessible")
    except Exception as e:
        logger.error(f"Error during remediation of {db_instance_identifier}: {e}")
        return {
            'statusCode': 400,
            'body': json.dumps(f"Error during remediation of {db_instance_identifier}: {e}")
        }

    return {
        'statusCode': 200,
        'body': json.dumps('Finished checking RDS instance public accessibility!')
    }
