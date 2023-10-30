################################################################################################################
#####################  AWS KMS CMKs automatically rotated once per year - AUTOREMEDIATION             ##########
################################################################################################################

import boto3
import json
import logging
import os
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import Dict, Any


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
    log_stream_name = 'cmk_kms_rotation'

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


def process_kms_key(kms_client, key_id, account_id, credentials):
    try:
        key_rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)        
        if not key_rotation_status['KeyRotationEnabled']:
            logger.warning(f"Key rotation is not enabled for KMS key {key_id}")           
            try:
                kms_client.enable_key_rotation(KeyId=key_id)
                logger.info(f"Enabled rotation for KMS key {key_id}")                
                # Notify & log successful rotation enablement
                notify_and_log(key_id, key_id, account_id, "Enabled key rotation")
                log_to_cloudwatch(f"Enabled rotation for KMS key {key_id}", credentials)                
            except Exception as e:
                logger.error(f"Failed to enable rotation for KMS key {key_id}: {e}")
                kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
                logger.info(f"Scheduled deletion for KMS key {key_id}")               
                # Notify & log scheduled deletion
                notify_and_log(key_id, key_id, account_id, "Scheduled key for deletion due to failure in enabling rotation")
        else:
            logger.info(f"Key rotation is already enabled for KMS key {key_id}")
    except Exception as e:
        logger.error(f"Failed to process KMS key {key_id}: {e}")
        log_to_cloudwatch(f"Failed to process KMS key {key_id}: {e}")  # Log to CloudWatch
        # Continue with next key
        pass

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
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
    
    role_arn = f"arn:aws:iam::{account_id}:role/kms-remediation"
    assumed_role = assume_role(session, role_arn, 'KMSPublicAccessRemediationSession')
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

    # Initiate KMS client with assumed role
    kms_client = boto3.client('kms', aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token)

    key_id = ( 
        event.get('detail', {}).get('responseElements', {}).get('keyMetadata', {}).get('keyId', '') or
        event.get('detail', {}).get('requestParameters', {}).get('keyId', '')
    )
    if not key_id:
        logger.error("'keyId' not found in the event object.")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: Missing keyId in the event object!')
        }
    try:
        process_kms_key(kms_client, key_id, account_id, credentials)
    except Exception as e:
        logger.error(f"Failed to list or process KMS keys: {e}")
        log_to_cloudwatch(f"Failed to list or process KMS keys: {e}")  # Log to CloudWatch

    return {
        'statusCode': 200,
        'body': json.dumps('Finished checking KMS keys rotation!')
    }