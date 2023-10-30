#################################################################################################################
#####################  AWS Elasticsearch Domain must not be publicly accessible - AUTODESTROY ###################
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
    log_stream_name = 'elasticsearch_not_public'

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

# Get all public Elasticsearch domains
def get_all_domains_without_vpc(es_client):
    """Retrieve all public Elasticsearch domains"""
    try:
        domains_list = es_client.list_domain_names()
        public_domains = []

        for domain in domains_list['DomainNames']:
            domain_config = es_client.describe_elasticsearch_domain(DomainName=domain['DomainName'])
            logger.info(f" Domain Configuration for domain{domain['DomainName']}: {domain_config}")

            is_in_vpc = 'VPCOptions' in domain_config['DomainStatus'] and 'VPCId' in domain_config['DomainStatus']['VPCOptions']

            if not is_in_vpc:
                public_domains.append(domain['DomainName'])

        return public_domains
    except Exception as e:
        logger.error(f"Failed to fetch and filter Elasticsearch domains: {e}")
        raise e

def delete_public_domains_with_check(es_client, domains, account_id, credentials):
    """Delete the provided list of Elasticsearch domains after checking exceptions and sending notifications"""
    for domain in domains:
        try:
            logger.info(f"Attempting to delete Elasticsearch domain: {domain}")
            
            es_client.delete_elasticsearch_domain(DomainName=domain)
            logger.info(f"Successfully deleted Elasticsearch domain: {domain}")
            
            # Notify and log the action
            notify_and_log(domain, domain, account_id, comment=f"Deleted publicly accessible Elasticsearch domain: {domain}")

            logger.info(f"Deleted publicly accessible Elasticsearch domain: {domain}")
            log_to_cloudwatch(f"Deleted publicly accessible Elasticsearch domain: {domain}", credentials)

        except Exception as e:
            logger.error(f"Failed to delete Elasticsearch domain {domain}: {e}")
            log_to_cloudwatch(f"Failed to delete Elasticsearch domain {domain}: {e}")


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
    
    role_arn = f"arn:aws:iam::{account_id}:role/es-remediation"
    assumed_role = assume_role(session, role_arn, 'ESPublicAccessRemediationSession')
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

    # Initiate Elasticsearch client with assumed role
    es_client = boto3.client('es', aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token)

    domain_name = event.get('detail', {}).get('requestParameters', {}).get('domainName', '')
    if not domain_name:
        logger.error("'domainName' not found in the event object.")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: Missing domainName in the event object!')
        }
    
    try:
        # Step 1: Get all publicly accessible domains
        logger.info(f"Fetching publicly accessible Elastisearch domains.")
        domains_without_vpc = get_all_domains_without_vpc(es_client)
        if not domains_without_vpc:
            return {
                'statusCode': 200,
                'body': json.dumps('No publicly accessible Elasticsearch domains found!')
            }

        # Step 2: Delete all found public domains (with exception check and notifications)
        logger.info(f"Attempting to process and delete the following domains: {domains_without_vpc}")
        delete_public_domains_with_check(es_client, domains_without_vpc, account_id, credentials)

        return {
            'statusCode': 200,
            'body': json.dumps('Successfully remediated public Elasticsearch domains!')
        }

    except Exception as e:
        logger.error(f"Error in processing: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(str(e))
        }