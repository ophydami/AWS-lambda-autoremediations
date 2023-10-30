#######################################################################################################################################################
#####################  AWS EKS cluster endpoint access should not be publicly enabled  and EKS Control Plane Logging be enabled - AUTOREMEDATION  #####
#######################################################################################################################################################

import boto3
import json
import logging
import time
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
    log_stream_name = 'eks_controlplane_not_public'

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

def enable_logging(client, cluster_name):
    try:
        client.update_cluster_config(
            name=cluster_name,
            logging={
                'clusterLogging': [{
                    'types': [
                        'api',
                        'audit',
                        'authenticator',
                        'controllerManager',
                        'scheduler'
                    ],
                    'enabled': True
                }]
            }
        )
        # Wait for the cluster to become active after enabling logging
        waiter = client.get_waiter('cluster_active')
        waiter.wait(name=cluster_name)

        # Add a delay for extra assurance
        time.sleep(60)  # Sleeps for 60 seconds

        return True
    except ClientError as e:
        logger.error(f"Failed to enable logging for cluster {cluster_name}: {str(e)}")
        return False

def check_and_remediate_clusters(credentials, cluster_name):
    eks_session = create_new_session(credentials)
    client = eks_session.client('eks')

    actions = []

    # Describe the cluster using the provided name
    cluster = client.describe_cluster(name=cluster_name)['cluster']

    # If cluster is in 'CREATING' or 'UPDATING' state, wait until it's 'ACTIVE' 
    if cluster.get('status') in ['CREATING', 'UPDATING']:
        try:
            waiter = client.get_waiter('cluster_active')
            waiter.wait(name=cluster_name)
            time.sleep(60)  # Sleeps for 60 seconds for extra assurance
        except Exception as e:
            actions.append(f"Error waiting for {cluster_name} to become active: {str(e)}")
            return ', '.join(actions)

    # Check and enable control plane logging if it's not enabled
    logging_enabled = any(
        log_type.get('enabled') for log_type in cluster.get('logging', {}).get('clusterLogging', [])
    )
    if not logging_enabled:
        if enable_logging(client, cluster_name):
            actions.append(f"Enabled control plane logging for {cluster_name}")
            # Wait for the cluster to become active after updating logging
            waiter = client.get_waiter('cluster_active')
            waiter.wait(name=cluster_name)
            time.sleep(60)  # Sleeps for 60 seconds for extra assurance

    # Check and update cluster's resourcesVpcConfig if endpointPublicAccess is True
    resources_vpc_config = cluster.get('resourcesVpcConfig')
    if resources_vpc_config.get('endpointPublicAccess', False):
        updated_vpc_config = {
            'endpointPublicAccess': False,
            'endpointPrivateAccess': True
        }
        try:
            client.update_cluster_config(
                name=cluster_name,
                resourcesVpcConfig=updated_vpc_config
            )
            # Wait for the cluster to become active after updating VPC config
            waiter = client.get_waiter('cluster_active')
            waiter.wait(name=cluster_name)
            time.sleep(60)  # Sleeps for 60 seconds for extra assurance
            actions.append(f"Updated {cluster_name} (Public Access disabled, Private Access enabled)")
        except ClientError as e:
            actions.append(f"Error updating cluster resource VPC config for {cluster_name}: {str(e)}")

    return ', '.join(actions)


def lambda_handler(event, context):
    if event.get('detail', {}).get('errorCode') or event.get('detail', {}).get('errorMessage'):
        # do nothing - this is error logged by cloudtrail
        logger.info("Error event (nothing to do). Exiting. ")
        return
    
    logger.info(f"Event Received: {json.dumps(event)}")
    
    if event.get('errorCode') or event.get('errorMessage'):
        # do nothing - this is error logged by cloudtrail
        return
    
    # Adding sleep to mitigate the potential race condition
    time.sleep(60)
    
    # Assume role in the target account
    session = boto3.Session()
    account_id = event.get('detail', {}).get('recipientAccountId', '')
    if not account_id:
        logger.error("account_id not found in the event")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: account_id not found in the event')
        }
    
    cluster_name = event.get('detail', {}).get('requestParameters', {}).get('name')
    if not cluster_name:
        logger.error("Cluster name not found in the event")
        return {
            'statusCode': 400,
            'body': json.dumps('Error: Cluster name not found in the event')
        }
    
    role_arn = f"arn:aws:iam::{account_id}:role/eks-remediation"
    assumed_role = assume_role(session, role_arn, 'EKSPublicAccessRemediationSession')
    credentials = assumed_role['Credentials']
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]

    actions_taken = check_and_remediate_clusters({
        'AccessKeyId': access_key,
        'SecretAccessKey': secret_key,
        'SessionToken': session_token
    }, cluster_name)
    
    # Get the ARN of the cluster after remediation actions
    eks_session = create_new_session(credentials)
    client = eks_session.client('eks')
    cluster = client.describe_cluster(name=cluster_name)['cluster']
    cluster_arn = cluster['arn']

    # Notify about the remediation actions taken
    actions_msg = f'Successfully attempted update on cluster {cluster_name} in account {account_id}. Actions: {actions_taken}'
    log_to_cloudwatch(actions_msg, credentials)
    notify_and_log(cluster_name, cluster_arn, account_id, actions_msg)

    return {
        'statusCode': 200,
        'body': actions_msg
    }