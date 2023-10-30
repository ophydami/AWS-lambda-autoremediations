# AWS Security Auto-remediation Lambdas and EventBridge

This repository contains a set of AWS Lambda functions designed to enforce security best practices in your AWS environment. By leveraging AWS EventBridge, these functions automatically trigger and take necessary actions whenever specific non-compliant configurations are detected. The primary goal is to ensure that your AWS resources remain secure and in compliance with recommended best practices.

## Supported Checks and Actions:

1. **AWS Elasticsearch Domain Public Accessibility**  
    - **Check**: Elasticsearch domain must not be publicly accessible.
    - **Action**: AUTODESTROY - The Elasticsearch domain that violates this check will be automatically destroyed.

2. **AWS RDS Instance Public Accessibility**  
    - **Check**: RDS instances must not be publicly accessible.
    - **Action**: AUTOREMEDIATE - The RDS instance will be modified to ensure that it is not publicly accessible.

3. **ECR Repository Public Accessibility**  
    - **Check**: ECR repositories must not be publicly accessible.
    - **Action**: AUTODESTROY - The ECR repository that violates this check will be automatically destroyed.

4. **AWS EKS Cluster Configuration**  
    - **Checks**: 
        - EKS cluster endpoint access must not be publicly enabled.
        - EKS Control Plane Logging must be enabled.
    - **Action**: AUTOREMEDIATION - The EKS cluster will be modified to ensure that the endpoint is not publicly accessible and Control Plane Logging is enabled.

5. **AWS KMS CMK Rotation**  
    - **Check**: KMS CMKs must be rotated once per year.
    - **Action**: AUTOREMEDIATION - The key rotation policy for the KMS CMK will be set to rotate once per year.

6. **AWS Redshift Cluster Public Accessibility**  
    - **Check**: Redshift clusters must not be publicly accessible.
    - **Action**: AUTOREMEDIATE - The Redshift cluster will be modified to ensure that it is not publicly accessible.

7. **AWS ECR Repository Image Scanning**  
    - **Check**: ECR repository's "ScanOnPush" property must be set to true.
    - **Action**: AUTOREMEDIATE - The ECR repository will be modified to ensure that "ScanOnPush" is set to true.

## Prerequisites:

- `sts:AssumeRole:` For the Lambda to assume the target role in the account it needs to perform remediation in.
- `logs:`CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents: For logging to CloudWatch.
- `sqs:SendMessage:` To send messages to the SQS queue for notification purposes.

- ## Required IAM Policies
 To successfully execute these auto-remediation scripts, the following IAM permissions are required:

- ### 1. Elasticsearch Domain Autoremediation:
- `es:DescribeDomain`
- `es:DeleteDomain`

- ### 2. RDS Instance Autoremediation:
- `rds:DescribeDBInstances`
- `rds:ModifyDBInstance`

- ### 3. ECR Repository Autoremediation:
- `ecr:DescribeRepositories`
- `ecr:DeleteRepository`

- ### 4. EKS Cluster Autoremediation:
- `eks:DescribeCluster`
- `eks:UpdateClusterConfig`

- ### 5. KMS CMK Autoremediation:
- `kms:DescribeKey`
- `kms:PutKeyRotationPolicy`

- ### 6. Redshift Cluster Autoremediation:
- `redshift:DescribeClusters`
- `redshift:ModifyCluster`

- ### 7. ECR Repository ScanOnPush Autoremediation:
- `ecr:DescribeRepositories`
- `ecr:PutImageScanningConfiguration`

- ### Additional Permissions:

- Permissions to write logs to CloudWatch for debugging and monitoring:
  - `logs:CreateLogGroup`
  - `logs:CreateLogStream`
  - `logs:PutLogEvents`

- If using AWS SAM or CloudFormation for deployment, the necessary permissions to create and manage the stack resources.

## Sample Role:

Here's a sample IAM role that has the above permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "es:DescribeDomain",
                "es:DeleteDomain",
                "rds:DescribeDBInstances",
                "rds:ModifyDBInstance",
                "ecr:DescribeRepositories",
                "ecr:DeleteRepository",
                "eks:DescribeCluster",
                "eks:UpdateClusterConfig",
                "kms:DescribeKey",
                "kms:PutKeyRotationPolicy",
                "redshift:DescribeClusters",
                "redshift:ModifyCluster",
                "ecr:PutImageScanningConfiguration",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

## EventBridge Patterns

For each remediation to work, you must configure the EventBridge patterns located in `eventbridge_patterns.txt`. These patterns help identify the specific AWS API calls or resource states that should trigger the remediation.


## Deployment

To deploy these Lambda functions and set up EventBridge rules:

1. Ensure you have the AWS CLI and SAM CLI installed. Also you can use Terraform and Cloudformation to deploy this solution.
2. Clone this repository.
3. Navigate to the repository's root directory.
4. Deploy the stack using the SAM CLI:  
   `sam deploy --guided`

5. Follow the on-screen prompts to finalize the deployment.


## Usage

Once deployed, the Lambda functions will automatically start monitoring your environment for non-compliant configurations based on the EventBridge patterns. If a resource violates any of the checks, the specified action will be automatically taken.

## Contributing

If you have suggestions for additional checks or actions or have found a bug, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

Note: Adjustments may be necessary based on the specifics of your Lambda functions, deployment methods, or other details specific to your repository. Remember, following the principle of least privilege, you should further restrict these policies where possible. For example, if you know which specific resources the Lambda function will work on, you can specify those ARNs instead of `"Resource": "*"`.

Ensure that the Lambda functions assume this role during execution. If deploying with SAM or CloudFormation, specify this role in the template. If manually creating the Lambda function via the AWS Management Console, you can choose this role in the "Execution role" section under "Permissions".

