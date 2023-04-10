# pylint: disable = C0103, R0902
"""
This file contains the code for the Lambda function that handles
the provisioning, updating, and deleting of resources for the
S3 Encryption solution. This code is also executed when an S3 Event
Notification is triggered from the uploading of a completed S3 Inventory
manifest file. All in all, it holds all of the logic required for the
S3 Encryption solution to work.
"""
import os
import json
import logging
import boto3
from botocore.exceptions import ClientError
import urllib3
from urllib.parse import unquote_plus


logger = logging.getLogger()
logger.setLevel(logging.INFO)


######################################################################
#                      LOGGING HELPER FUNCTIONS                      #
######################################################################

def info(msg):
    """
    Helper function to log informational messages.
    """
    logger.info(json.dumps({'info': msg}))


def error(msg):
    """
    helper function to log error messages.
    """
    if isinstance(msg, ClientError):
        logger.error(json.dumps({'error': msg.response['Error']['Code']}))
    else:
        logger.error(json.dumps(
            {'error': f'An unexpected error occurred: {repr(msg)}'}))

######################################################################
#                        CLASS DEFINITION                            #
######################################################################


class Encryptor:
    """
    Encryptor Controller class. Handles all resource creation/configuration
    operations and logic.
    """

    # INIT

    def __init__(self, event, context):

        if event.get('Records'):
            # EVENT NOTIFICATION
            self.e_tag = event['Records'][0]['s3']['object']['eTag']
            self.manifest = event['Records'][0]['s3']['object']['key']

        self.role_arn = os.environ.get('RoleArn')
        self.reporting_level = os.environ.get('ReportingLevel')
        self.database_name = os.environ.get('DBName')
        self.table_name_inv = os.environ.get('TBLNameInv')
        self.table_name_batch = os.environ.get('TBLNameBatch')
        self.s3_target_tag_key = os.environ.get('S3TargetTagKey')
        self.s3_target_tag_value = os.environ.get('S3TargetTagValue')
        self.s3_target_buckets = []
        self.s3_event_id_inv = os.environ.get('S3EventIdInv')
        self.s3_event_id_batch = os.environ.get('S3EventIdBatch')
        self.remove_s3_inventory_config = os.environ.get('RemoveS3InvConfig')
        self.encrypt = os.environ.get('Encrypt')
        self.account_id = boto3.client('sts').get_caller_identity()['Account']
        self.s3_inv_reports_bucket = os.environ.get("S3InvReportsBucket")
        self.s3_batch_reports_bucket = os.environ.get("S3BatchReportsBucket")
        self.kms_key_id = os.environ.get('KmsKey')
        self.sse_type = os.environ.get('SSEType')
        self.inventories_name = os.environ.get('S3InventoriesName')
        self.deployment_region = os.environ.get('DeploymentRegion')
        self.function_arn = context.invoked_function_arn
        self.add_tag_to_objects = os.environ.get('AddTag')
        self.object_tag_key = os.environ.get('ObjectTagKey')
        self.object_tag_value = os.environ.get('ObjectTagValue')

    def __set_target_buckets(self):
        """
        Get the list of S3 buckets for which we will be analyzing object
        encryption status. Only buckets that have the correct tagging will be
        analyzed.
        """

        s3 = boto3.client('s3', region_name=self.deployment_region)

        self.s3_target_buckets = []

        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            try:
                bucket_location = s3.get_bucket_location(Bucket=bucket['Name'])
                if bucket_location.get('LocationConstraint'):
                    bucket_location = bucket_location['LocationConstraint']
                else:
                    # The value of the bucket location is weirdly 'None' if the bucket
                    # is located in us-east-1
                    bucket_location = 'us-east-1'

                # Make sure that we are only processing buckets that are in the
                # same region as the deployment region
                if bucket_location == self.deployment_region:

                    try:
                        tag_set = s3.get_bucket_tagging(
                            Bucket=bucket['Name'])['TagSet']

                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchTagSet':
                            raise e
                        # No tags exist for the bucket. Skip it.
                        continue
                    for tag in tag_set:
                        if tag['Key'] == self.s3_target_tag_key and tag['Value'] == self.s3_target_tag_value:  # pylint: disable = C0301
                            # Tag is matched. Append it to the list.
                            self.s3_target_buckets.append(bucket['Name'])
                            break
            except Exception:
                logger.error(json.dumps(
                    {'error': f'unable to get bucket location for {bucket["Name"]}'}))

    def __set_up_inv_reports_bucket(self):
        """
        Creates the bucket in which S3 inventory reports will be placed and
        configures the bucket policy properly.
        """

        tb = [f'arn:aws:s3:::{b}' for b in self.s3_target_buckets]

        bucket_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'S3InventoryPermissions',
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 's3.amazonaws.com'
                    },
                    'Action': 's3:PutObject',
                    'Resource': f'arn:aws:s3:::{self.s3_inv_reports_bucket}/*',
                    'Condition': {
                        'StringEquals': {
                            'aws:SourceAccount': f'{self.account_id}',
                            's3:x-amz-acl': 'bucket-owner-full-control'
                        },
                        'ArnLike': {
                            'aws:SourceArn': tb
                        }
                    }
                }
            ]
        }

        s3 = boto3.client('s3', region_name=self.deployment_region)

        # Place bucket policy onto the reporting bucket that allows
        # other buckets to place into the reporting bucket
        # their S3 inventory reports.
        s3.put_bucket_policy(
            Bucket=self.s3_inv_reports_bucket,
            Policy=json.dumps(bucket_policy)
        )

    def __set_up_s3_event_notifications(self, bucket_name, event_id):
        """
        S3 PUT Object event notifications are configured, which will
        identify when a new manifest file is uploaded either for an 
        S3 Inventory report or an S3 Batch job completion report.
        """

        s3 = boto3.client('s3', region_name=self.deployment_region)

        # Grab existing notification configurations so that they are not overwritten
        configs = s3.get_bucket_notification_configuration(
            Bucket=bucket_name)
        new_configs = {k: v for k, v in configs.items() if k !=
                       'ResponseMetadata'}
        if not new_configs.get('LambdaFunctionConfigurations'):
            new_configs['LambdaFunctionConfigurations'] = []
        else:
            for config in new_configs['LambdaFunctionConfigurations']:
                if config.get('Id') == event_id:
                    # remove any existing event Id that might have the same
                    # name as our new one.
                    new_configs['LambdaFunctionConfigurations'].remove(config)
                    break
        new_configs['LambdaFunctionConfigurations'].append(
            {
                'Id': event_id,
                'LambdaFunctionArn': self.function_arn,
                'Events': ['s3:ObjectCreated:Put'],
                'Filter': {
                    'Key': {
                        'FilterRules': [
                            {
                                'Name': 'suffix',
                                'Value': 'manifest.json'
                            }]}}}
        )
        # Set up an S3 event notification to trigger every time a
        # new Inventory report is uploaded.
        s3.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration=new_configs
        )

    def __set_up_s3_inventory_configurations(self):
        """
        Sets up S3 inventory for each bucket specified with the designated tag.
        The inventory reports will be sent to the central report bucket.
        """

        s3 = boto3.client('s3', region_name=self.deployment_region)

        # determine what type of encryption to use for S3 inventory reports
        encryption = {}
        if self.sse_type == 'SSE-S3':
            encryption = {'SSES3': {}}
        elif self.sse_type == 'SSE-KMS':
            encryption = {'SSEKMS': {
                'KeyId': f'arn:aws:kms:{self.deployment_region}:{self.account_id}:key/{self.kms_key_id}'}}

        for bucket in self.s3_target_buckets:

            try:
                s3.delete_bucket_inventory_configuration(
                    Bucket=bucket,
                    Id=self.inventories_name
                )
            except ClientError as e:
                if not e.response['Error']['Code'] == 'NoSuchConfiguration':
                    raise e

            s3.put_bucket_inventory_configuration(
                Bucket=bucket,
                Id=self.inventories_name,
                InventoryConfiguration={
                    'Destination': {
                        'S3BucketDestination': {
                            'AccountId': self.account_id,
                            'Bucket': f'arn:aws:s3:::{self.s3_inv_reports_bucket}',
                            'Format': 'CSV',
                            'Encryption': encryption
                        }
                    },
                    'IsEnabled': True,
                    'Id': self.inventories_name,
                    'IncludedObjectVersions': 'Current',
                    'OptionalFields': [
                        'EncryptionStatus'
                    ],
                    'Schedule': {
                        'Frequency': 'Daily'
                    }
                }
            )

    def __set_up_s3_inventory_configuration(self, bucket):
        """
        Sets up S3 inventory for the bucket specified with the designated tag.
        The inventory report will be sent to the central report bucket.
        """

        s3 = boto3.client('s3', region_name=self.deployment_region)

        # determine what type of encryption to use for S3 inventory reports
        encryption = {}
        if self.sse_type == 'SSE-S3':
            encryption = {'SSES3': {}}
        elif self.sse_type == 'SSE-KMS':
            encryption = {'SSEKMS': {
                'KeyId': f'arn:aws:kms:{self.deployment_region}:{self.account_id}:key/{self.kms_key_id}'}}

        s3.put_bucket_inventory_configuration(
            Bucket=bucket,
            Id=self.inventories_name,
            InventoryConfiguration={
                'Destination': {
                    'S3BucketDestination': {
                        'AccountId': self.account_id,
                        'Bucket': f'arn:aws:s3:::{self.s3_inv_reports_bucket}',
                        'Format': 'CSV',
                        'Encryption': encryption
                    }
                },
                'IsEnabled': True,
                'Id': self.inventories_name,
                'IncludedObjectVersions': 'Current',
                'OptionalFields': [
                    'EncryptionStatus'
                ],
                'Schedule': {
                    'Frequency': 'Daily'
                }
            }
        )

    def __remove_s3_inventory_configurations(self):
        """
        Removes all S3 Inventory configurations for target buckets. This occurs when the
        CloudFormation stack is being torn down."""

        s3 = boto3.client('s3', region_name=self.deployment_region)

        for bucket in self.s3_target_buckets:
            try:
                s3.delete_bucket_inventory_configuration(
                    Bucket=bucket,
                    Id=self.inventories_name
                )
            except ClientError as e:
                if not e.response['Error']['Code'] == 'NoSuchConfiguration':
                    raise e

    def __remove_s3_inventory_configuration(self, bucket):
        """
        Removes the S3 Inventory configuration for the bucket that completed
        its report and uploaded it to the reporting bucket, triggering the event
        notification. It also updates the bucket policy on the reports bucket
        to remove the ARN of the bucket that had its S3 Inventory report removed.
        When enabled, this will ensure that inventory configurations will be automatically
        deleted after a batch processing job is triggered against their findings.
        """

        s3 = boto3.client('s3', region_name=self.deployment_region)
        try:
            s3.delete_bucket_inventory_configuration(
                Bucket=self.manifest.split('/')[0],
                Id=self.inventories_name
            )
        except ClientError as e:
            if not e.response['Error']['Code'] == 'NoSuchConfiguration':
                raise e
        try:
            existing_policy = s3.get_bucket_policy(
                Bucket=self.s3_inv_reports_bucket)
            existing_statement = json.loads(
                existing_policy['Policy'])['Statement']
            for i, statement in enumerate(existing_statement):
                if statement.get('Sid') == 'S3InventoryPermissions':
                    current_arns = statement['Condition']['ArnLike']['aws:SourceArn']
                    # Still multiple ARNs in the bucket policy
                    if isinstance(current_arns, list):
                        current_arns.remove(
                            f'arn:aws:s3:::{self.manifest.split("/")[0]}')
                        statement['Condition']['ArnLike']['aws:SourceArn'] = current_arns
                        existing_statement[i] = statement
                    # Only one ARN left
                    elif isinstance(current_arns, str):
                        statement['Condition']['ArnLike']['aws:SourceArn'] = []
                        existing_statement[i] = statement
                    break

            bucket_policy = {
                'Version': '2012-10-17',
                'Statement': existing_statement
            }
            s3.put_bucket_policy(
                Bucket=self.s3_inv_reports_bucket,
                Policy=json.dumps(bucket_policy)
            )

        except ClientError as e:
            # If no Bucket policies exist, that's fine. Other errors we should raise
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                raise e

    def __trigger_batch_job(self):
        """
        The event notification triggers an S3 batch job when
        a new S3 Inventory report is added to the report bucket.
        """

        s3_control = boto3.client(
            's3control', region_name=self.deployment_region)

        if self.add_tag_to_objects == 'yes':

            info('batch job will add tags to copied over objects')
            operation = {
                'LambdaInvoke': {
                    'FunctionArn': self.function_arn
                }
            }
        else:

            info('batch job will not add tags to copied over objects')
            operation = {
                'S3PutObjectCopy': {
                    'TargetResource': f'arn:aws:s3:::{self.manifest.split("/")[0]}',
                    'CannedAccessControlList': 'private',
                    'MetadataDirective': 'COPY'
                }
            }
            # Logic to determine whether we are using SSE-KMS or SSE-S3
            if self.sse_type == 'SSE-KMS':
                operation['S3PutObjectCopy']['SSEAwsKmsKeyId'] = self.kms_key_id
            elif self.sse_type == 'SSE-S3':
                operation['S3PutObjectCopy']['NewObjectMetadata'] = {
                    'SSEAlgorithm': 'AES256'}

        s3_control.create_job(
            AccountId=self.account_id,
            ConfirmationRequired=False,
            Operation=operation,
            Report={
                'Enabled': True,
                'Bucket': f'arn:aws:s3:::{self.s3_batch_reports_bucket}',
                'Format': 'Report_CSV_20180820',
                'Prefix': self.manifest.split('/')[0],
                'ReportScope': self.reporting_level
            },
            Manifest={
                'Spec': {
                    'Format': 'S3InventoryReport_CSV_20161130',
                },
                'Location': {
                    'ObjectArn': f'arn:aws:s3:::{self.s3_inv_reports_bucket}/{self.manifest}',
                    'ETag': self.e_tag
                }
            },
            Priority=10,
            RoleArn=self.role_arn
        )

    def __add_result_partition(self):
        """
        This method is responsible for adding S3 batch job completion report paths as partitions
        to the Glue table, which is then used by Athena queries for easy analysis.
        """

        glue = boto3.client('glue', region_name=self.deployment_region)

        try:
            path = "/".join(self.manifest.split("/")[:-1])
            glue.create_partition(
                DatabaseName=self.database_name,
                TableName=self.table_name_batch,
                PartitionInput={
                    'Values': ["-".join(self.manifest.split('/')[:2])],
                    'StorageDescriptor': {
                        'Columns': [
                            {
                                'Name': 'bucket_name',
                                'Type': 'string'
                            },
                            {
                                'Name': 'key_name',
                                'Type': 'string'
                            },
                            {
                                'Name': 'version_id',
                                'Type': 'string'
                            },
                            {
                                'Name': 'task_status',
                                'Type': 'string'
                            },
                            {
                                'Name': 'error_code',
                                'Type': 'string'
                            },
                            {
                                'Name': 'http_status_code',
                                'Type': 'string'
                            },
                            {
                                'Name': 'result_message',
                                'Type': 'string'
                            },
                        ],
                        'Location': f's3://{self.s3_batch_reports_bucket}/{path}/results/',
                        'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                        'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                        'Compressed': True,
                        'SerdeInfo': {
                            'Name': 'string',
                            'SerializationLibrary': 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
                            'Parameters': {
                                'field.delim': ','
                            }
                        }
                    }
                }
            )
        except ClientError as e:
            if e.response['Error']['Code'] != 'AlreadyExistsException':
                raise

    def __add_inv_partition(self):
        """
        This method is responsible for adding S3 Inventory paths as partitions
        to the Glue table, which is then used by Athena queries for easy analysis.
        """

        glue = boto3.client('glue', region_name=self.deployment_region)

        try:
            glue.create_partition(
                DatabaseName=self.database_name,
                TableName=self.table_name_inv,
                PartitionInput={
                    'Values': [self.manifest.split('/')[0]],
                    'StorageDescriptor': {
                        'Columns': [
                            {
                                'Name': 'bucket_name',
                                'Type': 'string'
                            },
                            {
                                'Name': 'key_name',
                                'Type': 'string'
                            },
                            {
                                'Name': 'version_id',
                                'Type': 'string'
                            },
                            {
                                'Name': 'is_latest',
                                'Type': 'string'
                            },
                            {
                                'Name': 'delete_marker',
                                'Type': 'string'
                            },
                            {
                                'Name': 'encryption_status',
                                'Type': 'string'
                            },
                        ],
                        'Location': f's3://{self.s3_inv_reports_bucket}/{self.manifest.split("/")[0]}/{self.inventories_name}/data/',
                        'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                        'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                        'Compressed': True,
                        'SerdeInfo': {
                            'Name': 'string',
                            'SerializationLibrary': 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
                            'Parameters': {
                                'field.delim': ','
                            }
                        }
                    }
                }
            )
        except ClientError as e:
            if e.response['Error']['Code'] != 'AlreadyExistsException':
                raise

    def __update_kms_key_policy(self, remove_only=False):
        """
        Updates the default KMS key policy to allow S3 to use the specified customer managed key
        for the encryption of S3 Inventory Reports.
        """

        kms = boto3.client('kms', region_name=self.deployment_region)
        policy = json.loads(kms.get_key_policy(KeyId=self.kms_key_id, PolicyName='default')[
                            'Policy'])  # pylint: disable = C0301
        statements = policy['Statement']
        for s in statements:
            if s.get('Sid') == 'S3InventoryPermissions':
                statements.remove(s)
                break
        if not remove_only:
            inv_permission = {
                'Sid': 'S3InventoryPermissions',
                'Effect': 'Allow',
                'Principal': {'Service': 's3.amazonaws.com'},
                'Action': ['kms:GenerateDataKey*'],
                'Resource': '*'
            }
            statements.insert(0, inv_permission)
        kms.put_key_policy(
            KeyId=self.kms_key_id,
            PolicyName='default',
            Policy=json.dumps(policy)
        )

    def __set_up_glue_database(self):
        """
        Sets up the Glue database in which tables for S3 Inventory and S3 Batch will be stored.
        """

        glue = boto3.client('glue')
        try:
            glue.create_database(
                CatalogId=self.account_id,
                DatabaseInput={
                    'Name': self.database_name,
                    'Description': 'This database is used to store tables for Amazon Athena to use to query S3 Inventory and S3 Batch job completion reports.'
                }
            )
        except ClientError as e:
            if e.response['Error']['Code'] != 'AlreadyExistsException':
                raise

    def update_resources(self):
        """
        This method is responsible for updating whether or not objects in a bucket
        should be encrypted by an S3 Batch job upon the delivery of an inventory report.

        Flow of operation:

        1. receive update
        2. check if 'encrypt' is now set to 'yes'
            3. if so, reconfigure S3 Inventory reports for all buckets
            4. when a new report arrives due to the reconfiguration, it will trigger
               an s3 event notification
            5. the s3 event notification will trigger the s3 batch encryption job, since
               the 'encrypt' variable is set to 'yes' after the update
        6. if the 'encrypt' variable is set to 'no', nothing happens. s3 inventory reports
           will still get delivered at least once if they haven't been delivered already,
           and the s3 batch encryption job will not be triggered since the 'encrypt'
           variable is set to 'no'

        """

        if self.encrypt == 'yes':
            info('getting target buckets for s3 inventory reports and encryption')
            self.__set_target_buckets()
            info(
                'setting up S3 Inventory reports for the S3 buckets targeted for encryption')
            self.__set_up_s3_inventory_configurations()
        else:
            info('buckets will not be encrypted upon the delivery of s3 inventory reports')

    def configure_resources(self):
        """
        This method is responsible for the creation/configuration of resources when the
        CloudFormation stack is being deployed.
        """
        if self.sse_type == 'SSE-KMS':
            info('updating the key policy on the KMS key designated for encryption to permit AWS S3 to use it for S3 Inventory report encryption')  # pylint: disable = C0301
            self.__update_kms_key_policy()
        info('looking through buckets to determine which ones are targeted for encryption')
        self.__set_target_buckets()
        info('setting up S3 Inventory reports for the S3 buckets targeted for encryption')
        self.__set_up_inv_reports_bucket()
        info('setting up the S3 bucket that will be used to store the S3 Inventory reports')
        self.__set_up_s3_inventory_configurations()
        info('setting up S3 event notifications that detect newly uploaded S3 Inventory reports')  # pylint: disable = C0301
        self.__set_up_s3_event_notifications(self.s3_inv_reports_bucket, self.s3_event_id_inv)
        info('setting up S3 event notifications that detect newly uploaded S3 Batch Job completion reports')  # pylint: disable = C0301
        self.__set_up_s3_event_notifications(self.s3_batch_reports_bucket, self.s3_event_id_batch)
        info('setting up glue database that will store queryable tables with athena')
        self.__set_up_glue_database()

    def deconfigure_resources(self):
        """
        This method is responsible for the deletion/configuration of resource when the
        CloudFormation stack is being rolled back.
        """
        if self.sse_type == 'SSE-KMS':
            info(
                'removing permissions for AWS S3 to access the KMS key designated for encryption')
            self.__update_kms_key_policy(remove_only=True)
        info('getting a list of all target buckets that were designated for encryption')
        self.__set_target_buckets()
        info('removing S3 Inventory configurations from S3 buckets targeted for encryption')
        self.__remove_s3_inventory_configurations()

    def process_s3_event(self, event):
        """
        This method creates an S3 Batch job that processes the manifest file
        that triggered the S3 Event notification.
        """
        if event['Records'][0]['s3']['bucket']['name'] == self.s3_inv_reports_bucket:
            info('s3 inventory manifest has been uploaded')
            if self.encrypt == 'yes':
                info('triggering the batch job with the manifest file')
                self.__trigger_batch_job()
            else:
                info('new manifest was uploaded but a batch job was not triggered since the '
                     '"EncryptBuckets" parameter in the CloudFormation template is set to "no"')

            if self.remove_s3_inventory_config == 'yes':
                info('removing the S3 Inventory configuration for the bucket that completed its S3 Inventory report')  # pylint: disable = C0301
                self.__remove_s3_inventory_configuration(
                    self.manifest.split('/')[0])

            info('adding partition to Glue table for easy querying with Athena')
            self.__add_inv_partition()

        elif event['Records'][0]['s3']['bucket']['name'] == self.s3_batch_reports_bucket:
            info('batch report manifest has been uploaded')
            self.__add_result_partition()

    def process_cloudwatch_event(self, event):
        """
        This method is checks whether a tag has been placed on a bucket
        specifying that S3 Inventory reports should now be turned on for
        the bucket. If the tag is present, S3 Inventory is configured for
        the bucket.
        """

        tag_set = event['detail']['requestParameters']['Tagging']['TagSet']['Tag']
        bucket_name = event['detail']['requestParameters']['bucketName']

        if isinstance(tag_set, list):
            for tag in tag_set:
                if tag.get('Key') == self.s3_target_tag_key and str(tag.get('Value')).lower() == self.s3_target_tag_value:
                    # Tag discovered. Configure S3 Inventory report
                    self.__set_up_s3_inventory_configuration(bucket_name)
                    return
        elif isinstance(tag_set, dict):
            if tag_set.get('Key') == self.s3_target_tag_key and str(tag_set.get('Value')).lower() == self.s3_target_tag_value:
                # Tag discovered. Configure S3 Inventory report
                self.__set_up_s3_inventory_configuration(bucket_name)
                return

        # No tags match. Delete present S3 Inventory reports and exit function.
        if self.remove_s3_inventory_config == 'yes':
            self.__remove_s3_inventory_configuration(bucket_name)

    def process_batch_job_invocation(self, event):
        """
        This contains the processing logic to encrypt objects in an S3 bucket and add a tag to them.
        """

        s3 = boto3.client('s3')

        # get bucket and key name of object to copy
        bucket_name = event['tasks'][0]['s3BucketArn'].split(':::')[-1]
        key_name = unquote_plus(event['tasks'][0]['s3Key'])

        # prepare batch response dict
        s3_batch_response = {

            'invocationSchemaVersion': event['invocationSchemaVersion'],
            'treatMissingKeysAs': 'PermanentFailure',
            'invocationId': event['invocationId'],
            'results': [
                {
                    'taskId': event['tasks'][0]['taskId'],
                    'resultCode': None,
                    'resultString': None
                }
            ]
        }

        result_code, result_string = None, None

        # main logic
        try:
            response = s3.head_object(Bucket=bucket_name, Key=key_name)
            if 'ServerSideEncryption' not in response:

                tags = s3.get_object_tagging(
                    Bucket=bucket_name, Key=key_name)['TagSet']
                tags.append({'Key': self.object_tag_key,
                            'Value': self.object_tag_value})
                s3.put_object_tagging(Bucket=bucket_name,
                                    Key=key_name, Tagging={'TagSet': tags})

                if self.sse_type == 'SSE-KMS':
                    s3.copy_object(Bucket=bucket_name,
                                CopySource={
                                    'Bucket': bucket_name, 'Key': key_name},
                                Key=key_name,
                                ACL='private',
                                MetadataDirective='COPY',
                                TaggingDirective='COPY',
                                ServerSideEncryption='aws:kms',
                                SSEKMSKeyId=self.kms_key_id)

                elif self.sse_type == 'SSE-S3':
                    s3.copy_object(Bucket=bucket_name,
                                CopySource={
                                    'Bucket': bucket_name, 'Key': key_name},
                                Key=key_name,
                                ACL='private',
                                MetadataDirective='COPY',
                                TaggingDirective='COPY',
                                ServerSideEncryption='AES256')
                else:
                    raise

                result_code = 'Succeeded'
                result_string = json.dumps(f'Object encrypted successfully.')

        # handle exception logic
        except Exception as e:

            error(f'Error: {e}')
            if isinstance(e, ClientError):
                if e.response['Error']['Code'] == 'RequestTimeout':
                    result_code = 'TemporaryFailure'
                    result_string = json.dumps(
                        f'Retry request to Amazon S3 due to timeout.')
                else:
                    result_code = 'PermanentFailure'
                    result_string = json.dumps(
                        f'Error: {e.response["Error"]["Code"]}')
            else:
                result_code = 'PermanentFailure'
                result_string = json.dumps(f'Error: {repr(e)}')

        finally:

            s3_batch_response['results'][0]['resultCode'] = result_code
            s3_batch_response['results'][0]['resultString'] = result_string

            return s3_batch_response


######################################################################
#                        FUNCTIONAL LOGIC                            #
######################################################################


def send(event, context, response_status, response_data, physical_resource_id, no_echo=False):  # pylint: disable = R0913
    """
    Helper function for sending updates on the custom resource to CloudFormation during a
    'Create', 'Update', or 'Delete' event.
    """

    http = urllib3.PoolManager()
    response_url = event['ResponseURL']

    json_response_body = json.dumps({
        'Status': response_status,
        'Reason': f'See the details in CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': physical_resource_id,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': no_echo,
        'Data': response_data
    }).encode('utf-8')

    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }

    try:
        http.request('PUT', response_url,
                     body=json_response_body, headers=headers)
    except Exception as e:  # pylint: disable = W0703
        error(e)


def handler(event, context):
    """
    Entry point for the Lambda function.
    """

    info(event)

    success = 'SUCCESS'
    failed = 'FAILED'
    physical_resource_id = 'EncryptorController'

    encryptor = Encryptor(event, context)

    # Create request from CloudFormation
    if event.get('RequestType') == 'Create':
        info(
            f'request received of type {event["RequestType"]}, proceeding to configure resources')
        try:
            encryptor.configure_resources()
            response_data = {
                'S3InvReportBucketName': encryptor.s3_inv_reports_bucket,
                'S3BatchReportBucketName': encryptor.s3_batch_reports_bucket
            }
            send(event, context, success, response_data, physical_resource_id)
        except Exception as e:  # pylint: disable = W0703
            send(event, context, failed, {}, physical_resource_id)
            error(e)

    # Update request from CloudFormation
    elif event.get('RequestType') == 'Update':
        info(
            f'request received of type {event["RequestType"]}, proceeding to configure resources')
        try:
            encryptor.update_resources()
            response_data = {
                'S3InvReportBucketName': encryptor.s3_inv_reports_bucket,
                'S3BatchReportBucketName': encryptor.s3_batch_reports_bucket
            }
            send(event, context, success, response_data, physical_resource_id)
        except Exception as e:  # pylint: disable = W0703
            send(event, context, failed, {}, physical_resource_id)
            error(e)

    # Delete request from CloudFormation
    elif event.get('RequestType') == 'Delete':
        info(
            f'request received of type {event["RequestType"]}, proceeding to delete resources')
        try:
            encryptor.deconfigure_resources()
            send(event, context, success, {}, physical_resource_id)
        except Exception as e:  # pylint: disable = W0703
            send(event, context, failed, {}, physical_resource_id)
            error(e)

    # Notification that an S3 PUT event occurred. Trigger an S3 Batch job that
    # will process the newly completed manifest file.
    elif event.get('Records'):
        info('S3 event notification received')
        try:
            encryptor.process_s3_event(event)
        except Exception as e:  # pylint: disable = W0703
            error(e)

    # Tag was updated on a bucket. Check if S3 Inventory should now be configured
    # for the bucket
    elif event.get('detail', {}).get('eventName') == 'PutBucketTagging':
        info('Lambda function triggered by CloudWatch PutBucketTagging event, proceeding to '
             'check if S3 Inventory needs to be configured for a bucket')
        try:
            encryptor.process_cloudwatch_event(event)
        except Exception as e:
            error(e)

    # Function is being invoked by S3 Batch Operations job
    elif event.get('job'):
        return encryptor.process_batch_job_invocation(event)
