import boto3

REPORT_DESTINATION_BUCKET = ''  # TODO
ACCOUNT_ID = ''  # TODO

s3_client = boto3.client('s3')


def enable_inventory(bucket_name):
    inventory_configuration = {
        'Destination': {
            'S3BucketDestination': {
                'AccountId': ACCOUNT_ID,
                'Bucket': REPORT_DESTINATION_BUCKET,
                'Format': 'CSV',
                'Prefix': bucket_name,
            }
        },
        'IsEnabled': True,
        'Id': get_report_id(BucketName=bucket_name),
        'IncludedObjectVersions': 'Current',  # 'Current' or 'All'
        'OptionalFields': [
            # Choose what to include in report
            'Size', 'LastModifiedDate', 'StorageClass', 'ETag', 'IsMultipartUploaded',
            'ReplicationStatus', 'EncryptionStatus', 'ObjectLockRetainUntilDate',
            'ObjectLockMode', 'ObjectLockLegalHoldStatus', 'IntelligentTieringAccessTier',
            'BucketKeyStatus', 'ChecksumAlgorithm',
        ],
        'Schedule': {
            'Frequency': 'Daily'
        }
    }

    try:
        s3_client.put_bucket_inventory_configuration(
            Bucket=bucket_name,
            Id=get_report_id(BucketName=bucket_name),
            InventoryConfiguration=inventory_configuration
        )
        print(f'Inventory report enabled for bucket: {bucket_name}')
    except Exception as e:
        print(f'Error enabling inventory report for bucket {bucket_name}: {e}')


def get_report_id(BucketName):
    return f"{BucketName}-main-report"


def main():
    bucket_names = [bucket['Name']
                    for bucket in s3_client.list_buckets()['Buckets']]

    for bucket_name in bucket_names:
        if bucket_name != REPORT_DESTINATION_BUCKET:
            enable_inventory(bucket_name)


if __name__ == '__main__':
    main()
