import boto3 

def get_all_bucket_names():
    s3 = boto3.client('s3')
    return [bucket['Name'] for bucket in s3.list_buckets()['Buckets']]