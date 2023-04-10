import boto3


def get_all_bucket_names():
    s3 = boto3.client('s3')
    return [bucket['Name'] for bucket in s3.list_buckets()['Buckets']]


def upsert_tag_buckets(list_of_buckets: list[str], key: str, value: str, account_id: str):
    s3 = boto3.client('s3')

    for bucket in list_of_buckets:
        current_tagset = []

        # Get the current tagset
        try:
            current_tagging = s3.get_bucket_tagging(
                Bucket=bucket, ExpectedBucketOwner=account_id)
        except Exception as e:
            print(f"Unable to retrieve TagSet for bucket {bucket}:::{e}")
        else:
            current_tagset = current_tagging['TagSet']

        # Upsert - Remove a tag if it has the same key as the new tag
        for index, tag in enumerate(current_tagset):
            if tag['Key'] == key:
                del current_tagset[index]
                break

        # Upsert - Add the new tag
        current_tagset.append({
            'Key': key,
            'Value': value
        },)

        # Re-apply the tagset with the new tag
        try:
            s3.put_bucket_tagging(Bucket=bucket, Tagging={
                'TagSet': current_tagset
            }, ExpectedBucketOwner=account_id)
        except Exception as e:
            print(
                f"Failed to tag {bucket} with tagset [{current_tagset}]:::{e}")

def get_object_encryption_status(bucket_name: str, key_name: str):
    s3 = boto3.client('s3')
    response = s3.head_object(Bucket=bucket_name, Key=key_name)
    print(response)