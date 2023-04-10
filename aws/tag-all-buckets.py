#######################################################
##########  Boilerplate Relative Import Hack ##########
import sys, os
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_dir)
#######################################################


from general.aws_helpers.s3.buckets import upsert_tag_buckets, get_all_bucket_names

buckets_to_tag = get_all_bucket_names()
tag_key = '__Inventory'
tag_value = 'true'
account = ''


upsert_tag_buckets(
    list_of_buckets=buckets_to_tag,
    key=tag_key,
    value=tag_value,
    account_id=account
)
