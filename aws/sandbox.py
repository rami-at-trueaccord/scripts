###################################################
##########  Boilerplate Relative Import Hack ##########
import sys, os
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_dir)
###################################################


from general.aws_helpers.s3.buckets import get_object_encryption_status

get_object_encryption_status(bucket_name='true-lending-credit-reports', key_name='reports/TRUEACCORDSATELLITEINCCPJWP4Y6VXEXPERIAN20210722.txt')
