from __future__ import print_function
import boto3

dynamodb = boto3.resource("dynamodb", region_name="us-west-2")

table = dynamodb.create_table(
    TableName="SenderBasedMsgs",
    KeySchema=[
        {
            "AttributeName": "sendername",
            "KeyType": "HASH"
        },
        {
            "AttributeName": "timestamp",
            "KeyType": "RANGE"
        }
    ],
    AttributeDefinitions=[
        {
            "AttributeName": "sendername",
            "AttributeType": "S"
        },
        {
            "AttributeName": "timestamp",
            "AttributeType": "S"
        }
    ],
    ProvisionedThroughput={
        "ReadCapacityUnits": 1,
        "WriteCapacityUnits": 1
    }
)
            
            
print ("Table status:", table.table_status)
