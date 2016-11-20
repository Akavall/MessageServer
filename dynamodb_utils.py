import boto3
from boto3.dynamodb.conditions import Key
import bcrypt
from datetime import datetime

dynamodb = boto3.resource("dynamodb", region_name="us-west-2")

def get_messages_from_dynamo_db(username):
    table = dynamodb.Table("ReceiverBasedMsgs")
    
    try:
        response = table.query(
            KeyConditionExpression=Key("receivername").eq(username)
        )

        print "Request for Table: ReceiverBasedMsgs, user: {} was successful".format(username)

        if "Items" in response:
            print "{} for Table: ReceiverBasedMsgs was found in database".format(username)
            return response["Items"]
        else:
            print "{} for Table: ReceiverBasedMsgs was NOT found in the database".format(username)
            return None 

    except Exception as exc:
        print "The request failed, Error: {}".format(exc)

def get_password_from_dynamo_db(username):
    table = dynamodb.Table("Passwords")
    try:
        response = table.get_item(Key={"username": username})

        print "Request for {} was successful".format(username)

        if "Item" in response:
            print "{} was found in database".format(username)
            return response["Item"]
        else:
            print "{} was NOT found in the database".format(username)
            return None 

    except Exception as exc:
        print "The request failed, Error: {}".format(exc)

def set_password(username, password):
    my_salt = bcrypt.gensalt().encode("utf-8")
    comp_password = (password + my_salt).encode("utf-8")
    hashpassword = bcrypt.hashpw(comp_password, my_salt)
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2') 
    my_item = {"username": username,
               "hashpassword": hashpassword,
               "salt": my_salt}
    table = dynamodb.Table("Passwords")
    table.put_item(Item=my_item)

def check_username_hashpassword(username, password):
    response = get_password_from_dynamo_db(username)
    if response is None:
        return False 
    hashpassword = response["hashpassword"]
    my_salt = response["salt"]
    
    comp_password = (password + my_salt).encode("utf-8")
    input_hashpassword = bcrypt.hashpw(comp_password, my_salt.encode("utf-8"))
    if input_hashpassword == hashpassword:
        return True
    return False

def update_sender_to_receiver(sender, receiver, message):
    table = dynamodb.Table("SenderBasedMsgs")
    timestamp = "utc time : " + str(datetime.utcnow())
    # Example of timestamp: '2016-11-20 01:06:20.681266'
    # likelyhood of duplicate is very small
    my_item = {"sendername": sender,
               "timestamp": timestamp,
               "receivername": receiver,
               "message": message[:1000]}
    table.put_item(Item=my_item)
    print "writing message to SenderBasedMsgs, receiver: {}, sender {}".format(receiver, sender)

def update_receiver_to_sender(sender, receiver, message):
    table = dynamodb.Table("ReceiverBasedMsgs")
    timestamp = "utc time : " + str(datetime.utcnow())
    # Example of timestamp: '2016-11-20 01:06:20.681266'
    # likelyhood of duplicate is very small
    my_item = {"receivername": receiver,
               "timestamp": timestamp,
               "sendername": sender,
               "message": message[:1000]}
    table.put_item(Item=my_item)
    print "writing message to ReceiverBasedMsgs receiver: {}, sender {}".format(receiver, sender)
