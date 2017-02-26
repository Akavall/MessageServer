import boto3
from boto3.dynamodb.conditions import Key
import bcrypt
from datetime import datetime
import logging

from utilities import format_all_messages, encrypt_message

dynamodb = boto3.resource("dynamodb", region_name="us-west-2")

def get_messages_from_dynamo_db(username, table_name):
    table = dynamodb.Table(table_name)

    #TODO: this probably can be improved
    if table_name == "ReceiverBasedMsgs":
        key_schema_element = "receivername"
    elif table_name == "SenderBasedMsgs":
        key_schema_element = "sendername"
    
    try:
        response = table.query(
            KeyConditionExpression=Key(key_schema_element).eq(username)
        )

        logging.info("Request for Table: {}, user: {} was successful".format(table_name, username))

        if "Items" in response:
            logging.info("{} for Table: {} was found in database".format(table_name, username))
            return response["Items"]
        else:
            logging.info("{} for Table: {} was NOT found in the database".format(table_name, username))
            return None 

    except Exception as exc:
        logging.error("The request failed, Error: {}".format(exc))

def get_password_from_dynamo_db(username):
    table = dynamodb.Table("Passwords")
    try:
        response = table.get_item(Key={"username": username})

        logging.info("Request for {} was successful".format(username))

        if "Item" in response:
            logging.info("{} was found in database".format(username))
            return response["Item"]
        else:
            logging.info("{} was NOT found in the database".format(username))
            return None 

    except Exception as exc:
        logging.error("The request failed, Error: {}".format(exc))

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

def update_sender_to_receiver(sender, receiver, receivers, message):
    table = dynamodb.Table("SenderBasedMsgs")
    timestamp = "utc time : " + str(datetime.utcnow())
    # Example of timestamp: '2016-11-20 01:06:20.681266'
    # likelyhood of duplicate is very small        
    my_item = {"sendername": sender,
               "timestamp": timestamp,
               "receivername": receiver,
               "all_receivers": receivers,
               "message": encrypt_message(message[:1000], receiver)}
    table.put_item(Item=my_item)
    logging.info("writing message to SenderBasedMsgs, receiver: {}, sender {}".format(receiver, sender))

def update_receiver_to_sender(sender, receiver, receivers, message):
    table = dynamodb.Table("ReceiverBasedMsgs")
    timestamp = "utc time : " + str(datetime.utcnow())
    # Example of timestamp: '2016-11-20 01:06:20.681266'
    # likelyhood of duplicate is very small

    my_item = {"receivername": receiver,
               "timestamp": timestamp,
               "sendername": sender,
               "all_receivers": receivers,
               "message": encrypt_message(message[:1000], receiver)}
    table.put_item(Item=my_item)
    logging.info("writing message to ReceiverBasedMsgs receiver: {}, sender {}".format(receiver, sender))

def get_user_to_user_thread(action_user, other_user):
    sent_messages = get_messages_from_dynamo_db(action_user, "SenderBasedMsgs")
    
    sent_messages_to_other = [m for m in sent_messages if m["receivername"] == other_user]

    received_messages = get_messages_from_dynamo_db(action_user, "ReceiverBasedMsgs")

    received_messages_from_other = [m for m in received_messages if m["sendername"] == other_user]

    all_messages = sent_messages_to_other + received_messages_from_other

    all_messages.sort(key = lambda x: x["timestamp"], reverse=True)

    if not all_messages:
        return "There are no messages between: {} and {}".format(action_user, other_user)
    # can't return list of dicts here
    return format_all_messages(all_messages)

   

    
