from Crypto.Cipher import XOR
import base64

def format_message(message):
    timestamp = message["timestamp"]
    sender = message["sendername"]
    receiver = message["receivername"]
    try:
        # Early feilds don't have functionality
        # for all_recievers, the field was empty
        receivers = message["all_receivers"]
    except KeyError:
        receivers = receiver
    message = decrypt_message(message["message"], receiver)
    msg = """timestamp: {}<br>
             sender: {}<br>
             receiver: {}<br>
             all recievers: {}<br>
             message: {}<br>""".format(timestamp, sender, receiver, receivers, message)
    return msg

def format_all_messages(all_messages):
    return "<br>".join(format_message(m) for m in all_messages)

def make_msg_summary(all_received_messages):
    total = len(all_received_messages)
    user_to_time = {}
    for ele in all_received_messages:
        user = ele["sendername"]
        time = ele["timestamp"]

        if user not in user_to_time:
            user_to_time[user] = time
        else:
            if time > user_to_time[user]:
                user_to_time[user] = time

    user_to_time_sorted = sorted(user_to_time.items(), key = lambda x: x[1], reverse=True)

    line_1 = "You have: {} total messages<br>".format(total)
    line_2 = "You have messages from users:<br>"
    
    columns = "<br>".join("{}: {}".format(a, b) for a,b in user_to_time_sorted)

    return line_1 + line_2 + "<br>" + columns

def encrypt_message(message, receiver):
    cipher = XOR.new(receiver)
    return base64.b64encode(cipher.encrypt(message))

def decrypt_message(encrypted_message, receiver):
    cipher = XOR.new(receiver)
    return cipher.decrypt(base64.b64decode(encrypted_message))
