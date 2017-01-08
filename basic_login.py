from flask import Flask, session, request, url_for, redirect, render_template, Markup
from dynamodb_utils import get_messages_from_dynamo_db, get_password_from_dynamo_db, set_password, check_username_hashpassword, update_sender_to_receiver, update_receiver_to_sender, get_user_to_user_thread
from utilities import make_msg_summary

app = Flask(__name__)
app.secret_key = "any random string"

@app.route("/")
def index():
    if "username" in session:
        username = session["username"]
        return render_template("index.html", username=username)       
    return "You are not logged in"

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        # When we submit data it is a post request
        username = request.form["username"]
        password = request.form["password"]
        
        
        if check_username_hashpassword(username, password):
            session["username"] = request.form["username"]
            return redirect(url_for("index"))
        return "password/username combination not found"
    
    # When we just go to the site, it is a GET request
    return """
    Login page
    <form action = "" method = "post">
        <p><input type = text name = username></p>
        <p><input type = password name = password></p>
        <p><input type = submit value = Login></p>
    </form>
    """


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        session["username"] = request.form["username"]
        username = request.form["username"]

        if get_password_from_dynamo_db(username):
            return "username already exists"

        password = request.form["password"]
        if len(password) < 5:
            "password should be at least 5 characters"

        set_password(username, password)
        return redirect(url_for("login"))
    
    return """
    Registration Page
    <form action = "" method = "post">
        <p><input type = text name = username></p>
        <p><input type = password name = password></p>
        <p><input type = submit value = Register></p>
    </form>
    """

@app.route("/send", methods=["GET", "POST"])
def send():
    if "username" not in session:
        return "You are not logged in"

    if request.method == "POST":
        sender = session["username"]
        receivers = request.form["send_to"]
        receivers_list = receivers.split()
        if not receivers:
            
            return render_template("send_info.html", message="receiver user cannot be empty string")
        message = request.form["message"]
        if not message:
            return render_template("send_info.html", message="message cannot be empty")

        sent_message_to = []
        not_sent_message_to = []
        for receiver in receivers_list:
            if not get_password_from_dynamo_db(receiver):
                not_sent_message_to.append(receiver)
            else:
                update_sender_to_receiver(sender, receiver, receivers, message)
                update_receiver_to_sender(sender, receiver, receivers, message)
                sent_message_to.append(receiver)

        sent_string = ",".join(sent_message_to)
        not_sent_string = ".".join(not_sent_message_to)

        line_break = "<BR>"

        # What I am sending is not interpreted by html
        # Good is some way, but bad that I don't know how to format it!
        my_data = Markup("Sent to: {} {} Did not sent to: {}".format(sent_string, line_break, not_sent_string ) )
        rendered_message = render_template("send_info.html", data=my_data)

        return rendered_message 

    html_format = """
    Send a message
    <form action = "" method = "post" id=sendform>
        <p>Send to:<input type = text name = send_to></p>
        <p><input type = submit value = Send></p>
    </form>
    <textarea form ="sendform" name="message" cols="35" wrap="soft"></textarea>
    """

    return render_template("send.html")

@app.route("/inbox")
def inbox():
    if "username" not in session:
        return "You are not logged in"

    username = session["username"]
    # users_messages = receiver_to_sender.get(username, "No messages found")
    users_messages = get_messages_from_dynamo_db(username, "ReceiverBasedMsgs")
    summary = make_msg_summary(users_messages)
    return render_template("inbox.html", data=Markup(summary))

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))

@app.route("/user_to_user", methods=["GET", "POST"])
def user_to_user():
    if request.method == "POST":
        other_user = request.form["username"]
        user_to_user_thread = get_user_to_user_thread(session["username"], other_user)
        return user_to_user_thread
    return """  
        Check messages from user:
        <form action = "" method = "post">
            <p><input type = text name = username></p>
            <p><input type="submit" value="submit"></p>
        </form>
    """
    
if __name__ == "__main__":
    app.run()

