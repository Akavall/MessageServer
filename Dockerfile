FROM ubuntu

# setting up python
RUN apt-get update
RUN apt-get install -y apt-utils
RUN apt-get install -y tar git net-tools build-essential
RUN apt-get install -y python python-dev python-distribute python-pip


# pulling app date
RUN git clone https://github.com/Akavall/MessageServer 

#ADD /MessageServer/tables /MessageServer/tables
#ADD /MessageServer/static /MessageServer/static 
#ADD /MessageServer/templates /MessageServer/templates 
#ADD /MessageServer/utilities.py /MessageServer/utilities.py
#ADD /MessageServer/basic_login.py /MessageServer/basic_login.py
#ADD /MessageServer/dynamodb_utils.py /MessageServer/dynamodb_utils.py
#ADD /MessageServer/requirements.txt
#
RUN pip install -r /MessageServer/requirements.txt

EXPOSE 8090
# ENTRYPOINT ["python"]
# CMD ["/MessageServer/basic_login.py"]


