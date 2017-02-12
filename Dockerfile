FROM ubuntu

RUN apt-get update
RUN apt-get install -y apt-utils
RUN apt-get install -y tar git net-tools build-essential
RUN apt-get install -y python python-dev python-distribute python-pip

RUN git clone https://github.com/Akavall/MessageServer 

RUN pip install -r /MessageServer/requirements.txt

EXPOSE 8090
CMD python /MessageServer/basic_login.py


