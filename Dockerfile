FROM ubuntu

# setting up python
RUN apt-get upadate
RUN apt-get install -y tar git net-tools build-essential
RUN apt-get install -y python python-dev python-distribute python-pip

# pulling app date
RUN git clone https://github.com/Akavall/MessageServer 

ADD /tables /tables
ADD /static /static 
ADD /templates /templates 


