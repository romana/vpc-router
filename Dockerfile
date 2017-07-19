FROM nimmis/alpine-python:2
ADD requirements/deploy.txt /tmp/requirements.txt 
ADD . /code
WORKDIR /code
RUN python setup.py install
EXPOSE 33289
VOLUME ["/conf"]
ENTRYPOINT ["vpcrouter", "-l", "-"]
