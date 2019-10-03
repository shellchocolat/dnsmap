FROM python:latest

RUN pip install --upgrade IPWhois \
	&& pip install --upgrade neo4jrestclient \
	&& pip install --upgrade colorama \
	&& pip install --upgrade argparse

ADD dnsmap.py /

ENTRYPOINT ["python", "./dnsmap.py"]
