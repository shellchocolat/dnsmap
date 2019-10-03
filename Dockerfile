FROM python:latest

RUN pip install --upgrade IPWhois \
	&& pip install --upgrade neo4jrestclient \
	&& pip install --upgrade colorama \
	&& pip install --upgrade argparse

ADD graphdns.py /

ENTRYPOINT ["python", "./dnsmap.py"]
