FROM python:latest

RUN apt-get update -y && apt-get install -y whois zmap

RUN pip install --upgrade IPWhois \
	&& pip install --upgrade whois \
	&& pip install --upgrade neo4jrestclient \
	&& pip install --upgrade colorama \
	&& pip install --upgrade argparse \
	&& pip install --upgrade cymruwhois

ADD dnsmap.py /

ENTRYPOINT ["python", "./dnsmap.py"]
