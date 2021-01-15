FROM python:latest

RUN apt-get update -y && apt-get install -y whois zmap

RUN pip install --upgrade IPWhois \
	&& pip install --upgrade whois \
	&& pip install --upgrade neo4j \
	&& pip install --upgrade colorama \
	&& pip install --upgrade beautifulsoup4 \
	&& pip install --upgrade requests \
	&& pip install --upgrade argparse 

ADD dnsmap.py /

ENTRYPOINT ["python", "./dnsmap.py"]
