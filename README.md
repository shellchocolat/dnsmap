# DnsMap

Allow to create an interactive map of all DNS records

So you can have a nice view of your domain and subdomains and how they interact within each other.

As an example, you can check very quickly if some of your subdomains are sensitives to subdomain takeover, check what are the publics IPs of your domains, identify some relevant entrypoints, and more :)

This tool doesn't bruteforce subdomains, you have to use your favorite tool for that and put all of your subdomains into a file with the format:
```
DOMAIN:test.com
SUBDOMAIN:sub1.test.com
SUBDOMAIN:sub2.test.com
SUBDOMAIN:sub3.test.com
DOMAIN:test.xyz
SUBDOMAIN:sub1.test.xyz
SUBDOMAIN:sub2.test.xyz
```

Below is an example of the output:

![poc](poc.png)

## create the neo4j docker
```
docker run \                                          
    --name neo4j \
    -p7474:7474 -p7687:7687 \
    -d \
    -v $HOME/neo4j/data:/data \
    -v $HOME/neo4j/logs:/logs \
    -v $HOME/neo4j/import:/var/lib/neo4j/import \
    -v $HOME/neo4j/plugins:/plugins \
    --env NEO4J_AUTH=neo4j/test \
    neo4j:latest
```

```
docker stop neo4j
docker start neo4j
```

## create a custom bridge to communicate easily with the neo4j docker
```
docker network create -d bridge --subnet 192.168.42.0/24 --gateway 192.168.42.1 dnsmap
```

## create the dnsmap docker
```
docker build -t dnsmap .
```

## use the dnsmap
```
docker run --rm dnsmap -h
docker run --rm dnsmap -d test.com -s 8.8.8.8
docker run --rm -v /pathToFile/subdomains.txt:/subdomains.txt dnsmap -f subdomains.txt
```

Then go to your browser: 127.0.0.1:7474

Some nice requests to the neo4j cypher:
* display all nodes:
```
MATCH (n) RETURN n
```
* display all nodes with all relations:
```
MATCH (n)-[r]->(m) RETURN n,r,m
```
* display nodes+relations for 1 specific node:
```
MATCH (n)-[r]->(m) WHERE n.name='test.com' RETURN n,r,m
```
* display nodes+relations for 2 specific nodes:
```
MATCH (n)-[r]->(m) WHERE n.name='test.com' OR n.name='sub.test.com' RETURN n,r,m
```
* display nodes+relations for 1 specific node and with a recursive depth of 3:
```
MATCH (n)-[r*1..3]->(m) WHERE n.name='test.com' RETURN n,r,m
```
* display all nodes that satisfy a regex:
```
MATCH (n)-[r]->(m) WHERE n.name=~'tes.*' RETURN n,r,m
```



