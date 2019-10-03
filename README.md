# Graphdns

Allow to create an interactive map of all DNS records

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
