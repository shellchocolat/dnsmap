#!/usr/bin/python3
import dns.resolver
from ipwhois import IPWhois
import socket
import argparse
from neo4jrestclient.client import GraphDatabase
from colorama import Fore
import sys
import os
import re
from dataclasses import dataclass

# CHANGE THIS
db_username = "neo4j"
db_password = "test"

global GREEN, RED, YELLOW, MAGENTA, RESET
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RESET = Fore.RESET

@dataclass
class Link:
    node_from: str
    node_from_name: str
    node_to: str
    node_to_name: str
    relation: str


def create_node(LABEL, NODE):
    """
        check if the node NODE with tag TAG exists
        if yes: do nothing
        if no: create the node
    """
    if NODE != None:
        if doesThatFuckingNodeExist( NODE ) == True:
            print(YELLOW + '[*] ('+NODE+') NOT created because it already exists with label: ' + LABEL + RESET)
        else:
            print(GREEN + '[+] ('+NODE+') created with label: ' + LABEL + RESET)
            try:
                query = """CREATE (n: %s { name: '%s' })"""%( LABEL, NODE )
                db.query( query )
            except Exception as e:
                print(RED + "[-] ("+NODE+") not created because empty value" + RESET)
                #print(str( e ))

def create_link(NODE_N, RELATION_R, NODE_M ):
    """
        check if relation exists
        if yes: do nothing
        if no: create the relation
    """
    if NODE_N != None and NODE_M != None:
        if doesThatCrazyLinkExist( NODE_N, RELATION_R, NODE_M ) == True:
            print(YELLOW + '[*] ('+NODE_N+')-['+RELATION_R+']-('+NODE_M+') NOT created' + RESET)
        else:
            print(MAGENTA + '[+] ('+NODE_N+')-['+RELATION_R+']-('+NODE_M+') created' + RESET)
            try:
                query = """ MATCH (n { name: '%s' }), (m { name: '%s' })
                            CREATE (n)-[r:%s]->(m)"""%( NODE_N, NODE_M, RELATION_R )
                db.query( query )
            except Exception as e:
                print(str( e ))


def is_ip(string):
    if string != None:
        # determine if the string is an ip
        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', string) != None:
            netname = find_netname(string)
            create_node('netname', netname)
            create_link(string, 'netname', netname)
            #Link_tab.append( Link(string, 'IP', netname, 'netname', 'netname' ))
            return True
        else:
            return False
    else:
        return False

def find_netname(ip):

    if "/" in ip: # if there is a range like x.x.x.x/24
        ip, sep, ip_range = ip.partition("/")

    try:
        # using whois to find network name
        obj = IPWhois(ip)

        res = obj.lookup_rdap()

        netname = res['network']['name']
    except:
        netname = 'UNKNOWN'

    return netname

def answer_records(domain, records_list):
    records = records_list

    for q in records:
        try:
            my_resolver = dns.resolver.Resolver()
            my_resolver.namesers = [ns]
            answers = my_resolver.query(domain, q)
            for rdata in answers:
                node_name = q

                #print('Mail exchange:',rdata.exchange,'preference:',rdata.preference)
                if q == 'MX':
                    rdata = rdata.exchange

                is_ip(str(rdata))

                create_node(node_name, str(rdata))

                create_link(domain, node_name, str(rdata))

                link = Link(domain, node_name, str(rdata), node_name, node_name)
                if link not in Link_tab:
                    Link_tab.append( link )


        except dns.resolver.NoAnswer:
            pass
            #print('[-] No ' + q + ' record for ' + domain)
        except dns.resolver.NXDOMAIN:
            pass
            #print('[-] The name ' + domain + ' does not exist')
        except Exception as e:
            pass
            #print(str(e))

    return True

def spf_parse(n1,TXT_content):
    TXT_content = TXT_content.replace('"', '')
    elements = TXT_content.split(' ')

    if 'v=spf' not in elements[0]:
        return False


    for e in elements[1:]:
        if 'ip4' in e:
            ip = e.replace('ip4:','')
            create_node('IP', ip)
            create_link(n1, 'IP', ip)

            netname = find_netname(ip)
            create_node('netname', netname)
            create_link(ip, 'netname', netname)
        elif 'ip6' in e:
            ip = e.replace('ip6:','')
            create_node('IP', ip)
            create_link(n1, 'IP', ip)

            netname = find_netname(ip)
            create_node('netname', netname)
            create_link(ip, 'netname', netname)
        elif 'all' in e:
            if e[0] == '+':
                pass
            elif e[0] == '~':
                pass
            elif e[0] == '?':
                pass
            elif e[0] == '-':
                pass
        elif 'include' in e:
            inc = e.replace('include:','')
            create_node('INCLUDE', inc)
            create_link(n1, 'SPF_INCLUDE', inc)
            answer_records(inc,records)


def doesThatFuckingNodeExist( NODE_NAME ):
    """
        try to get all node name and node tag
        then check if this particular node exist
        if yes: return True
        if no: return False
        if there is no node: return False
    """
    query = """ MATCH (n)
                RETURN n.name, n.tag"""
    try:
        results = db.query( query, data_contents=True ) # get nodes
        all_nodes = results.rows
    except Exception as e:
        print(str( e ))

    if all_nodes == None:
        return False # if there is no node at all in the neo4j database
    else:

        for nodeAndTag in all_nodes:
            if ( NODE_NAME in nodeAndTag  ):
                return True # if node with that specific tag exist, return True
            else:
                continue
        else: # if node with that specific tag does not exist, return False
            return False

def doesThatCrazyLinkExist( NODE_N, RELATION_R, NODE_M ):
    """
        try to get all relationships (links) between NODE_N and NODE_M
        if yes: return True
        if no: return False
    """
    if( doesThatFuckingNodeExist( NODE_N ) == True and doesThatFuckingNodeExist( NODE_M ) == True ):

        query = """ MATCH (n { name: '%s' })-[r:%s]->(m { name: '%s' })
                    RETURN SIGN(COUNT(r))"""%( NODE_N, RELATION_R, NODE_M )

        try:
            results = db.query( query, data_contents=True )

            if results.rows[0][0] == 1: 
                return True # if relation exist, return True
            else: 
                return False # if relation does not exist, return False
        except Exception as e:
            print(str( e ))
    else:#
        print(RED + "[-] one or two nodes are missing in order to check if a relationship exists between ("+NODE_N+") and ("+NODE_M+")" + RESET)
        return True # do as the relation exist and not try to create one

def do_the_magic(label, domain):
    # create the domain node
    create_node(label, domain)

    # DNS records
    global records
    records = ['A', 'NS', 'AAAA', 'CNAME', 'MX', 'TXT', 'SOA']
    answer_records(domain, records)

    # get the ip of the answer and create node and link
    for link in Link_tab:
        if link.node_to != None:
            if not is_ip(link.node_to):
                answer_records(link.node_to, records)

            if 'v=spf' in link.node_to:
                spf_parse(link.node_from, link.node_to)

        


def check_if_not_already_done(domain):
    r = doesThatFuckingNodeExist( domain )

    if r:
        return False # already done, so do not do it
    else:
        return True # not done, so do it

   

def db_connect():
    try:
        db = GraphDatabase('http://192.168.42.1:7474', username=db_username, password=db_password)
    except Exception as e:
        print(str(e))

    return db

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="domain name (example.com)")
    parser.add_argument("-f", "--file", help="all domain or subdomain in a file (file format: DOMAIN:domain.com\nSUBDOMAIN: sub.domain.com)")
    parser.add_argument("-R", "--remove", help="remove all data into the neo4j db", action="store_true")
    parser.add_argument("-s", "--server", help="name server to use for DNS request (default: 8.8.8.8)")
    args = parser.parse_args()

    if args.domain or args.file:
        if args.domain:
            domain = args.domain
        else:
            domain = None
        if args.file:
            domain_file = args.file
        else:
            domain_file = None
    else:
        print('display the help bitch ...')
        sys.exit(1)

    # name server to use to do DNS requests
    global ns
    if args.server:
        ns = args.server
    else:
        ns = "8.8.8.8"


    global db
    db = db_connect()

    # to clear the DB before making the DNS requests
    if args.remove:
        query = """ MATCH (n)-[r]->() DELETE n,r """
        db.query(query)
        query = """ MATCH (n) DELETE n"""
        db.query(query)

    global Link_tab
    Link_tab = []

    if domain:
        label = "DOMAIN"
        do_the_magic(label, domain)

    if domain_file:
        with open(domain_file, "r") as fp:
            for line in fp:
                line = line.strip()
                label, sep, domain = line.partition(":")
                print("+++++++++++++++++++++++++++++ ")
                print("+++++++++++++++++++++++++++++ " + label)
                print("+++++++++++++++++++++++++++++ " + domain)
                print("+++++++++++++++++++++++++++++ ")
                
                if check_if_not_already_done(domain):
                    do_the_magic(label, domain)
                else:
                    print(YELLOW + "[*] " + domain + " has already been added into the db"  +RESET)

                Link_tab = []
            

    print()
    print("+++++++++++++++++++++++++++++ ")
    print("+++++++++++++++++++++++++++++ HELP")
    print("+++++++++++++++++++++++++++++ ")
    print("[*] display all nodes:\n\t MATCH (n) RETURN n")
    print("[*] display all nodes with relations:\n\t MATCH (n)-[r]->(m) RETURN n,r,m")
    print("[*] display node+relations for 1 specific node:\n\t MATCH (n)-[r]->(m) WHERE n.name='NODE' RETURN n,r,m")
    print("[*] display node+relations for 2 specific nodes:\n\t MATCH (n)-[r]->(m) WHERE n.name='NODE_1'OR n.name='NODE_2' RETURN n,r,m")
    print("[*] display node+relations for 1 specific node and a recursive depth of 2:\n\t MATCH (n)-[r*1..2]->(m) WHERE n.name='NODE' RETURN n,r,m  ")
    



if __name__ == '__main__':
    main()
