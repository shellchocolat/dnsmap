#!/usr/bin/python3
import dns.resolver
from ipwhois import IPWhois
import socket
import argparse
import subprocess
from neo4jrestclient.client import GraphDatabase
from ipaddress import ip_network, ip_address
from colorama import Fore
import sys
import os
import re
import whois
from dataclasses import dataclass
import requests
import hashlib
from bs4 import BeautifulSoup as bs

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
class Link_rel:
    node_from: str
    node_from_name: str
    node_to: str
    node_to_name: str
    relation: str


def create_node(LABEL, NODE, TAG):
    """
        check if the node NODE with tag TAG exists
        if yes: do nothing
        if no: create the node
    """
    if NODE != None:
        if doesThatFuckingNodeExist( NODE, TAG ) == True:
            print(YELLOW + '[*] ('+NODE+':'+TAG+') NOT created because it already exists with label: ' + LABEL + RESET)
        else:
            print(GREEN + '[+] ('+NODE+':'+TAG+') created with label: ' + LABEL + RESET)
            try:
                query = """CREATE (n: %s { name: '%s', tag: '%s' })"""%( LABEL, NODE, TAG )
                db.query( query )
            except Exception as e:
                print(RED + "[-] ("+NODE+":"+TAG+") not created because empty value" + RESET)
                #print(str( e ))

    return True

def create_link(NODE_N, TAG_N, RELATION_R, NODE_M, TAG_M ):
    """
        check if relation exists
        if yes: do nothing
        if no: create the relation
    """
    if NODE_N != None and NODE_M != None:
        if doesThatCrazyLinkExist( NODE_N, TAG_N, RELATION_R, NODE_M, TAG_M ) == True:
            print(YELLOW + '[*] ('+NODE_N+':'+TAG_N+')-['+RELATION_R+']-('+NODE_M+':'+TAG_M+') NOT created' + RESET)
        else:
            print(MAGENTA + '[+] ('+NODE_N+':'+TAG_N+')-['+RELATION_R+']-('+NODE_M+':'+TAG_M+') created' + RESET)
            try:
                query = """ MATCH (n { name: '%s', tag: '%s' }), (m { name: '%s', tag: '%s' })
                            CREATE (n)-[r:%s]->(m)"""%( NODE_N, TAG_N, NODE_M, TAG_M, RELATION_R )
                db.query( query )
            except Exception as e:
                print(str( e ))

    return True

def is_website_exist(domain):
    url = domain
    headers = requests.utils.default_headers()
    headers.update({'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'})

    print('***************************************')
    print(url)
    print('***************************************')
    req_http = requests.get('http://' + url, headers)
    if req_http.status_code == 200:
        content_http = get_website_content(req_http)
        content_hash_http = calculate_hash(content_http)
    else:
        content_hash_http = ''

    req_https = requests.get('https://' + url, headers)
    if req_https.status_code == 200:
        content_https = get_website_content(req_https)
        content_hash_https = calculate_hash(content_https)
    else:
        content_hash_https = ''
        
    if content_hash_http == '' and content_hash_https == '':
        # website does not exist
        return False, False

    if content_hash_http == content_hash_https:
        # the http and https are the same website or there is a redirection
        create_node('HTTPS', 'HTTPS', domain)
        create_link(domain, '', 'PROTOCOL', 'HTTPS', domain)

        return False, content_https
    else:
        # http and https are not the same
        create_node('HTTP', 'HTTP', domain)
        create_link(domain, '', 'PROTOCOL', 'HTTP', domain)

        create_node('HTTPS', 'HTTPS', domain)
        create_link(domain, '', 'PROTOCOL', 'HTTPS', domain)

        return content_http, content_https





def get_website_content(req):
    return req.content

def calculate_hash(content):
    h = hashlib.sha1(content)
    return h.hexdigest()

def scrap_url(domain, content, NODE_FROM):
    # HTTP : HTTP or HTTPS
    soup = bs(content, 'html.parser')

    tags = ['a', 'script', 'img', 'link', 'iframe', 'form']
    tag_attr = ['href', 'src', 'action']

    for tag in tags:
        for t in soup.find_all(tag):
            for attr in tag_attr:
                if t.has_attr(attr):
                    # too much link with that ....
                    if 'http' in t[attr] and domain in t[attr]:
                        find_parameter(NODE_FROM, t[attr], tag, True, False)
                    find_path_traversal(NODE_FROM, t[attr], 'LFI_PT_'+tag)
                    find_relative_path(NODE_FROM, t[attr], tag)

    return True

def find_parameter(n1, url,tag, create_PARAM_YES_TF, create_PARAM_NO_TF):
    if n1 == 'HTTP':
        node_from = 'HTTP'
        node_tag = init_domain
    elif n1 == 'HTTPS':
        node_from = 'HTTPS'
        node_tag = init_domain
    else:
        node_from = n1
        node_tag = ''

    if "?" in url:
        if create_PARAM_YES_TF:
            create_node('PARAM_YES', url, '')
            create_link(node_from, node_tag , 'PARAMETER', url, '')
            create_link(node_from, node_tag, tag, url, '')
    else:
        if create_PARAM_NO_TF:
            create_node('PARAM_NO', url, '')
            create_link(node_from, node_tag, tag, url, '')
    if url not in Link_temp_tab:
        if 'http' not in url:
            if url not in Link_all_tab:
                Link_temp_tab.append(url)
                Link_all_tab.append(url)

def find_relative_path(n1, url, tag):
    if n1 == 'HTTP':
        node_from = 'HTTP'
        node_tag = init_domain
    elif n1 == 'HTTPS':
        node_from = 'HTTPS'
        node_tag = init_domain
    else:
        node_from = n1
        node_tag = ''
    # HTTP : HTTP or HTTPS
    if url[0] == '/'  or url[0] == '.': # if the link begins with '/' or '.' and not 'http://'
        if 'www.' not in url:
            find_parameter(node_from, url, tag, True, False)


def find_path_traversal(n1, url, tag):
    if n1 == 'HTTP':
        node_from = 'HTTP'
        node_tag = init_domain
    elif n1 == 'HTTPS':
        node_from = 'HTTPS'
        node_tag = init_domain
    else:
        node_from = n1
        node_tag = ''
    # HTTP : HTTP or HTTPS
    if 'http' in url and '../' in url:
        create_node(tag, url, '')
        create_link(node_from, node_tag, tag, url, '')
    if init_domain in url and '../' in url:
        create_node(tag, url, '')
        create_link(node_from, node_tag, tag, url, '')


    


def zmap_scan(ip_lst):

    #21: ftp
    #22: ssh
    #23: telnet
    #25: smtp
    #53: domain name system
    #80: http
    #110: pop3
    #111: rpcbind
    #135: msrpc
    #139: netbios-ssn
    #143: imap
    #443: https
    #445: microsoft-ds
    #993: imaps
    #995: pop3s
    #1723: pptp
    #3306: mysql
    #3389: ms-wbt-server
    #5900: vnc
    #8080: http-proxy

    ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]


    ips = ""
    for ip in ip_lst:
        ips += ip + " " # construct a string like ip1 ip2 ip3 ...

    for port in ports:
        print(YELLOW + "[*] scannning for opened port " + str(port) + " ..." + RESET)
        cmd = 'sudo zmap -p{0} -f saddr,sport,success -M tcp_synscan -o zmapoutput{2} -B 100k -c 2 -t 3 -v 0 {1}'.format(port,ips,port)
        #print(cmd)
        subprocess.call(cmd.split(), shell=False)

    for port in ports:
        with open("zmapoutput{0}".format(port), "r") as fp:
            lines = fp.readlines()
            lines = lines[1:]

        for line in lines:
                line = line.strip()
                r = line.split(",")
                if r[2] == "1":
                    create_node('PORT', r[1], '')
                    create_link(r[0], '', 'tcp_synscan', r[1], '')

    
def is_ip_into_range(ip, ip_range):
    # True: ip is into the range
    # False: ip is not into the range
    result = ip_address(ip) in net
    return result 


def is_ip(string,record):
    if string != None:
        # determine if the string is an ip
        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', string) != None:
            if record == "A":
                # usefull for scanning if needed
                A_tab.append(string)

            ip = string
            return ip
        else:
            return False
    else:
        return False

def parse_whois(ip):
    init_ip = ip
    if "/" in ip: # if there is a range like x.x.x.x/24
        ip, sep, ip_range = init_ip.partition("/")
    else:
        ip = init_ip

    try:
        # using whois to find network name, asn, ...
        obj = IPWhois(ip)

        res = obj.lookup_rdap()

    except:
        return False

    as_number = "AS" + res["asn"]
    as_owner = res["asn_description"]
    create_node('autonomous_system', as_number, '')
    create_node('autonomous_system', as_owner, '')
    create_link(as_number, '', 'AS_owner', as_owner, '')
    create_link(init_ip, '', 'AS_number', as_number, '')

    netname = res['network']['name']
    create_node('netname', netname, '')
    create_link(init_ip, '', 'netname', netname, '')

    return True


def find_registrar(domain):
    try:
        d = whois.query(domain)
        if d != '':
            return d.registrar
        else:
            return 'registrar not found'
    except:
        return 'registrar not found'



def answer_records(nameServerToUse, domain, records_list):
    ns = nameServerToUse
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

                if q == 'DNSKEY' or q=='CAA' or q == 'NSEC3PARAM':
                    rdata = "DNSSEC"

                if q == 'NS':
                    if rdata not in nameservers:
                        nameservers.append(rdata)

                if q == "AXFR":
                    if rdata:
                        rdata = "AXFR"

                yes_it_is_ip = is_ip(str(rdata), q)

                nodeLabel = node_name
                nodeValue = str(rdata)
                tagNodeValue = ''
                create_node(nodeLabel, nodeValue, tagNodeValue)

                if domain == init_domain:
                    nodeFrom = 'DNS'
                    tagNodeFrom = init_domain
                else:
                    nodeFrom = domain
                    tagNodeFrom = ''
                nodeTo = str(rdata)
                tagNodeTo = ''
                fromLinkTo = node_name
    
                create_link(nodeFrom, tagNodeFrom, fromLinkTo, nodeTo, tagNodeTo)

                if yes_it_is_ip:
                    parse_whois(yes_it_is_ip)

                link = Link_rel(nodeFrom, node_name, nodeTo, node_name, fromLinkTo)
                if link not in Link_rel_tab:
                    Link_rel_tab.append( link )


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

def dmarc_parse(n1, TXT_content, domain):
    TXT_content = TXT_content.replace('"', '')
    TXT_content = TXT_content.replace(' ','')
    elements = TXT_content.split(';')

    if n1 == 'DNS':
        node_from = 'DNS'
        tag_node_from = init_domain
    else:
        node_from = n1
        tag_node_from = ''


    if "v=DMARC" not in elements[0]:
        return False

    dmarc_value = elements[0].replace("v=",'')
    create_node('DMARC', dmarc_value, '')
    create_link(node_from, tag_node_from, 'DMARC_VERSION', dmarc_value, '')

    for e in elements[1:]:
        if "sp" in e:
            create_node("DMARC_POLICY", e, '')
            create_link(node_from, tag_node_from, "SUBDOMAIN_DMARC_POLICY", e, '')
        elif "p=" in e:
            create_node("DMARC_POLICY", e, '')
            create_link(node_from, tag_node_from, "DMARC_POLICY", e, '')
        elif "pct" in e:
            create_node("DMARC_POLICY", e, '')
            create_link(node_from, tag_node_from, "PERCENT_DMARC_POLICY", e, '')
    
    return True
        


def spf_parse(n1,TXT_content, nameServerToUse, records, domain):
    TXT_content = TXT_content.replace('"', '')
    elements = TXT_content.split(' ')

    if n1 == 'DNS':
        node_from = 'DNS'
        tag_node_from = init_domain
    else:
        node_from = n1
        tag_node_from = ''

    if 'v=spf' not in elements[0]:
        return False


    for e in elements[1:]:
        if 'ip4' in e:
            ip = e.replace('ip4:','')
            create_node('SPF_IP', ip, '')
            create_link(node_from, tag_node_from,'SPF_IP', ip, '')

            parse_whois(ip)
        elif 'ip6' in e:
            ip = e.replace('ip6:','')
            create_node('SPF_IP', ip, '')
            create_link(node_from, tag_node_from, 'SPF_IP', ip, '')

            parse_whois(ip)
        elif 'all' in e:
            # all ip are authorized to send email (not good)
            # Pass = The address passed the test; accept the message. Example: "v=spf1 +all"
            if e[0] == '+':
                create_node('spf_all', '+all', '')
                create_link(node_from, tag_node_from, 'spf_all', '+all', '')

            # can send email with other server that those listed (not really good: email spoofing)
            # Soft Fail = The address failed the test, but the result is not definitive; accept & tag any non-compliant mail. Example: "v=spf1 ~all"
            elif e[0] == '~':
                create_node('spf_all', '~all', '')
                create_link(node_from, tag_node_from, 'spf_all', '~all', '')

            # the spf specify that it is neutral and there could be other servers that could send email
            # Neutral = The address did not pass or fail the test; do whatever (probably accept the mail). Example: "v=spf1 ?all"
            elif e[0] == '?':
                create_node('spf_all', '?all', '')
                create_link(node_from, tag_node_from, 'spf_all', '?all', '')

            # only the registred ip (x.x.x.x on the example below)is authorized
            # v=spf1 ip4:x.x.x.x –all
            # if v=spf1 -all, then domain cannot send email at all
            # (Hard) Fail = The address failed the test; bounce any e-mail that does not comply. Example: "v=spf1 -all"
            elif e[0] == '-':
                create_node('spf_all', '-all', '')
                create_link(node_from, tag_node_from, 'spf_all', '-all', '')

        elif 'include' in e:
            inc = e.replace('include:','')
            create_node('INCLUDE', inc, '')
            create_link(node_from, tag_node_from, 'SPF_INCLUDE', inc, '')
            answer_records(nameServerToUse, inc,records)

    return True


def doesThatFuckingNodeExist( NODE_NAME, TAG ):
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
            if ( NODE_NAME in nodeAndTag and TAG in nodeAndTag):
                return True # if node with that specific tag exist, return True
            else:
                continue
        else: # if node with that specific tag does not exist, return False
            return False

def doesThatCrazyLinkExist( NODE_N, TAG_N, RELATION_R, NODE_M, TAG_M ):
    """
        try to get all relationships (links) between NODE_N and NODE_M
        if yes: return True
        if no: return False
    """
    if( doesThatFuckingNodeExist( NODE_N, TAG_N ) == True and doesThatFuckingNodeExist( NODE_M, TAG_M ) == True ):

        query = """ MATCH (n { name: '%s', tag: '%s' })-[r:%s]->(m { name: '%s', tag: '%s' })
                    RETURN SIGN(COUNT(r))"""%( NODE_N, TAG_N, RELATION_R, NODE_M, TAG_M )

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

def zone_transfer(name_server, domain):
    records = ["AXFR"]
    answer_records(name_server, domain, records)

def do_the_magic(nameServerToUse, label, domain):
    # create the domain node
    create_node(label, domain, '')


    if "_dmarc." not in domain:
        try:
            # is there a website for the domain
            # and return the content
            content_http, content_https = is_website_exist(domain)
            # find all urls referenced into the content
            if content_http:
                scrap_url(domain, content_http, 'HTTP')
            if content_https:
                scrap_url(domain, content_https, 'HTTPS')
        except:
            pass
            

        # find registrar
        create_node("WHOIS", 'WHOIS', domain)
        create_link(domain, '', 'WHOIS', 'WHOIS', domain)
        registrar = find_registrar(domain)
        create_node("REGISTRAR", registrar, '')
        create_link('WHOIS', domain, 'REGISTRAR', registrar, '')

        # DNS records
        create_node("DNS", 'DNS', domain)
        create_link(domain, '', 'PROTOCOL', 'DNS', domain)
        records = ['A', 'NS', 'AAAA', 'CNAME', 'MX', 'TXT', 'SPF', 'SRV', 'SOA', 'CAA', 'RRSIG', 'DNSKEY', 'NSEC3PARAM']
        answer_records(nameServerToUse, domain, records)

    else: # for DMARC
        records = ["TXT"]
        answer_records(nameServerToUse, domain, records)


    # get the ip of the answer and create node and link
    for link in Link_rel_tab:
        if link.node_to != None:
            if not is_ip(link.node_to,""):
                answer_records(nameServerToUse, link.node_to, records)

            if 'v=spf' in link.node_to:
                spf_parse(link.node_from, link.node_to, nameServerToUse, records, domain)

            if "v=DMARC" in link.node_to:
                dmarc_parse(link.node_from, link.node_to, domain)


        

        


def check_if_not_already_done(domain):
    r = doesThatFuckingNodeExist( domain, '' )

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
    parser.add_argument("-R", "--removeAll", help="remove all datas into the neo4j db", action="store_true")
    parser.add_argument("-r", "--remove", help="remove only datas for the current domain", action="store_true")
    parser.add_argument("-s", "--server", help="name server to use for DNS request (default: 8.8.8.8)")
    parser.add_argument("-S", "--scan", help="scan current ports for A records", action="store_true")
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
    if args.server:
        nameServerToUse = args.server
    else:
        nameServerToUse = "8.8.8.8"


    global db
    db = db_connect()

    # to clear the DB before making the DNS requests
    if args.removeAll:
        r = input(YELLOW + "[*] are you sure you want to delete all datas from the neo4j db? [y/N] " + RESET)
        if r.lower() == "y":
            query = """ MATCH (n)-[r]->() DELETE n,r """
            db.query(query)
            query = """ MATCH (n) DELETE n"""
            db.query(query)
        else:
            print(GREEN + "[*] Good boy" + RESET)
            sys.exit(1)

    if args.scan:
        scan = True
    else:
        scan = False

    global init_domain, nameservers
    init_domain = domain
    nameservers = []

    global Link_rel_tab, A_tab, Link_temp_tab, Link_all_tab
    Link_rel_tab = [] # contains link relation used to make relation between nodes
    A_tab = [] # contains all the A records in order to port scan eventually
    Link_temp_tab = [] # contains direct link into a website on a given page
    Link_all_tab = [] # contains all links for the specified domain


    if domain:
        if args.remove:
            query = """MATCH p=(n)-[r*1..10]->(m) WHERE n.name='%s' DETACH DELETE p"""%(domain)
            db.query(query)

        label = "DOMAIN"
        do_the_magic(nameServerToUse, label, domain)
        Link_rel_tab = []
        Link_tab = []
        do_the_magic(nameServerToUse, "DMARC","_dmarc." + domain)
        create_link('DNS', domain, "DMARC", "_dmarc."+domain, '')

        if scan:
            zmap_scan(A_tab)

        for n in nameservers:
            zone_transfer(n, domain)

        nameservers = [] # reset the list
        Link_rel_tab = []
        A_tab = []

    if domain_file:
        with open(domain_file, "r") as fp:
            for line in fp:
                line = line.strip()
                label, sep, domain = line.partition(":")
                print("+++++++++++++++++++++++++++++ ")
                print("+++++++++++++++++++++++++++++ " + label)
                print("+++++++++++++++++++++++++++++ " + domain)
                print("+++++++++++++++++++++++++++++ ")

                init_domain = domain # init_domain is a global variable

                if args.remove:
                    query = """MATCH p=(n)-[r*1..4]->(m) WHERE n.name='%s' DETACH DELETE p"""%(domain)
                    db.query(query)
                
                if check_if_not_already_done(domain):
                    do_the_magic(nameServerToUse, label, domain)
                else:
                    print(YELLOW + "[*] " + domain + " has already been added into the db"  +RESET)

                if scan:
                    zmap_scan(A_tab)

                for n in nameservers:
                    zone_transfer(n, domain)

                nameservers = [] # reset the list
                Link_rel_tab = []
                A_tab = []

            do_the_magic(nameServerToUse, "DMARC","_dmarc." + domain)
            create_link('DNS', domain, "DMARC", "_dmarc."+domain, '')
            

    print()
    print("+++++++++++++++++++++++++++++ ")
    print("+++++++++++++++++++++++++++++ HELP")
    print("+++++++++++++++++++++++++++++ ")
    print("[*] display all nodes:\n\t MATCH (n) RETURN n")
    print("[*] display all nodes with relations:\n\t MATCH (n)-[r]->(m) RETURN n,r,m")
    print("[*] display node+relations for 1 specific node:\n\t MATCH (n)-[r]->(m) WHERE n.name='NODE' RETURN n,r,m")
    print("[*] display node+relations for 2 specific nodes:\n\t MATCH (n)-[r]->(m) WHERE n.name='NODE_1'OR n.name='NODE_2' RETURN n,r,m")
    print("[*] display node+relations for 1 specific node and a recursive depth of 2:\n\t MATCH (n)-[r*1..2]->(m) WHERE n.name='NODE' RETURN n,r,m  ")
    print("[*] or use regex to search all nodes that begins with 'tes':\n\t MATCH (n)-[r]->(m) WHERE n.name =~ 'tes.*' RETURN n,r,m")
    print("[*] delete 1 node only:\n\t MATCH p=(n) WHERE n.name='test.com' DELETE p")
    print("[*] delete node with all relationship with depth 4:\n\t MATCH p=(n)-[r*1..4]->(m) WHERE n.name='test.com' DETACH DELETE p")
    



if __name__ == '__main__':
    main()
