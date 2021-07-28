import boto3
import json
import requests
import dns
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *
from dns.message import *
from dns.query import *
import dns.resolver


# doamin = gppgle.com
def NSdomaintakeover(domain):
    res =  dns.resolver.Resolver()
    takeover = None
    awsnslist =[]

    try : 
        Nsrecord =  res.query(domain, "NS")
        #print(Nsrecord)
    
    except DNSException as error:
        return takeover
    
    awstargetns = []
    for i in Nsrecord:
        if "awsdns" not in str(i):
            return takeover
        else:
            awstargetns.append(str(i))
            try:
                nsip = res.query(str(i), "A")
                for j in nsip:
                    awsnslist.append(str(j))
            
            except:
                continue
    
    for z in awsnslist:
        nameser =  z
        response = None
        query = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
        query.flags ^= dns.flags.RD
        cname = []
        try: 
            cnamerequest = res.query(domain, "CNAME")
            for j in cnamerequest:
                cname.append(j)
        except DNSException:
            cname= []
        #print(cname)
        
        if not cname:
            try:
                response = dns.query.udp(query, nameser)
                #print("test")
                #print(response)
                if response.rcode() == dns.rcode.REFUSED:
                    print("Domain : " + domain)
                    print("NSservers takeover is possible: \n" + ",".join(awstargetns))
                    takeover = domain
                elif response.rcode() == dns.rcode.SERVFAIL:
                    print( " Domain: " + domain)
                    print("NSservers takeover is possible: \n" + ",".join(awstargetns))
                    takeover = domain
                else:
                    print(nameser + "\n" + "NS Takeover is not possible")

            except DNSException:
                return None
        else:
            return None

def vul_alias_cf_s3(domain):
    try:
        response =  requests.get('https://' + domain, timeout = 1)
        if response.status_code == 404 and "Code: NoSuchBucket" in response.text:
            return True
        else:
            return False
    
    except:
        pass

    try:
        response =  requests.get('http://', domain, timeout = 1)
        if response.status_code == 404 and "Code: NoSuchBucket" in response.text:
            return True
        else:
            return False
    
    except:
        return False

def vul_alias_eb(domain):
    global a_records
    try: 
        a_records = dns.resolver.resolve(domain, "A")
        return False
    except dns.resolver.NoAnswer:
        return True
    except:
        print("error while fetching CNAME record for {}", format(domain))

def vul_s3_alias(domain):
    try:
        response = requests.get("http://" + domain, timeout= 1)
        if response.status_code == 404 and "Code: NoSuchBucket" in response.text:
            return True
        else:
            return False
    except:
        return False

def vul_cname_cf_s3(domain):
    try:
        response =  requests.get('https://' + domain, timeout = 1)
        if response.status_code == 404 and "Code: NoSuchBucket" in response.text:
            return True
        else:
            return False
    
    except:
        pass

    try:
        response =  requests.get('http://', domain, timeout = 1)
        if response.status_code == 404 and "Code: NoSuchBucket" in response.text:
            return True
        else:
            return False
    
    except:
        return False


def vul_cname_eb(domain):
    arecord =  None
    try:
        arecord =  dns.resolver.resolve(domain_name, 'A')
        return False
    except dns.resolver.NXDOMAIN:
        if dns.resolver.resolve(domain_name, 'CNAME'):
            return True, ""
        else:
            return False, "\tI: Error fetching CNAME Records for " + domain_name
    except:
        return False, ""


def vul_cname_s3(domain):
    try:
        response =  requests.get('https://' + domain, timeout = 1)
        if response.status_code == 404 and "Code: NoSuchBucket" in response.text:
            return True
        else:
            return False
    
    except:
        pass

    try:
        response =  requests.get('http://', domain, timeout = 1)
        if response.status_code == 404 and "Code: NoSuchBucket" in response.text:
            return True
        else:
            return False
    
    except:
        return False
        
def main():
    session = boto3.Session(profile_name='default')
    boto3.setup_default_session(profile_name='default')

    r53 = boto3.client('route53')
    try:
        r53_paginator = r53.get_paginator('list_hosted_zones')
        r53_page_iterator = r53_paginator.paginate()
        
        for page in r53_page_iterator:
            h_zones = page['HostedZones']
            
            for h_zone in h_zones:
                if not h_zone["Config"]['PrivateZone']:
                    try:
                        p_records = r53.get_paginator('list_resource_record_sets')
                        page_records =  p_records.paginate(HostedZoneId=h_zone['Id'])
                        for pages_records in page_records:
                            r_sets =  pages_records['ResourceRecordSets']
                            
                            for record in r_sets:
                                #print(record['Name'])
                                if "ResourceRecords" in record:
                                    if "cloudfront.net" in record['ResourceRecords'][0]['Value']:
                                        domain = record['Name']
                                        res = vul_cname_cf_s3(domain)
                                        if res:
                                            print("vulnerable cf  domain" + " " +"--------->" +" "+ domain)
                                        else:
                                            print("Domain is Secure"+ " " +"--------->" +" "+ domain)
                                    
                                    elif "elasticbeanstalk.com" in record['ResourceRecords'][0]['Value']:
                                        domain = record['Name']
                                        res = vul_cname_eb(domain)

                                        if res:
                                            print("vulnerable cf  domain" + " " +"--------->" +" "+ domain)
                                        else:
                                            print("Domain is Secure"+ " " +"--------->" +" "+ domain)
                                    
                                    elif "amazonaws.com" in record['ResourceRecords'][0]['Value'] and ".s3-website." in record['ResourceRecords'][0]['Value']:
                                        domain = record['Name']
                                        res = vul_cname_s3(domain)
                                        if res:
                                            print("vulnerable s3  domain" + " " +"--------->" +" "+ domain)
                                        else:
                                            print("Domain is Secure"+ " " +"--------->" +" "+ domain) 
                                    elif record["Type"] == "NS":
                                        domain = record['Name']
                                        NSdomaintakeover(domain)
                                    
                                    else:
                                        None 
                                
                                elif "AliasTarget" in record:
                                    if "cloudfront.net" in record["AliasTarget"]["DNSName"] and "AAAA" not in record["Type"]:
                                        domain  = record['Name']
                                        alias =  record["AliasTarget"]["DNSName"]
                                        res =  vul_alias_cf_s3(domain)
                                        if res:
                                            print("vulnerable cloudfront domain" + " " +"--------->" +" "+ domain)
                                            print("missing resource" + " " + "----------->" + alias)
                                        else:
                                            print("Domain is Secure"+ " " +"--------->" +" "+ domain)
                                    elif "elasticbeanstalk.com" in record['AliasTarget']['DNSName']:
                                        domain  = record['Name']
                                        alias =  record["AliasTarget"]["DNSName"]
                                        res = vul_alias_eb(domain)
                                        if res:
                                            print("vulnerable elasticbean domain" + " " +"--------->" +" "+ domain)
                                            print("missing resource" + " " + "----------->" + alias)
                                        else:
                                            print("Domain is Secure"+ " " +"--------->" +" "+ domain)
                                    elif ("amazonaws.com" in record['AliasTarget']['DNSName']) and ".s3-website." in (record['AliasTarget']['DNSName']):
                                        domain  = record['Name']
                                        alias =  record["AliasTarget"]["DNSName"]
                                        res = vul_s3_alias(domain)
                                        if res:
                                            print("vulnerable s3 domain" + " " +"--------->" +" "+ domain)
                                            print("missing resource" + " " + "----------->" + alias)
                                        else:
                                            print("Domain is Secure"+ " " +"--------->" +" "+ domain)
                                    else:
                                        None
                                
                                
                                



                    except:
                        pass

    except:
        pass                        




if __name__ == "__main__":
    main()
