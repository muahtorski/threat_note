import sqlite3
import logging
from sqlite3 import Error
from datetime import date
import urllib2
import sys

log_format='%(asctime)s.%(msecs)06d : %(levelname)s : %(message)s'
logging.basicConfig(level=logging.INFO,format=log_format,datefmt='%Y-%m-%d %H:%M:%S')
conn = ""

def create_connection(db_file):
    try: 
        conn = sqlite3.connect(db_file)
        conn.text_factory = str
        return(conn)
    except Error as e:
        logging.error(e)

    return None

def popIndicatorList(conn):
    
    iset = ([])
    try:
        c = conn.cursor()
        sql = "select object from indicators order by object asc"
        logging.info(sql)
        rs = c.execute(sql)
        for row in rs:
            iset.append(row[0])        
    except Error as e:
        logging.error(e)

    return iset

def add_indicator(inConn,inObject,inType,inSource):
    today = date.today().isoformat()

    sFirstSeen = today
    sLastSeen = ""
    sDiamondModel = ""
    sCampaign = ""
    sConfidence="Low"
    sComments="This is a raw indicator that requires analysis to determines its value. Follow the analysis process outlined in the runbook."
    sTags = "NEEDS_ANALYSIS"
    sRelationships = ""

    try:
        sql = ''' INSERT INTO indicators( 
            _id,object,type,firstseen,lastseen,diamondmodel,campaign,confidence,comments,tags,relationships,source)
            VALUES (null,'{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}','{9}','{10}')
        '''.format(inObject,inType,sFirstSeen,sLastSeen,sDiamondModel,sCampaign,sConfidence,sComments,sTags,sRelationships,inSource)
        logging.info(sql)
        inConn.execute(sql)
        inConn.commit()    
    except Error as e:
        logging.error(e)


def main():
    sDatabase = "/home/ec2-user/code/threat_note/threatnote.db"
    conn = create_connection(sDatabase)
    inds = popIndicatorList(conn)
    getIPs(conn,inds)


def getIPs(inConn,inIndicators):
    print("================= getIPs() ====================")
    URL="https://www.dshield.org/ipsascii.html"
    i = 0
    opener = urllib2.build_opener()
    opener.addheaders = [('User-Agent', 'Python/franke.don@gmail.com')]
    response = opener.open(URL)
    lines = response.readlines()
    for line in lines:
        line = line.decode()
        line = line.strip()
        if(line.find("#")<0):
            line = line.split()[0]
            ip = line.split('.')
            oct1=str(int(ip[0]))
            oct2=str(int(ip[1]))
            oct3=str(int(ip[2]))
            oct4=str(int(ip[3]))
            ipfinal=oct1+"."+oct2+"."+oct3+"."+oct4
            j = inIndicators.count(ipfinal)
            print("---{0}---".format(j))
            if(j<1):
                add_indicator(inConn,ipfinal,"IPv4","DShield")
                i+=1

    print("{0} IPs added!".format(i))

if __name__ == '__main__':
    main()
