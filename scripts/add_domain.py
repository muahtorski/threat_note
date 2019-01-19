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

    print(iset)
    j = "xoxo2019.ml" in iset
    print("===={0}====".format(j))
    return iset

def add_indicator(inConn,inObject,inType):
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
            _id,object,type,firstseen,lastseen,diamondmodel,campaign,confidence,comments,tags,relationships)
            VALUES (null,'{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}','{9}')
        '''.format(inObject,inType,sFirstSeen,sLastSeen,sDiamondModel,sCampaign,sConfidence,sComments,sTags,sRelationships)
        logging.info(sql)
        inConn.execute(sql)
        inConn.commit()    
    except Error as e:
        logging.error(e)


def main():
    sDatabase = "/home/ec2-user/code/threat_note/threatnote.db"
    conn = create_connection(sDatabase)
    inds = popIndicatorList(conn)
    getDomains(conn,inds)

def getDomains(inConn,inIndicators):
    print("================= getDomains() ====================")
    URL="http://dns-bh.sagadc.org/domains.txt"
    i = 0
    response = urllib2.urlopen(URL)
    lines = response.readlines()
    for line in lines:
        line = line.decode()
        #line = re.sub(r"\t","",line)
        line = line.strip()
        if(line.find("#")<0):
            line = line.split()[:1][0]
            if ((line.find("2019")>-1)):
                j = inIndicators.count(line)
                print("---{0}---".format(j))
                if(j<1):
                    add_indicator(inConn,line,"IPv4")
                    i+=1

    print("{0} domains added!".format(i))


if __name__ == '__main__':
    main()
