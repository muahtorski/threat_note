#!/usr/bin/python
import ast
import sqlite3
import logging
from sqlite3 import Error
from datetime import date
import urllib2
import sys
import boto3
import config
from botocore.exceptions import ClientError


log_format='%(asctime)s.%(msecs)06d : %(levelname)s : %(message)s'
logging.basicConfig(level=logging.INFO,format=log_format,datefmt='%Y-%m-%d %H:%M:%S')
conn = ""


def getS3Credentials():
    client = boto3.client(
        'secretsmanager',
        region_name='us-east-1',
        aws_access_key_id=config.sm_key,
        aws_secret_access_key=config.sm_secret
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId="SANS_S3_Credentials"
        )

        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            data = ast.literal_eval(secret)
            #logging.info(data['sans_s3_key'])
            #logging.info(data['sans_s3_secret'])
            return(data)
        else:
            logging.error("Value not found")

    except ClientError as e:
       logging.error(e) 


def writeToFile(inList,inCreds):
    sBucket="sans-giac-guardduty"

    #1. open s3 file
    #client = boto3.client(
    #    's3',
    #    region_name='us-east-1',
    #    aws_access_key_id=inCreds['sans_s3_key'],
    #    aws_secret_access_key=inCreds['sans_s3_secret']
    #)
    logging.info("key: {0} secret: {1}".format(inCreds['sans_s3_key'],inCreds['sans_s3_secret']))
    s3 = boto3.resource( 
        's3',
        region_name='us-east-1',
        aws_access_key_id=inCreds['sans_s3_key'],
        aws_secret_access_key=inCreds['sans_s3_secret']
    )

    #bucket = s3.Bucket('sans-giac-guardduty')

    logging.info("===== writeToFile() =====")
    iplist = ""
    for ip in inList:
        iplist+=ip+","

    logging.info(iplist)
    #bData = ' '.join(format(ord(x), 'b') for x in iplist) 
    s3.Object(sBucket, 'threatlist.txt').put(Body=iplist)






def create_connection(db_file):
    try:
        conn = sqlite3.connect(db_file)
        conn.text_factory = str
        return(conn)
    except Error as e:
        logging.error(e)

    return None

def getReadyIndicators(conn):
    logging.info("===== getReadyIndicators() =====")
  
    iset = ([])
    try:
        c = conn.cursor()
        sql = "select object from indicators where tags like '%READY_TO_PUSH%' order by object asc"
        rs = c.execute(sql)
        for row in rs:
            iset.append(row[0])
    except Error as e:
        logging.error(e)

    return iset



def main():
    logging.info("===== main() =====")
    sDatabase = "/home/ec2-user/code/threat_note/threatnote.db"
    #1. get credentials for s3
    s3_creds=getS3Credentials()

    conn = create_connection(sDatabase)
    #2. get list of ips that need to be added to GuardDuty
    inds = getReadyIndicators(conn)
    
    #3. write IPs to S3 file for GuardDuty to pick up
    writeToFile(inds,s3_creds)
    
    #4. update ips in database, set tag to "ADDED_TO_GUARD_DUTY"


    #5. close db conn
    conn.close()



if __name__ == '__main__':
    main()
