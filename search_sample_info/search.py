#!/usr/bin/env python
import os
import sys
import ConfigParser
from mongodb import get_static_info_key
from tools import set_logger

config_file = os.getcwd() + '/config.ini'
cf = ConfigParser.ConfigParser()
cf.read(config_file)
DB_ADDR = cf.get('mongodb','addr')
DB_PORT = int(cf.get('mongodb','port'),10)
READONLY = cf.get('mongodb','readonly_user')
READONLY_PASSWD = cf.get('mongodb','readonly_password')
READWRITE = cf.get('mongodb','readwrite_user')
READWRITE_PASSWD = cf.get('mongodb','readwrite_password')
LOG_FILE = os.path.join(os.getcwd(), cf.get('support','log_path'))
logger = set_logger('search.py', LOG_FILE)

def get_compiler(hashvalue):
    res = get_static_info_key("hashvalue", hashvalue, "compiler")
    if not res:
        return "NULL"
    return res["compiler"]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logger.info("usage: program <hashvalue>")
        sys.exit(1)
    else:
        hashvalue = sys.argv[1]
        res = get_compiler(hashvalue)
        logger.info("compiler: {0}".format(res))

