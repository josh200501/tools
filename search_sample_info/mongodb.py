# -*- coding: utf8 -*-
import pymongo
import time
import base64
import string
import traceback
import sys
import os
from tools import set_logger
import ConfigParser
from datetime import datetime

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
logger = set_logger('mongodb.py', LOG_FILE)

'==数据库连接操作=='
def connect_readwrite():
    try:
        con = pymongo.Connection(DB_ADDR,DB_PORT)
        db = con.mydb
        db.authenticate(READWRITE,READWRITE_PASSWD)
    except:
        traceback.print_exc()
        logger.critical('Database connect error, exit.')
        exit()
    return db

def connect_readonly():
    try:
        con = pymongo.Connection(DB_ADDR,DB_PORT)
        db = con.mydb
        db.authenticate(READONLY,READONLY_PASSWD)
    except:
        traceback.print_exc()
        logger.critical('Database connect error, exit.')
        exit()
    return db

'==数据库连接操作==END=='


'==样本状态操作=='
def get_static_info_key(search_key, search_value, get_key):
    db = connect_readonly()
    collection = db.logs_static
    res = collection.find_one({search_key:search_value}, {"_id":0, get_key:1})
    if not res:
        res = collection.find_one({search_key:search_value.upper()}, {"_id":0, get_key:1})
    return res


def add_sample_status(sample_status):
    db = connect_readwrite()
    collection = db.status_dynamic
    collection.insert(sample_status)

def get_sample_status_evaluation(hashvalue):
    db = connect_readonly()
    collection = db.status_evaluation
    res = collection.find_one({"hashvalue":hashvalue}, {"_id":0, "process_status":1})
    return res

def add_sample_status_evaluation(sample_status_evaluation):
    db = connect_readwrite()
    collection = db.status_evaluation
    collection.insert(sample_status_evaluation)

def update_sample_process_status_evaluation(hashvalue, key, value):
    db = connect_readwrite()
    collection = db.status_evaluation
    collection.update({"hashvalue":hashvalue},{"$set":{key:value}})

def get_sample_process_status(sample_hashvalue):
    db = connect_readonly()
    collection = db.status_dynamic
    res = collection.find_one(
            {'hashvalue':sample_hashvalue},
            {'_id':0,'process_status':1})
    return res

def get_sample_error_info_in_status_static(sample_hashvalue):
    db = connect_readonly()
    collection = db.status_static
    res = collection.find_one(
            {'hashvalue':sample_hashvalue},
            {'_id':0,'error_info':1})
    return res

def get_sample_error_info_in_status_dynamic(sample_hashvalue):
    db = connect_readonly()
    collection = db.status_dynamic
    res = collection.find_one(
            {'hashvalue':sample_hashvalue},
            {'_id':0,'error_info':1})
    return res

def get_sample_ana_res(sample_hashvalue):
    db = connect_readonly()
    collection = db.status
    res = collection.find_one(
            {'hashvalue':sample_hashvalue},
            {'_id':0, 'ana_res':1})
    return res

def get_sample_execute_para(sample_hashvalue):
    db = connect_readonly()
    collection = db.status_dynamic
    res = collection.find_one(
            {'hashvalue':sample_hashvalue},
            {'_id':0, 'execute_para':1})
    return res

def update_sample_status_info_in_status_evaluation(sample_hashvalue, key, value):
    db = connect_readwrite()
    collection = db.status_evaluation
    collection.update(
            {"hashvalue":sample_hashvalue},
            {"$set":{key:value}})

def get_sample_status_info_in_status_evaluation(sample_hashvalue, key):
    db = connect_readonly()
    collection = db.status_evaluation
    res = collection.find_one(
            {'hashvalue':sample_hashvalue},
            {'_id':0, key:1})
    return res


def update_sample_ana_res(sample_hashvalue, ana_res):
    db = connect_readwrite()
    collection = db.status_dynamic
    collection.update(
            {"hashvalue":sample_hashvalue},
            {"$set":{"ana_res":ana_res}})

def update_sample_process_status(sample_hashvalue, process_status):
    db = connect_readwrite()
    collection = db.status_dynamic
    collection.update(
            {"hashvalue":sample_hashvalue},
            {"$set":{"process_status":process_status}})

def update_sample_execute_para(sample_hashvalue, execute_para):
    db = connect_readwrite()
    collection = db.status_dynamic
    collection.update(
            {"hashvalue":sample_hashvalue},
            {"$set":{"execute_para":execute_para}})

'==样本状态操作==END=='

'==分析队列操作=='
def get_queue(vm_type):
    db = connect_readwrite()
    collection = db.queue

    if vm_type == 'xp':
        collection = db.queue_xp

    if vm_type == 'win7':
        collection = db.queue_win7

    collection = db.queue_dynamic
    return collection

def add_sample_to_queue(sample_info, vm_type):
    collection = get_queue(vm_type)
    collection.insert(sample_info)

def del_sample_from_queue(sample_hashvalue, vm_type):
    collection = get_queue(vm_type)
    collection.remove({"hashvalue":sample_hashvalue})

def update_sample_checked_flag_in_queue_evaluation(hashvalue, flag):
    db = connect_readwrite()
    collection = db.queue_evaluation
    collection.update({"hashvalue":hashvalue}, {"$set":{"checked":flag}},multi=True)


def update_sample_checked_flag_in_queue(sample_hashvalue, vm_type, flag):
    collection = get_queue(vm_type)
    collection.update(
            {"hashvalue":sample_hashvalue},
            {"$set":{"checked":flag}}
            )

def read_queue_evaluation(flag):
    res = []
    """
    LIMIT的值与系统支配的虚拟机数量有关，这里的200是临时取的值，
    实际中要根据虚拟机数量来设定。
    """
    LIMIT = 200
    db = connect_readonly()
    collection = db.queue_evaluation

    cur = collection.find({"checked":flag},{"_id":0})
    length = cur.count()
    if length < LIMIT:
        pass
    else:
        length = LIMIT

    for i in range(length):
        res.append(cur.next())
    return res

def get_queue_evaluation_num():
    db = connect_readonly()
    collection = db.queue_evaluation
    cur = collection.find({})
    return cur.count()

def add_sample_to_evaluation_queue(sample_info):
    db = connect_readwrite()
    collection = db.queue_evaluation
    collection.insert(sample_info)

def store_evaluation_log_to_db(data):
    db = connect_readwrite()
    collection = db.logs_evaluation
    sample_hashvalue = data['hashvalue']
    res = 'success'
    try:
        collection.remove({'hashvalue':sample_hashvalue})
        collection.insert(data)
    except:
        res = 'fail'
        logger.exception('exception')
    return res

def get_sample_config(sample_hashvalue, vm_type):
    """
    read sample configuration of analysis environment.
    """
    collection = get_queue(vm_type)
    data = collection.find_one(
            {"hashvalue":sample_hashvalue},
            {"_id":0, "ana_env_config":1})
    return data

def update_evaluation_in_global_status(sample_hashvalue, flag):
    db = connect_readwrite()
    collection = db.status
    collection.update({"hashvalue":sample_hashvalue}, {"$set":{"evaluation":flag}})

def get_evaluation_in_global_status(sample_hashvalue):
    db = connect_readonly()
    collection = db.status
    res = collection.find_one({"hashvalue":sample_hashvalue}, {"_id":0, "evaluation":1})

def add_evaluation_to_global_status(sample_hashvalue):
    db = connect_readwrite()
    collection = db.status
    collection.insert({"hashvalue":sample_hashvalue})

def get_preparation_for_evaluation(sample_hashvalue):
    db = connect_readonly()
    collection = db.status
    res = collection.find_one({"hashvalue":sample_hashvalue}, {"_id":0})
    return res

def temp():
    db = connect_readwrite()
    collection = db.status
    cur = collection.find({})
    length = cur.count()
    for i in range(length):
        hashvalue = cur.next()['hashvalue']
        cur_n = collection.find({"hashvalue":hashvalue})
        length_j = cur_n.count()
        if length_j > 1:
            for j in range(length_j):
                res = cur_n.next()
                if not "static" in res or "dynamic" in res:
                    print "remove {0}:{1}".format(res['hashvalue'], res['_id'])
                    collection.remove({"_id":res['_id']})
'==分析队列操作==END=='


'==虚拟机列表操作=='
def get_vm_list(vm_type):
    db = connect_readwrite()
    collection = db.vmlist
    try:
        if vm_type == 'xp':
            collection = db.vmlist_xp
        if vm_type == 'win7':
            collection = db.vmlist_win7
    except:
        pass
    return collection


def add_vm_to_vmlist(vm_type, vm_info):
    collection = get_vm_list(vm_type)
    collection.insert(vm_info)

def del_vm_from_vmlist(vm_hashvalue, vm_type):
    collection = get_vm_list(vm_type)
    collection.remove({"hashvalue":vm_hashvalue})

def update_vm_status(vm_hashvalue, vm_type, status):
    collection = get_vm_list(vm_type)
    collection.update({'hashvalue':vm_hashvalue},{'$set':{'status':status}})

def get_idle_vms(vm_type):
    res = []
    collection = get_vm_list(vm_type)
    cur = collection.find({'status':'0'},{'_id':0, 'hashvalue':1})
    length = cur.count()
    if length < 1:
        return res

    for i in range(length):
        try:
            res.append(cur.next()['hashvalue'])
        except Exception, e:
            logger.error(e)
            return res
    return res

def get_vms_status(vm_type):
    res = []
    collection = get_vm_list(vm_type)
    cur = collection.find({},{'_id':0, 'status':1, 'hashvalue':1})

    length = cur.count()
    if length < 1:
        return res

    for i in range(length):
        try:
            res.append(cur.next())
        except Exception, e:
            logger.error(e)
            return res
    return res

def reset_vmlist(vm_type):
    collection = get_vm_list(vm_type)
    collection.update({'status':'1'},{'$set':{'status':'0'}}, multi=True)

def reset_vm_status(vm_hashvalue, vm_type):
    collection = get_vm_list(vm_type)
    collection.update({'hashvalue':vm_hashvalue},{'$set':{'status':'0'}})

def get_vm_info(vm_hashvalue, vm_type):
    collection = get_vm_list(vm_type)
    res = collection.find_one(
            {'hashvalue':vm_hashvalue},
            {'_id':0, 'vminfo':1})['vminfo']
    return res

def clear_vmlist(vm_type):
    collection = get_vm_list(vm_type)
    collection.remove()

def update_vm_counter(vm_hashvalue, vm_type):
    collection = get_vm_list(vm_type)
    collection.update({'hashvalue': vm_hashvalue}, {'$inc':{'counter': 1}})

def update_vm_interval(vm_hashvalue, vm_type, interval):
    collection = get_vm_list(vm_type)

    res = collection.find_one({'hashvalue': vm_hashvalue})
    res['interval'].append(interval)
    collection.update({'hashvalue': vm_hashvalue}, res)

def clear_resource_pool():
    db = connect_readwrite()
    collection = db.resource_pool_evaluation_info
    collection.remove()

def add_item_to_resource_pool(data):
    db = connect_readwrite()
    collection = db.resource_pool_evaluation_info
    collection.insert(data)

def update_resource_status(resource_id,status):
    db = connect_readwrite()
    collection = db.resource_pool_evaluation_info
    collection.update({'id':resource_id},{'$set':{'status':status}})

def get_idle_resources(status):
    res = []
    db = connect_readwrite()
    collection = db.resource_pool_evaluation_info
    cur = collection.find({'status':status},{'_id':0, 'id':1})
    length = cur.count()
    if length < 1:
        return res

    for i in range(length):
        try:
            res.append(cur.next()['id'])
        except Exception, e:
            logger.error(e)
            return res
    return res


'==虚拟机列表操作==END=='

"operation of log"

def store_log(data):
    db = connect_readwrite()
    collection = db.logs_dynamic
    sample_hashvalue = data['hashvalue']
    res = 'success'
    try:
        collection.remove({'hashvalue':sample_hashvalue})
        collection.insert(data)
    except:
        res = 'fail'
        logger.exception('exception')

    return res

def store_evluation_log_to_db(data):
    db = connect_readwrite()
    collection = db.logs_evaluation
    sample_hashvalue = data['hashvalue']
    res = 'success'
    try:
        collection.remove({'hashvalue':sample_hashvalue})
        collection.insert(data)
    except:
        res = 'fail'
        logger.exception('exception')
    return res

def clear_log(sample_hashvalue):
    db = connect_readwrite()
    collection = db.logs_dynamic
    collection.remove({'hashvalue':sample_hashvalue})

def encodepcap(filepath):
    '''
    函数功能：将pcap进行base64编码，返回编码后的数据
    输入参数：pcap文件的路径
    输出参数：经过base64编码的数据
    '''
    f = file(filepath,'rb')
    cont = f.read()
    f.close()
    cont = base64.b64encode(cont)
    return cont

def encode_str(str_file):
    MAX_STR = 2*1024*1024
    f = file(str_file,'r')
    if os.path.getsize(str_file) > MAX_STR:
        cont_str = f.read(MAX_STR)
    else:
        cont_str = f.read()
    f.close()
    try:
        cont = cont_str.decode('gb2312','ignore').encode('utf8')
    except:
        logger.error('fail to convert gb2312 to utf8')
        cont = ""
    return cont

def decode(line):
    '''
    将日志的一行分割成不同的字段，返回各个字段的列表
    输入格式：[0] EXEC_create: pathname=<Idle>, pid=<0>, parent_pid=<0>, cmdline=<>, image_base=<0x0>, image_size=<0>
    输出格式：['action', 'EXEC_create:', 'pathname=<Idle>', 'pid=<0>', 'parent_pid=<0>',...]
    新的格式：['0', 'EXEC_create:', 'pathname=<Idle>', 'pid=<0>', 'parent_pid=<0>',...]
    '''
    b=line.split(' ')   #以空格分割开
    final = b[0:2]  #将前两项加入列表 ['[0]','EXEC_create:']
    time = final[0][1:-1] #'[0]' --> '0' = time
    #print 'time: ',time
    #exit()
    final[0] = 'action' #将'[0]'替换成'action'：['action','EXEC_create:']
    final[0] = string.atoi(time)     #将'[0]'替换成'0'：['0','EXEC_create:']
    #print 'final: ',final
    d = '<'
    res = []
    for i in range(len(b)):
        if d in b[i]:
            #print '包含<的项： ',i
            res.append(i)
    for i in range(len(res)):
        if i+1 >= len(res):
            break
        final.append(" ".join(b[res[i]:res[i+1]]))  #将被分隔开的<xx xx>组合到一块
        #print res1
    final.append(" ".join(b[res[-1]:]))
    #print final 
    return final

def process_one_line(line):
    '''
    函数功能：处理从文件中读取的一行字符串，针对特定的日志格式
    输入格式：
    [0] EXEC_create: pathname=<Idle>, pid=<0>, parent_pid=<0>
    返回值的格式:
    {'time':'0','action':'EXEC_create','pathname':'Idle','pid':'0','parent_pid':'0'}
    '''
    #line = line.strip()
    line = line + ','   #在每行的最后加入','，方便处理
    #print 'line: \n', line
    post = decode(line)
    '''
    post格式如下：
    ['0', 'EXEC_create:', 'pathname=<Idle>', 'pid=<0>', 'parent_pid=<0>']
    '''
    #print 'decoded: \n', post
    key1 = 'time'
    key2 = 'action'
    value1 = post[0]  # 'action' --> '0'
    value2 = post[1][0:-1]  # 去除冒号：'EXEC_create:'->'EXEC_create'
    dict1 = {}
    dict1[key1] = value1
    dict1[key2] = value2
    for i in range(len(post)-2):
        dd = post[i+2].split('=')   # 对于第三项及其以后的元素，每个用'='分割开:'pathname=<Idle>'->'pathname','<Idle>'
        dict1[dd[0]]=dd[1][1:-2]    # 将第一项作为键，第二项作为值加入字典:'pathname','<Idle>'-> {'pathname':'Idle'}
    #print 'dict1: ',dict1
    return dict1

def log2json(logfile):
    '''
    函数功能：将log日志转换（解析）成json格式数据
    输入格式：多行的文本文件
    输出格式：[{'time':'0','action':'xx',...},
            {'time':'1','action':'xx',...},
            {'time':'2','action':'xx',...},
            ...,
            {'time':'n','action':'xx',...}]
    '''
    MAX_LOG = 5*1024*1024
    array = []
    f = file(logfile,'r')
    # 判断文件大小是否超过10M，如果超过则截断
    logger.info('log file size: {0}'.format(os.path.getsize(logfile)))
    if os.path.getsize(logfile) > MAX_LOG:
        cont = f.read(MAX_LOG)
    else:
        cont = f.read()
    f.close()
    #print 'cont size before reencode: ', len(cont)
    cont = cont.decode('gb2312','ignore').encode('utf8')
    #print 'cont size after reencode: ', len(cont)
    '''
    if sys.platform.startswith('win'):
        cont = cont.split("\n")
    if sys.platform.startswith('linux'):
        cont = cont.split("\r\n") #按行分割
    '''
    cont = cont.split("\n") #按行分割
    #print 'len of cont after split: ', len(cont)
    del cont[-1]    #删除cont最后的一个空行或者不完整的行
    for i in cont:
        array.append(process_one_line(i))
    #print 'size of array: ', len(array)
    return array

def pack_old(logfile,pcapfile,hashvalue):
    '将老日志处理成json格式的数据以便于插入数据库（Mongodb）'
    array = []
    dict1 = {}
    f = file(logfile,'r')
    cont = f.read()
    f.close()
    cont = cont.decode('gb2312').encode('utf8')
    cont = cont.split("\n") #按行分割
    del cont[-1]    #删除cont最后的一个空行
    for i in cont:
        #print i
        j = i.split('##')
        if len(j) == 4:
            dict1['time'] = j[0]
            dict1['action'] = j[1]
            dict1['src'] = j[2]
            dict1['dst'] = j[3]
        array.append(dict1)

    f = file(pcapfile,'r')
    cont = encodepcap(pcapfile)

    key = 'actionlist'
    value = array
    key1 = 'pcap'
    value1 = cont
    dict_new = {key:value, key1:value1}
    data = {str(hashvalue):dict_new}
    return data

def pack(logfile,pcapfile,ssfile,strfile,hashvalue):
    '''
    函数功能：返回存入mongodb的json格式数据
    输入参数：log文件路径，pcap文件路径，样本文件的hash值
    返回值格式：
    {
        'hashvalue':'xxx',
        'ana_time':'xx',
        'ana_res':'xx',
        'vm_type':'xx',
        'contents':{
            'actionlist':[
                {'time':'0','action':'xxx',...},
                {'time':'1','action':'xxx',...},
                ...,
                {'time':'n','action':'xxx',...}
            ],
            'pcap':base64encoded,
            'str':base64encoded,
            'ss':base64encoded
        }
    }
    '''
    if os.path.exists(logfile):
        #print 'we have log file.'
        array = log2json(logfile)
    else:
        #print 'we do not have log file'
        array = ""
    if os.path.exists(pcapfile):
        cont = encodepcap(pcapfile)
    else:
        cont = ""
    if os.path.exists(ssfile):
        ss = encodepcap(ssfile)
    else:
        ss = ""
    if os.path.exists(strfile):
        cont_str = encode_str(strfile)
    else:
        cont_str = ""

    key = 'actionlist'
    value = array
    key1 = 'pcap'
    value1 = cont
    key2 = 'ss'
    value2 = ss
    key3 = 'sstr'
    value3 = cont_str
    dict_new = {key:value, key1:value1, key2:value2, key3:value3}
    data = {'hashvalue':str(hashvalue), 'contents':dict_new}
    return data

def read_log_static(hashvalue):
    db = connect_readonly()
    collection = db.logs_static
    res = collection.find_one({"hashvalue":hashvalue},{"_id":0})
    return res

def read_log_dynamic(hashvalue):
    db = connect_readonly()
    collection = db.logs_dynamic
    res = collection.find_one({'hashvalue':hashvalue},{'_id':0})
    if res != None:
        contents = res['contents']
        actionlist = contents['actionlist']
        pcap = contents['pcap']
        pcap = base64.b64decode(pcap)
        static_info = res['static_info']
        ss = contents['ss']
        try:
            sstr = contents['sstr']
        except:
            sstr = ''
        try:
            ana_time = res['ana_time']
        except:
            ana_time = ''
        try:
            ana_res = res['ana_res']
        except:
            ana_res = ''
    else:
        logger.warning('if we do not have this hashvalue, you will see this.')
        actionlist = ''
        pcap = ''
        static_info = ''
        ss = ''
        sstr = ''
        ana_time = ''
        ana_res = ''
    return actionlist, pcap, static_info, ss, sstr, ana_time, ana_res

if  __name__ == '__main__':
    pass

