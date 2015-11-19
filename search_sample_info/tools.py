#-*- coding:utf8 -*-

from copy import deepcopy
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import sys
import time
from termcolor import cprint

def unique_dict(dict_a, dict_b, key):
    """
    比较两个字典除了指定的键值外，其余键值是否都相同
    相同返回True，不相同返回False
    """
    set_a = set(dict_a.keys())
    set_b = set(dict_b.keys())
    res = set_a.difference(set_b)

    if len(dict_a) != len(dict_b):
        #print 'error: length of the two input dict do not match.'
        return False

    if len(res):
        return False

    for i in dict_a.keys():
        if i == key:
            continue
        if dict_a[i] != dict_b[i]:
            #print 'do not match'
            return False
    #print 'match'
    return True

def unique_dict_part(L):
    #print 'len of input L:\n', len(L)
    #print 'input L:\n', L
    Org = deepcopy(L)
    Res = []
    for i in Org:
        L.remove(i)
        Flag = True
        for j in L:
            try:
                res = cmp(i, j)
            except Exception, e:
                print e
                #print i,j
                continue
            if res == 0:
                #L.remove(j)
                Flag = False
                continue
            if unique_dict(i, j, 'time'):
                #print 'i:\n', i
                #print 'j:\n', j
                #print 'res:\n', res
                #L.remove(j)
                Flag = False
                continue
        if Flag:
            Res.append(i)
    #print 'len of output:\n', len(Res)
    #print 'output Res:\n', Res
    return Res

def unique_list_dict(L):
    """
    去除字典列表中重复的字典
    比如：
    L = [{'k1':'v1','k2':'v2'},{'k1':'v1','k2':'v3'},{'k1':'v1','k2':'v2'},{'k1':'v2','k2':'v2'},{'k1':'v1','k2':'v2'}]
    print uniqueList(L)
    输出 ：[{'k2': 'v2', 'k1': 'v1'}, {'k2': 'v3', 'k1': 'v1'}, {'k2': 'v2', 'k1': 'v2'}]
    """
    (output, temp) = ([],[])
    for l in L:
        for k, v in l.iteritems():
            flag = False
            if (k,v) not in temp:
                flag = True
                break
        if flag:
            output.append(l)
        temp.extend(l.items())
    return output

def unique_list(L):
    """
    去除列表中重复的元素(非字典元素)
    """
    output = sorted(set(L),key=L.index) #去除重复项
    return output

def set_logger(prog_name, log_path):
    # create a logger
    logger = logging.getLogger(prog_name)
    logger.setLevel(logging.DEBUG)

    # create a handler inorder to write log into file
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)

    # create another handler to send info to console
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # split log file into small file
    Rthandler = RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=5)
    Rthandler.setLevel(logging.INFO)

    # define handler's ouput format
    formatter = logging.Formatter('%(asctime)s - %(module)s.%(funcName)s.%(lineno)d - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    Rthandler.setFormatter(formatter)

    # add handler to logger
    #logger.addHandler(fh)
    logger.addHandler(ch)
    logger.addHandler(Rthandler)
    # log one
    # logger.info('hello')
    return logger

"""
compute file or strings hashvalue.
"""
def sumfile(fobj):
    m = hashlib.md5()
    while True:
        d = fobj.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()

def md5sum(fname):
    if fname == '-':
        ret = sumfile(sys.stdin)
    else:
        try:
            f = file(fname, 'rb')
        except:
            return 'Failed to open file'
        ret = sumfile(f)
        f.close()
    return ret

def sumfile_sha1(fobj):
    m = hashlib.sha1()
    while True:
        d = fobj.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()

def sha1sum(fname):
    if fname == '-':
        ret = sumfile_sha1(sys.stdin)
    else:
        try:
            f = file(fname, 'rb')
        except:
            return 'Failed to open file'
        ret = sumfile_sha1(f)
        f.close()
    return ret

def sumfile_sha256(fobj):
    m = hashlib.sha256()
    while True:
        d = fobj.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()

def sha256sum(fname):
    if fname == '-':
        ret = sumfile_sha256(sys.stdin)
    else:
        try:
            f = file(fname, 'rb')
        except:
            return 'Failed to open file'
        ret = sumfile_sha256(f)
        f.close()
    return ret

def time_now():
    return time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())

def print_critical(msg):
    if sys.platform.startswith('win'):
        print ("{0} - CRITICAL - {1}".format(time_now(),msg))
    else:
        cprint ("{0} - CRITICAL - {1}".format(time_now(),msg), color="white", on_color="on_red")

def print_error(msg):
    if sys.platform.startswith('win'):
        print ("{0} - ERROR - {1}".format(time_now(),msg))
    else:
        cprint ("{0} - ERROR - {1}".format(time_now(),msg), color="red")

def print_warning(msg):
    if sys.platform.startswith('win'):
        print ("{0} - WARNING - {1}".format(time_now(),msg))
    else:
        cprint ("{0} - WARNING - {1}".format(time_now(),msg), color="yellow")

if __name__ == '__main__':
    pass
