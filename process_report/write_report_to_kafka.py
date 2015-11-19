# -*- coding:utf-8 -*-

import os
import sys
import json
from kafka import SimpleProducer, KafkaClient

kafka = KafkaClient('192.168.1.30:9092')
producer = SimpleProducer(kafka)

def write_report(samples_path):
    if os.path.exists(samples_path):
        files = walk_dir(samples_path)
    else:
        print 'No sample dir.'
        exit()

    for i in files:
        if sys.platform.startswith('win'):
            path = samples_path + '\\' + i
        if sys.platform.startswith('linux'):
            path = samples_path + '/' + i

        fp = open(path, 'r')
        sample_info_json = fp.read()
        fp.close()
        #sys_info.add_sample_to_queue(sample_info, vm_type)
        print ("process {0}".format(path))
        #print ("message: {0}".format(sample_info_json))
        producer.send_messages(b'analysis_zc', sample_info_json)

def walk_dir(rootDir):
    length = len(rootDir)
    file_list_cont = []
    list_dir = os.walk(rootDir)
    for root, dirs, files in list_dir:
        for f in files:
            file_list_cont.append(os.path.join(root, f)[length+1:])

    return file_list_cont


if __name__ == '__main__':
    report_path = r'/home/imas/tmp/zc/tmp_zc'
    write_report(report_path)

