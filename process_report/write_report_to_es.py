import os
"write result to elasticsearch"
ES = True
def import_into_es(doc):
    if ES:
        es_host = "192.168.1.134"
        from elasticsearch import Elasticsearch
        es = Elasticsearch([{'host':es_host}])
        try:
            res = es.index(index="ana_res_zc",doc_type="json",body=doc)
            print "res: {0}".format(res)
        except Exception,e:
            raise e

def main():
    sample_folder = 'tmp_zc'
    files = os.listdir(sample_folder)
    for i in files:
        print("file list: {0}".format(i))
        fp = os.path.join(sample_folder,i)
        if os.path.isfile(fp):
            print("write {0}".format(i))
            doc = open(fp,'r').read()
            import_into_es(doc)

if __name__ == "__main__":
    main()

