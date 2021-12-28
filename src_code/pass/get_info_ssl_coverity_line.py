# -*-coding:utf-8-*-
import linecache
import os
from xml.dom.minidom import parse
"""
input:
    ssl direcotory
    ssl_coverity.xml(file and linenum info)
output:
    c statement corresponding to .c file linenum
    
"""

file_list=[]
line_list=[]

def parse_xml(xmlfile):
    doc = parse(xmlfile)
    root = doc.documentElement
    item = root.getElementsByTagName('item')
    for it in item:
        filename=it.getAttribute("file")
        linenum=it.getAttribute("linenum")
        file_list.append(filename)
        line_list.append(linenum)
    pass

def get_line_context(file_path, line_number):
    return linecache.getline(file_path, line_number).strip()

def find_line_info(dir):
    path_list1 = os.listdir(dir)
    i=0
    for fl in file_list:
        fldirpath=dir+"/"+fl
        # print(fldirpath)
        linenum=line_list[i]
        # print(linenum)
        fileinfo=fldirpath+":"+linenum
        print(fileinfo)
        lininfo=get_line_context(fldirpath,int(linenum))
        print(lininfo)
        print("\n")
        i=i+1


if __name__ == '__main__':
    dir="/home/raoxue/Downloads/openssl-1.0.1f/ssl"
    xmlfile="/home/raoxue/Desktop/MemVerif/meta_data/covrity_result/ssl_coverity.xml"

    #parse xmlfile
    parse_xml(xmlfile)

    # find corresponding file in dir
    find_line_info(dir)

