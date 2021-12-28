# -*-coding:utf-8-*-
import os
import re
import sys

"""
input:
    /home/raoxue/Downloads/SARD-testsuite-108
output:
    all badsink info
    all badsource info
    
"""

cwetype=["CWE121","CWE122","CWE123","CWE124","CWE126","CWE127"]
sstype=["BadSource","GoodSource","BadSink","GoodSink"]
badsink=[]
def zhushi(path1):
    path_list1 = os.listdir(path1)
    for file in path_list1:
        repath = path1 + "/" + file
        # print(repath)
        if os.path.isdir(repath):
            zhushi(repath)
        elif os.path.splitext(file)[1] == ".c":
            lindex=file.find("_")
            cwe=file[:lindex]
            if cwe in cwetype:
                pass
            else:
                continue
            file1 = open(repath, "r", encoding='utf-8')
            # print(file)
            for line in file1.readlines():
                reline=line.lstrip()
                # if reline.startswith("*") and "BadSource" in line:
                #     print(line)
                # elif reline.startswith("*") and "GoodSource" in line:
                #     print(line)
                # elif reline.startswith("*") and "BadSink" in line:
                #     print(line)
                # elif reline.startswith("*") and "GoodSink" in line:
                #     print(line)
                if reline.startswith("*") and "BadSink" in line:
                    if line in badsink:
                        pass
                    else:

                        print(file)
                        print(line)
                        badsink.append(line)

                else:
                    pass
            file1.close()
            # print("\n")
            # print("########")
        else:
            pass

if __name__ == '__main__':
    path1="/home/raoxue/Downloads/SARD-testsuite-108"
    zhushi(path1)
    # zhushi(sys.argv[1])



