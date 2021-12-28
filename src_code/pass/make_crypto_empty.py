import os
import re
from string import Template

from pycparser import parse_file

rec = r"\s*\w*\s*\w*\s*[*]?\s*\w*\s*\("
recfun=r"[\s|a-z|A-Z|0-9|\*|_]*\(\*[\s|a-z|A-Z|_]*\)"
funlist=[]
null_body = Template('${st}{\t}\n')
void_body = Template('${st}{\t}\n')
zero_body = Template('${st}{\t}\n')
include_str= Template('#include <openssl/${h}>\n')

include_list=[]
basic_type_list=['int','double','float','char','size_t',"unsigned char",'long','unsigned long','time_t'
                 ,'BN_ULONG']
def judge_retrun_type(s):
    print(s)
    split_list=[]
    substr=""
    for e in s:
        # print(e)
        if e=="*":
            if substr!="":
                split_list.append(substr)
            split_list.append("*")
            substr = ""
        elif e==" ":
            if substr!="":
                split_list.append(substr)
            substr = ""
        elif e=="\t":
            if substr!="":
                split_list.append(substr)
            substr = ""

        elif e=="(":
            if substr!="":
                split_list.append(substr)
            split_list.append("(")
            substr = ""
        elif e==")":
            if substr!="":
                split_list.append(substr)
            split_list.append(")")
            substr = ""
        else:
            substr=substr+e

    loop = 0
    if split_list[1]=="(" or split_list[0]=="(":
        return
    print(split_list)
    for l in split_list:
        if l == "(":
            if split_list[loop + 1] != "*":
                # print(split_list[loop - 1])
                funname = split_list[loop - 1]
                if funname in funlist:
                    break
                else:
                    funlist.append(funname)

                pre_fun = split_list[loop - 2]
                if pre_fun in basic_type_list:
                    file.write(zero_body.substitute(st=s))
                elif pre_fun=="void":
                    file.write(void_body.substitute(st=s))
                else:
                    file.write(null_body.substitute(st=s))

                # print(split_list[loop - 2])
                break
        loop = loop + 1

def entry_source():
    taget_dir = "/home/raoxue/Downloads/copy_openssl/include/openssl"
    print(os.path.abspath(taget_dir))
    abspath_dir = os.path.abspath(taget_dir)
    file_list = os.listdir(taget_dir)
    loop = 0
    for file in file_list:
        abspath_file = abspath_dir + "/" + file
        realpath_file = os.path.realpath(abspath_file)
        if "crypto" in realpath_file:
            include_list.append(include_str.substitute(h=file))
            if True:
                print(realpath_file)

                read_file = open(realpath_file, 'r')
                line_list = read_file.readlines()
                preline = ""
                ifacross = False
                matchline = []
                funptrmathchline = []
                # print(ast)
                enddifine=False
                is_coment=False

                for line in line_list:
                    line=line.lstrip().rstrip()
                    if line.startswith("#define"):
                        # print(line)
                        if line.endswith("\\"):
                            # print("*************")
                            enddifine=True
                            continue
                    if enddifine:
                        if line.endswith("\\"):
                            pass
                        else:
                            enddifine=False
                            ifacross = False
                            preline = ""
                            continue
                    if line.startswith("/*"):
                        if line.endswith("*/"):
                            ifacross = False
                            preline = ""
                            continue
                        else:
                            is_coment=True
                    if is_coment:
                        if line.endswith("*/"):
                            is_coment=False
                            continue
                        else:
                            continue

                    if line.startswith("#") or line.startswith("typedef") or line.startswith("*") or line.startswith("extern"):
                        ifacross = False
                        preline = ""
                        continue
                    if "return" in line or "__bio_h__attr__" in line:
                        ifacross = False
                        preline = ""
                        continue

                    if ifacross:
                        newline = preline.rstrip() + " " + line.lstrip()
                        if "{" in newline:
                            ifacross = False
                            preline = ""
                            continue
                        # print(newline)
                    else:
                        newline = line

                    if ";" in newline:
                        if re.match(rec, newline):

                            if re.match(recfun, newline):
                                funptrmathchline.append(newline)
                                preline = ""
                                ifacross = False
                                continue

                            matchline.append(newline)
                            print(newline)

                            index=newline.find(";")
                            newline=newline[:index+1]
                            templine = newline.lstrip().rstrip()[:-1]
                            judge_retrun_type(templine)

                            # print(newline.rstrip().rstrip()[:-1])
                            preline = ""
                            ifacross = False
                    else:
                        preline = newline
                        ifacross = True

            loop = loop + 1
    pass

# def entry():
#     taget_dir="/home/raoxue/Desktop/openssl-1.0.1f/include/openssl"
#     print(os.path.abspath(taget_dir))
#     abspath_dir=os.path.abspath(taget_dir)
#     file_list = os.listdir(taget_dir)
#     loop=0
#     for file in file_list:
#         abspath_file=abspath_dir+"/"+file
#         realpath_file=os.path.realpath(abspath_file)
#         if "crypto" in realpath_file:
#             include_list.append(include_str.substitute(h=file))
#             if loop==1:
#                 print(realpath_file)
#
#                 ret=os.system('gcc -E -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN -DTERMIO -O0 -g '
#                               '-Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM '
#                               '-DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION '+realpath_file +'>tempfile')
#                 # ast=parse_file("tempfile")
#                 read_file = open(realpath_file, 'r')
#                 line_list=read_file.readlines()
#                 preline=""
#                 ifacross=False
#                 matchline=[]
#                 funptrmathchline=[]
#                 # print(ast)
#
#                 for line in line_list:
#                     if line.startswith("#") or line.startswith("typedef"):
#                         continue
#                     if "extern" in line or "return" in line or "__attribute__" in line or line.startswith("typedef"):
#                         ifacross = False
#                         preline = ""
#                         continue
#
#                     if ifacross:
#                         newline=preline.rstrip()+" "+line.lstrip()
#                         if "{" in newline:
#                             ifacross=False
#                             preline=""
#                             continue
#                         # print(newline)
#                     else:
#                         newline=line
#
#                     if ";" in newline:
#                         if re.match(rec, newline):
#                             if re.match(recfun,newline):
#                                 funptrmathchline.append(newline)
#                                 preline = ""
#                                 ifacross = False
#                                 continue
#                             matchline.append(newline)
#                             templine=newline.lstrip().rstrip()[:-1]
#                             judge_retrun_type(templine)
#
#                             print(newline.rstrip().rstrip()[:-1])
#                             preline=""
#                             ifacross=False
#                     else:
#                         preline=newline
#                         ifacross=True
#
#             loop=loop+1

if __name__ == '__main__':
    file=open("temp_crypto.c","w")
    entry_source()
    file.close()
    tempfile=open("temp_crypto.c","r")
    temp_list = tempfile.readlines()
    tempfile.close()
    genfile = open("gen_crypto.c", "w")
    genfile.write("#include <stdlib.h>\n")
    for i in include_list:
        genfile.write(i)

    for line in temp_list:
        genfile.write(line)
    genfile.close()




