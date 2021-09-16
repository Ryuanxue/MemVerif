import re
import subprocess

file = open("FunName.txt","r", encoding='utf-8')

Dir="/home/raoxue/Desktop/openssl-1.0.1f/ssl/"

for line in file.readlines():
    #print(line)

    if ".ll" in line:
        #print("2222")

        line=line.strip()
        line = line.replace(".ll", ".c")
        List=re.split(" ",line)
        filename=List[0]
        funname=List[1]
        command="cflow -b -d 2 "+Dir+filename+" -m "+funname+" |tree2dotx >>out/"+funname+".dot"
        print(command)

        (status, output) = subprocess.getstatusoutput(command)
        print(status)
        print(output)
        #print(line)

        """cflow - b - d
        2 - o
        out / dtsl_do_write.dot
        d1_both.c - m
        dtls1_do_write | tree2dotx >> dtsl_do_write.do"""