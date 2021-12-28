# -*-coding:utf-8-*-
import os
import re
import shutil


def copydir(inputdir, outdir):
    path_list = os.listdir(inputdir)
    for file in path_list:
        newinput=inputdir+"/"+file
        newoutput=outdir+"/"+file

        if os.path.isdir(newinput):
            if os.path.exists(newoutput):
                pass
            else:
                os.makedirs(newoutput)
            copydir(newinput,newoutput)
        elif os.path.splitext(file)[1] ==".h" or os.path.splitext(file)[1]==".c":
            file1 = open(newinput, "r", encoding='utf-8',errors='ignore')
            file2 = open(newoutput, 'w', encoding='utf-8')
            try:
                print(newinput)
                for line in file1.readlines():
                    if "const" in line:
                        # line = line.replace("const", "")
                        line = re.sub(r'\bconst\b', "", line)
                    file2.write(line)
            finally:
                file1.close()
                file2.close()


            # file1 = open(newinput, "r", encoding='utf-8')
            # file2 = open(newoutput, 'w', encoding='utf-8')
            # try:
            #     for line in file1.readlines():
            #         file2.write(line)
            # finally:
            #     file1.close()
            #     file2.close()
        else:
            shutil.copyfile(newinput, newoutput)







if __name__ == '__main__':
    # input:inputdir
    # output:outputdir
    inputdir="/home/raoxue/Downloads/openssl-1.0.1f"
    outdir="/home/raoxue/Downloads/copy_openssl"

    # input="/home/raoxue/Downloads/openssl-1.0.1f/crypto/x509v3/v3_pcia.c"
    # output="/home/raoxue/Downloads/copy_openssl/temp.c"
    # file1 = open(input, "r", encoding='utf-8',errors='ignore')
    # file2 = open(output, 'w', encoding='utf-8')
    # try:
    #     # print(newinput)
    #     for line in file1.readlines():
    #         if "const" in line:
    #             # line = line.replace("const", "")
    #             line=re.sub(r'\bconst\b',"",line)
    #         file2.write(line)
    # finally:
    #     file1.close()
    #     file2.close()
    if os.path.exists(outdir):
        pass
    else:
        os.makedirs(outdir)
    copydir(inputdir,outdir)