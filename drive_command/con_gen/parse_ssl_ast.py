import os
import subprocess
import sys

from pycparser import parse_file, c_ast

from con_gen.cal_path import modifylocalvarible

if __name__ == '__main__':
    fake_include="../../utils/fake_libc_include"
    abs_fake_include=os.path.abspath(fake_include)
    savedStdout = sys.stdout  #保存标准输出流


    fpath="/home/hp/Desktop/llvmref/Overread_Detect_Verify/test_c_source/openssl-1.0.1f/ssl"
    pathname="/home/hp/Desktop/llvmref/Overread_Detect_Verify/test_c_source/openssl-1.0.1f/ssl/s3_pkt.c"
    command = "cd "+fpath+";gcc -E " + pathname + " -I../crypto -I.. -I../include -I"+abs_fake_include+" " \
                                         "-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN " \
                                         "-DTERMIO -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM" \
                                         "-DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM >>fun"
    (status, output) = subprocess.getstatusoutput(command)
    print(output)
    if status == 0:
        ast = parse_file(fpath+'/fun',use_cpp=True)
        print(ast)
        file=open("parse_temp.txt","w")
        # file.write(ast)
        # file.close()

        sys.stdout = file  #标准输出重定向至文件
        print(ast)
        sys.stdout = savedStdout  #恢复标准输出流
        # for fun in ast.ext:
        #     if type(fun) == c_ast.FuncDef:
        #         funname=fun.decl.name
        #         modifylocalvarible(ast,funname)
