import os

if __name__ == '__main__':
    dic = "/home/raoxue/Desktop/llvmref/Overread_Detect_Verify/test_c_source/openssl-1.0.1f/ssl"
    abspath = os.path.abspath(dic)
    dicpath = os.listdir(dic)
    os.system("cd "+dic+";rm *.dot")
    for file in dicpath:
        filename = os.path.basename(file)
        if filename.endswith(".ll"):
            if "_instrument" not in filename:
                command="cd "+dic+";opt -load libCFGPass.so -CFG "+filename
                os.system(command)

    os.system("cd ../../meta_data/cfg_dot;rm *.dot")
    dot_path="../../meta_data/cfg_dot"
    dot_abs_path=os.path.abspath(dot_path)
    os.system("cd "+dic+";cp *.dot "+dot_abs_path)
