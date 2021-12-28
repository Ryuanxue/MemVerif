# -*-coding:utf-8-*-
# -*-coding:utf-8-*-
basic_type_list=['int','double','float','char','size_t',"unsigned char",'long','unsigned long','void']
def judge_retrun_type(s):
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
    return split_list

def idityfy_funnamne(split_list):
    loop=0
    templist=[]
    for l in split_list:
        if l=="(":
            if split_list[loop+1]!="*":
                print(split_list[loop-1])
                funname=split_list[loop-1]
                pre_fun=split_list[loop-2]
                print(split_list[loop-2])
                break
        loop=loop+1




if __name__ == '__main__':
    s="int OPENSSL_sk_num(const OPENSSL_STACK *)"
    s="int (*BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int)"
    s="int	BIO_free(BIO *a){	return NULL;}"
    sl=judge_retrun_type(s)
    print(sl)
    idityfy_funnamne(sl)