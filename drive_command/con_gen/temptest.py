# file=open("have_path.txt","r")
# filelist=file.readlines()
# for line in filelist:
#     linesplit=line.split("  ")
#     print(linesplit[0].strip())
#     print(linesplit[1].strip())
# print(line)
import os
import subprocess
import sys

sys.path.append("../")
from pycparser import c_ast, c_generator, parse_file
from con_gen.deal_return import deal_return

generator = c_generator.CGenerator()
from con_gen.cal_path import get_last_linenum, isincludefuncall1, deal_global_variable, global_dic, modifylocalvarible, \
    find_fun_loop, fun_loop, fun_decl_dic, dir_ast, Ismodifyloclavarible


def is_have_funcall(nextfunname, stmt, linenum, funlist):
    if stmt is None:
        return False
    for s in stmt:
        curlinenum = str(s.coord)
        print(curlinenum)
        if linenum in curlinenum:
            print("line ......")
            stype = type(s)
            print(s)
            if stype == c_ast.FuncCall:
                tempfunname = s.name
                funname = generator.visit(tempfunname)
                if funname == nextfunname:
                    funlist.append("true")
                    funlist.append(s)
                    return True
                else:
                    is_have_funcall(nextfunname, s, linenum, funlist)
            else:
                is_have_funcall(nextfunname, s, linenum, funlist)
        else:
            is_have_funcall(nextfunname, s, linenum, funlist)


def find_called_fun(loopast, linenum, funname, rdic):
    # 获得callend函数的被调用位置pos,被插入的父节点，如何进行插入
    typeloopast = type(loopast)
    if typeloopast == c_ast.For:
        forinit = loopast.init
        funlist = []
        is_have_funcall(funname, forinit, linenum, funlist)
        if len(funlist) > 0:
            print(forinit)

        forcond = loopast.cond
        funlist = []
        is_have_funcall(funname, forcond, linenum, funlist)
        if len(funlist) > 0:
            print(forcond)

        fornext = loopast.next
        funlist = []
        is_have_funcall(funname, fornext, linenum, funlist)
        if len(funlist) > 0:
            print(fornext)

        forstmt = loopast.stmt
        if type(forstmt) == c_ast.Compound:
            pass
        else:
            loopast.stmt = c_ast.Compound(block_items=forstmt)
        newforstmt = loopast.stmt
        for sta in newforstmt.block_items:
            depth = 1
            isincludefuncall1(sta, funname, rdic, depth, linenum, newforstmt.block_items)

    elif typeloopast == c_ast.While:
        whilecond = loopast.cond
        whilestmt = loopast.stmt
    elif typeloopast == c_ast.DoWhile:
        dowhliecond = loopast.cond
        dowhilestmt = loopast.stmt


def judge_line_inloop(funname, startlinenum, ret_list):
    isloop = False
    if funname in fun_loop.keys():
        for loop in fun_loop[funname]:
            loopkey = list(loop.keys())[0].split(":")
            start = int(loopkey[0])
            end = int(loopkey[1])
            templist = list(range(start, end))
            if int(startlinenum) in templist:
                # splitindex = ele
                onlyloopast = loop[list(loop.keys())[0]]
                ret_list.append(onlyloopast)
                # end_ele_index = re_endplus_list.index(ele)
                isloop = True
                break
    return isloop








if __name__ == '__main__':
    fpath = "/home/raoxue/Desktop/llvmref/Overread_Detect_Verify/test_c_source/openssl-1.0.1f/ssl"
    fake_include = "../../utils/fake_libc_include"
    abs_fake_include = os.path.abspath(fake_include)
    pathname = "s3_srvr.c"
    pathname1 = "t1_lib.c"
    command = "cd " + fpath + ";gcc -E " + pathname + " -I../crypto -I.. -I../include -I" + abs_fake_include + " " \
                                                                                                               "-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN " \
                                                                                                               "-DTERMIO -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM" \
                                                                                                               "-DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM >>fun"
    command1 = "cd " + fpath + ";gcc -E " + pathname1 + " -I../crypto -I.. -I../include -I" + abs_fake_include + " " \
                                                                                                                 "-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN " \
                                                                                                                 "-DTERMIO -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM" \
                                                                                                                 "-DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM >>fun1"

    (status, output) = subprocess.getstatusoutput(command)
    (status1, output1) = subprocess.getstatusoutput(command1)
    if status == 0:
        ast = parse_file(fpath + '/fun', use_cpp=True)
        deal_global_variable(ast)
        # 对两个函数进行ssa修改
        fun1_global_list = global_dic['ssl3_send_server_hello']
        modifylocalvarible(ast, 'ssl3_send_server_hello', fun1_global_list)
        fun2_global_list = global_dic['ssl3_accept']
        modifylocalvarible(ast, 'ssl3_accept', fun2_global_list)

        # 找到主调函数中的loop
        find_fun_loop(ast, 'ssl3_accept')

        for ext1 in ast.ext:
            if type(ext1) == c_ast.FuncDef and ext1.decl.name == "ssl3_send_server_hello":
                # return 归一化
                deal_return(ext1, 'ssl3_send_server_hello')
                # print(ext1)
                # print(generator.visit(ext1))
                next_ast = ext1.body.block_items

                funname = 'ssl_add_serverhello_tlsext'
                linenum = '1503'
                for i in next_ast:
                    rdic = []
                    depth = 1
                    isincludefuncall1(i, funname, rdic, depth, linenum, next_ast)
                    if len(rdic) > 0:
                        print(rdic)
                        break
                break

        """判断被调用函数是否在循环中，如果在，得到loop的ast"""
        funname = 'ssl3_send_server_hello'
        linenum = '390'
        ret_list = []
        flag = judge_line_inloop('ssl3_accept', linenum, ret_list)
        if flag:
            """"如果在，在loop中找到被调用函数，找到insert的pos，父节点，插入方式，判断被调用函数是否有返回值，
            # 在此处要进行实参形参传递"""
            rdic = []
            find_called_fun(ret_list[0], linenum, funname, rdic)
            if len(rdic) > 0:
                re_move_code(rdic, funname, next_ast)

                if status1 == 0:
                    print("staus1.....")
                    ast1 = parse_file(fpath + '/fun1', use_cpp=True)
                    deal_global_variable(ast1)
                    # 对两个函数进行ssa修改
                    fun2_global_list = global_dic['ssl_add_serverhello_tlsext']
                    modifylocalvarible(ast1, 'ssl_add_serverhello_tlsext', fun2_global_list)
                    for ext1 in ast1.ext:
                        if type(ext1) == c_ast.FuncDef and ext1.decl.name == "ssl_add_serverhello_tlsext":
                            # return 归一化
                            deal_return(ext1, 'ssl_add_serverhello_tlsext')
                            # print(ext1)
                            # print(generator.visit(ext1))
                            next_ast1 = ext1.body.block_items
                            print(next_ast1)
                            print(generator.visit(ext1.body))

                            funname = 'ssl_add_serverhello_tlsext'
                            linenum = '1503'
                            for i in next_ast:
                                rdic = []
                                depth = 1
                                isincludefuncall1(i, funname, rdic, depth, linenum, next_ast)
                                if len(rdic) > 0:
                                    re_move_code(rdic, funname, next_ast1)
                                    print(ret_list[0])
                                    print(generator.visit(ret_list[0]))
                                    break
                            break
