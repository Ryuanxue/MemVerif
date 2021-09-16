import os
import subprocess

import pydot
from pycparser import parse_file, c_ast, c_generator

# from con_gen.cal_path import dir_ast, Ismodifyloclavarible, deal_global_variable, global_dic, modifylocalvarible, \
#     isincludefuncall1, re_move_code
# from con_gen.deal_return import deal_return
# from con_gen.lib_code_gen import split_path
from con_gen.cal_path import modifylocalvarible, global_dic, deal_global_variable, get_lineinfo, get_last_linenum, \
    findid
from con_gen.deal_return import deal_return
from con_gen.lib_code_gen import split_path, split_path_pos, parse_to_ast

pathlist1 = [
    "ssl_add_serverhello_tlsextBB261",
    "ssl_add_serverhello_tlsextBB259",
    "ssl_add_serverhello_tlsextBB255",
    "ssl_add_serverhello_tlsextBB262",
    "ssl_add_serverhello_tlsextBB192",
    "BBssl_add_serverhello_tlsext_end",
    "ssl3_send_server_helloBB555",
    "ssl3_send_server_helloBB556",
    "ssl3_send_server_helloBB558",
    "ssl3_send_server_helloBB546",
    "BBssl3_send_server_hello_end",
    "ssl3_acceptBB96",
    "ssl3_acceptBB98",
    "ssl3_acceptBB99",
    "ssl3_acceptBB101",
    "ssl3_acceptBB103",
    "ssl3_acceptBB104",
    "ssl3_acceptBB77",
    "ssl3_acceptBB262",
    "ssl3_acceptBB23",
    "ssl3_acceptBB30",
    "BBssl3_send_server_hello_start",
    "ssl3_send_server_helloBB537",
    "ssl3_send_server_helloBB539",
    "BBssl3_do_write_start",
    "ssl3_do_writeBB0",
    "ssl3_do_writeBB1",
    "ssl3_do_writeBB3",
    "ssl3_do_writeBB5",
    "BBssl3_finish_mac_start",
    "ssl3_finish_macBB230",
    "ssl3_finish_macBB231",
    "ssl3_finish_macBB233"
]

pathlist = [
    'dtls1_retrieve_buffered_fragmentBB445',
    'dtls1_retrieve_buffered_fragmentBB446',
    'dtls1_retrieve_buffered_fragmentBB447',
    'dtls1_retrieve_buffered_fragmentBB448',
    'dtls1_retrieve_buffered_fragmentBB449',
    'dtls1_retrieve_buffered_fragmentBB438',
    'BBdtls1_retrieve_buffered_fragment_end',
    'dtls1_get_message_fragmentBB138',
    'dtls1_get_message_fragmentBB139',
    'dtls1_get_message_fragmentBB142',
    'dtls1_get_message_fragmentBB143',
    'dtls1_get_message_fragmentBB144',
    'BBdtls1_get_message_fragment_end',
    'dtls1_get_messageBB119',
    'dtls1_get_messageBB120',
    'dtls1_get_messageBB120',
    'dtls1_get_messageBB122',
    'dtls1_get_messageBB121',
    'dtls1_get_messageBB123',
    'dtls1_get_messageBB124',
    'dtls1_get_messageBB127',
    'dtls1_get_messageBB128',
    'dtls1_get_messageBB129',
    'BBssl3_finish_mac_start',
    'ssl3_finish_macBB230',
    'ssl3_finish_macBB231',
    'ssl3_finish_macBB233',
]
dir_ast = {}
Ismodifyloclavarible = []


def getfunnmae(elename):
    if elename.endswith("_start"):
        funname = elename[2:-6]
    elif elename.endswith("_end"):
        funname = elename[2:-4]
    else:
        inde = elename.index("BB")
        funname = elename[:inde]
    return funname


generator = c_generator.CGenerator()


def get_per_linenum(lineinfo):
    if lineinfo.startswith('BB'):
        index = lineinfo.index('/home/')
        l1 = lineinfo[index:]
        ind = l1.index(":")
        relist1_linenum = int(l1[ind + 1:-2])
    else:
        ind = lineinfo.index(":")
        relist1_linenum = int(lineinfo[ind + 1:-2])
    return relist1_linenum


def recurfindline(child, line, blockname, blocknamelist, varlist, tempast, inc_linenum):
    for c in child:
        if c is None:
            break
        else:
            if str(line) in str(c.coord):

                index = blockname.index('BB')
                funn = 'BB' + blockname[:index] + '_start'
                last_num = get_last_linenum(c)
                if len(inc_linenum) == 0:
                    inc_linenum.append(last_num)
                else:
                    inc_linenum[0] = last_num

                # 判断何时需要将声明记录到para_list
                if funn in blocknamelist:
                    pass
                elif type(c) == c_ast.Decl:
                    pass
                else:
                    findid(c, varlist)
                tempast.append(c)
            else:
                recurfindline(c, line, blockname, blocknamelist, varlist, tempast, inc_linenum)


def getfirstline(ele):
    relabel_list = ele.get("label")[2:-2]
    relabellist_list = relabel_list.split("\n")
    for l in relabellist_list:
        if "/home/" in l:
            if l.startswith('BB'):
                index = l.index('/home/')
                l1 = l[index:]
                relist1_linenum = l1
                break
            else:
                relist1_linenum = l
                break
    return relist1_linenum

def parse_dot(bb,dot_dir,ret_list):
    bbfunname = getfunnmae(bb)
    if bbfunname in dot_file.keys():
        filedot = dot_file[bbfunname]
    else:
        dotfile = os.path.abspath(dot_dir) + "/" + bbfunname + ".dot"
        (filedot,) = pydot.graph_from_dot_file(dotfile)
    nodes = filedot.get_nodes()
    # 找到对应第一个字符串的node
    for n in nodes:
        if n.get_name() == bb:
            curnode = n
            break
    # 给定起始行号，判断行号是否小于其实行号，如果小于，则continue
    ast = parse_to_ast(curnode)
    ret_list.append(ast)
    ret_list.append(nodes)
    # return ast

# def parser_to_ast(ele):
#     funname = getfunnmae(ele.get_name())
#     startline = getfirstline(ele)  # 取第一行
#     rindex = startline.rfind(":")
#     rslash = startline.rfind("/")
#     filename = startline[rslash + 1:rindex]
#     pathname1 = startline[:rindex]
#     fpath = startline[:rslash]
#     fake_include = "../../utils/fake_libc_include"
#     abs_fake_include = os.path.abspath(fake_include)
#     if filename in dir_ast.keys():
#         tempast = dir_ast[filename]
#         if funname in Ismodifyloclavarible:
#             pass
#         else:
#             fun_global_list = global_dic[funname]
#             modifylocalvarible(tempast[0], funname, fun_global_list)
#             Ismodifyloclavarible.append(funname)
#     else:
#         command1 = "cd " + fpath + ";gcc -E " + pathname1 + " -I../crypto -I.. -I../include -I" + abs_fake_include + " " \
#                                                                                                                      "-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN " \
#                                                                                                                      "-DTERMIO -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM" \
#                                                                                                                      "-DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM >>fun1"
#
#         (status, output) = subprocess.getstatusoutput(command1)
#         if status == 0:
#             tempast = parse_file(fpath + '/fun1', use_cpp=True)
#             deal_global_variable(tempast)
#             # 对两个函数进行ssa修改
#             fun2_global_list = global_dic[funname]
#             modifylocalvarible(tempast, funname, fun2_global_list)
#             Ismodifyloclavarible.append(funname)
#
#             dir_ast[filename] = []
#             dir_ast[filename].append(tempast)
#             os.remove(fpath + '/fun1')
#     for ext1 in tempast.ext:
#         if type(ext1) == c_ast.FuncDef and ext1.decl.name == funname:
#             deal_return(ext1, funname)
#             ret_ast = ext1
#             break
#     return ret_ast


dot_dir = "../../meta_data/cfg_dot"
dot_file = {}

if __name__ == '__main__':
    split_pathlist = []
    split_path_pos(pathlist, split_pathlist)
    print(split_pathlist)

    # 第一部分
    first_part = split_pathlist[0]
    start = first_part[0]
    end = first_part[1]
    part_path = pathlist[start:end]
    print(part_path)
    # 处理第一部分
    bb = part_path[0]
    # 根据第一个字符串解析.dot文件

    # 给定起始行号，判断行号是否小于起始行号，如果小于，则continue
    templist=[]
    parse_dot(bb,dot_dir,templist)
    tempast=templist[0]
    nodes=templist[1]
    funname= "dtls1_retrieve_buffered_fragment"
    for ext1 in tempast.ext:
        if type(ext1) == c_ast.FuncDef and ext1.decl.name == funname:
            deal_return(ext1, funname)
            ast = ext1
            break
#     return ret_ast

    child = ast.body
    varlist = []
    tempast = []
    inc_linenum = []
    startline = 568
    for p in part_path:
        for n in nodes:
            if n.get_name() == p:
                curele = n
                break
        lineinfo_list = get_lineinfo(curele)
        for l in lineinfo_list:
            print(l)



        for line in lineinfo_list:
            linenum = get_per_linenum(line)
            if len(inc_linenum) > 0 and linenum <= inc_linenum[0]:
                continue
            if linenum < startline:
                continue
            recurfindline(child, linenum, p, pathlist, varlist, tempast, inc_linenum)

    for te in tempast:
        print(generator.visit(te))

    #剩余部分
    #最后一部分
    for i in range(1, len(split_pathlist)):
        print(i)
        cursplit_bb = split_pathlist[i]
        start = cursplit_bb[0]
        end = cursplit_bb[1]
        partpath = pathlist[start:end]
        firstbb = partpath[0]
        templist=[]
        parse_dot(firstbb,dot_dir,templist)
        ast=templist[0]
        nodes=templist[1]
