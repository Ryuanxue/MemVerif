# -*-coding:utf-8-*-
import os.path
from string import Template
from xml.dom.minidom import Document
from xml.dom.minidom import parse

# from toy_test import count_location

# creare a variable
create_var = Template('${type} ${var};\n')
var_assign = Template('${var}=(${type})${data}[$num];\n')
ptrvar_assign = Template('${var}=(${type})&${data}[$num];\n')
struct_ptrfiledname = Template('${parent}->${child}')
struct_nonptrfiledname = Template('${parent}.${child}')
var_assign_setence = Template('${left} = ${right};\n')
pointer_point_str=Template('${po}=&${p_to};\n')
i = 0
procecced_type = []
copydata_ele = []
args_byteslice_map = {}

const_i = 0
first_one = True

prerealsize = 0

total_size_arr = []

strtab = "\t"
twotabstr = "\t\t"
threetabstr = "\t\t\t"
fun_args = []


def recur_typr(s, typedecl, name, rdata, strtab, trueptr, const):
    global i
    global const_i
    global first_one
    global ture_total_size
    global prerealsize
    reftype = s.getAttribute("ref")
    if reftype in procecced_type:
        return
    procecced_type.append(reftype)
    for decl in typedecl:
        declname = decl.getAttribute("name")
        size = decl.getAttribute("size")

        if declname == reftype:
            par_indice = i
            # ture_total_size = par_indice
            intsize = int(size)
            if intsize % 8 != 0:
                intsize = intsize // 8 * 8 + 8
            i = i + intsize
            # print(par_indice)
            # print(".......par_indice")
            member_indice = par_indice
            print(declname)
            print(member_indice)

            filedvar = decl.getElementsByTagName('filed')
            ture_total_size = 0
            for var in filedvar:
                membername = var.getAttribute("name")
                # print(membername)
                memberptr = var.getAttribute("ptr")
                membertype = var.getAttribute("type")
                memberconst = var.getAttribute("const")
                membersize = int(var.getAttribute("size"))
                # retsize=count_location(total_size_arr)

                if var == filedvar[0]:
                    # print("prerealsize   " + str(prerealsize))
                    prerealsize = membersize
                    ture_total_size = membersize
                    first_one = False
                    # print("membersize   " + str(membersize))
                    # print("total_size   " + str(ture_total_size))
                    # print("member_slice   " + str(member_indice))
                    # print("i   "+str(i))
                    # print("\n")
                    # print(".......the first element")
                else:
                    if ture_total_size // 8 == (ture_total_size + membersize) // 8:
                        # print("?????")
                        member_indice = member_indice + prerealsize
                    elif ture_total_size // 8 != (ture_total_size + membersize) // 8:
                        # print("******")
                        if (ture_total_size + membersize) % 8 == 0 and (
                                ture_total_size + membersize - 8) // 8 == ture_total_size // 8:
                            member_indice = member_indice + prerealsize
                        elif (member_indice + prerealsize) % 8 == 0:
                            member_indice = (member_indice + prerealsize) // 8 * 8
                        else:
                            member_indice = (member_indice + prerealsize) // 8 * 8 + 8
                    # print("prerealsize   "+str(prerealsize))
                    prerealsize = membersize
                    if var.hasAttribute("ref"):
                        pass
                    else:
                        ture_total_size = member_indice + membersize
                    # print("membersize   "+str(membersize))
                    # print("totao_size   "+str(ture_total_size))
                    # print("member_slice   "+str(member_indice))
                    # print("i   " + str(i))
                    # print(membername)
                    # print(par)

                # print(member_indice)
                # print(membertype)
                if member_indice > i:
                    print(membername)
                    print(par)
                    exit(1)

                if trueptr:
                    par = struct_ptrfiledname.substitute(parent=name, child=membername)
                else:
                    par = struct_nonptrfiledname.substitute(parent=name, child=membername)
                # print(par)
                # print("\n")
                if var.hasAttribute("ref"):
                    refname = var.getAttribute("ref")
                    if refname == declname:
                        continue
                # if i % 8 != 0:
                #     print(i)
                #     print(par)
                #     exit()
                if var.hasAttribute("funptr"):
                    file.write(strtab+par+"= NULL;\n")

                if memberptr == "*" and var.hasAttribute("funptr") is False and const != "const":
                    file.write(
                        strtab + ptrvar_assign.substitute(var=par, type=membertype + memberptr, data=rdata, num=i))
                    if "char" in membertype or "void" in membertype:
                        i = i + 64
                        file.write(strtab + "copydata[" + str(i - 1) + "]=" + "'\\0';\n")

                if memberptr == "**":
                    file.write(
                        strtab + ptrvar_assign.substitute(var=par, type=membertype + memberptr, data=rdata, num=i))
                    i = i + 8
                    getvaluestr = Template('*(${name}) = (${type})&data[$num];\n')
                    file.write(strtab + getvaluestr.substitute(name=par, type=membertype + "*", num=i))
                    defptr = Template('${type}* ${vname}=*(${name});\n')
                    if "char" in membertype:
                        pass
                    else:
                        file.write(strtab + defptr.substitute(type=membertype, vname=membername + "__", name=par))
                        par = membername + "__"

                if memberptr == "*" and var.hasAttribute("funptr") is False and const == "const":
                    copydata_ele.append(member_indice)
                    copydata_ele.append(i)
                    file.write(
                        strtab + "long *_point_" + str(const_i) + "=(long *)&copydata[" + str(member_indice) + "];\n")
                    file.write(
                        strtab + " *_point_" + str(const_i) + "=(long)&copydata[" + str(i) + "];\n")

                    const_i = const_i + 1
                    if "char" in membertype or "void" in membertype:
                        i = i + 64
                        file.write(strtab + "copydata[" + str(i - 1) + "]=" + "'\\0';\n")

                if var.hasAttribute("ref"):
                    if memberptr == "*" or memberptr == "**":
                        recur_typr(var, typedecl, par, rdata, strtab, True, memberconst)
                    else:
                        recur_typr(var, typedecl, par, rdata, strtab, False, memberconst)
            procecced_type.pop()
            break


def gen_global_var(tabstr, args):
    for s in args:
        name = s.getAttribute("name")
        ptr = s.getAttribute("ptr")
        type = s.getAttribute("type")
        if ptr == "*" :
            argname = name
            # if type=="char":
            #     file.write(tabstr+create_var.substitute(type=type,var="base_"+name+"[64]"))
            # else:
            #     file.write(tabstr + create_var.substitute(type=type, var="base_" + name))

        else:
            argname = "*" + name
        if  argname not in fun_args:
            fun_args.append(argname)


        file.write(tabstr + create_var.substitute(type=type + "*", var=name))
        # if ptr == "*":
        #     file.write(tabstr+pointer_point_str.substitute(po=name,p_to="base_"+name))





def only_var_assign(rdata, strtab, args,typedecl):
    global i
    for s in args:
        name = s.getAttribute("name")
        type = s.getAttribute("type")
        size = s.getAttribute("size")

        args_byteslice_map[name] = [i, type]
        file.write(strtab + ptrvar_assign.substitute(var=name, type=type + "*", data=rdata, num=i))
        if s.hasAttribute("ref"):
            recur_typr(s, typedecl, name, rdata, strtab, True, None)
        else:
            if "char" in type or "void" in type:
                i = i + 64
                file.write(strtab + "copydata[" + str(i - 1) + "]=" + "'\\0';\n")
            else:
                i = i + int(size)



def gen_call_fun_1_arg():
    paramstr = "(${var0})"


    paramatrtemp = Template(paramstr + ";\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0]))


def gen_call_fun_2_arg():
    paramstr = "(${var0},"
    for j in range(0, 2):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1]))


def gen_call_fun_3_arg():
    paramstr = "(${var0},"
    for j in range(0, 3):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2]))


def gen_call_fun_4_arg():
    paramstr = "(${var0},"
    for j in range(0, 4):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2],
                                                               var3=fun_args[3]))


def gen_call_fun_5_arg():
    paramstr = "(${var0},"
    for j in range(0, 5):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2],
                                                               var3=fun_args[3],
                                                               var4=fun_args[4]))


def gen_call_fun_6_arg():
    paramstr = "(${var0},"
    for j in range(0, 6):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2],
                                                               var3=fun_args[3],
                                                               var4=fun_args[4], var5=fun_args[5]))


def gen_call_fun_7_arg():
    paramstr = "(${var0},"
    for j in range(0, 5):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2],
                                                               var3=fun_args[3],
                                                               var4=fun_args[4], var5=fun_args[5], var6=fun_args[6]))


def gen_call_fun_8_arg():
    paramstr = "(${var0},"
    for j in range(0, 5):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")
    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2],
                                                               var3=fun_args[3],
                                                               var4=fun_args[4], var5=fun_args[5], var6=fun_args[6],
                                                               var7=fun_args[7]))


def gen_call_fun_9_arg():
    paramstr = "(${var0},"
    for j in range(0, 9):
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")

    file.write(twotabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2],
                                                               var3=fun_args[3],
                                                               var4=fun_args[4],
                                                               var5=fun_args[5], var6=fun_args[6], var7=fun_args[7],
                                                               var8=fun_args[8]))


copare_lowarg = Template('if(*(${left})==*(${right})){}else {printf("insecure"); exit(1);}\n')
copare_lowchar = Template(
    'if(strcmp((const char*)${one},(const char*)${two})==0){}else {printf("insecure");exit(1);}\n')
copare_lowbasic = Template('if(${left}==${right}){}else {printf("insecure");exit(1);}\n')





def main_entry(vartype_output):
    doc = parse(vartype_output)
    root = doc.documentElement
    args = root.getElementsByTagName('arg')
    typedecl = root.getElementsByTagName('typedecl')

    """definete global varible"""

    file.write("int loop=0;\n")
    file.write("int real_loop=0;\n")

    """entry of fuzz LLVMFuzzerTestOneInput"""
    file.write("\n\n")
    file.write('extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)\n ')
    file.write("{\n")
    """generate local varible definition"""
    gen_global_var(strtab,args)



    """condition of loop,aissign of local varible"""
    file.write(strtab + "if (size>=_num_)\n")
    file.write(strtab + "{\n")  # is size

    memcpystr = Template("memcpy(copydata,${arg},size);\n")
    file.write(twotabstr + memcpystr.substitute(arg="data"))
    rdata = "copydata"
    only_var_assign(rdata, twotabstr,args,typedecl)


    """ call function that need to verify,updata local varible to global varible"""
    argsize = len(fun_args)
    if argsize==1:
        gen_call_fun_1_arg()
    elif argsize == 2:
        gen_call_fun_2_arg()
    elif argsize==3:
        gen_call_fun_3_arg()
    elif argsize==4:
        gen_call_fun_4_arg()
    elif argsize==5:
        gen_call_fun_5_arg()
    elif argsize==6:
        gen_call_fun_6_arg()
    elif argsize==7:
        gen_call_fun_7_arg()
    elif argsize==8:
        gen_call_fun_8_arg()
    elif argsize == 9:
        gen_call_fun_9_arg()


    file.write(twotabstr + "loop++;\n")
    file.write(strtab + "}\n")  # if size


    file.write(strtab + 'cout<<real_loop<<"\trealloop time.."<<endl;\n')
    file.write(strtab + 'cout<<size<<"\tsize of every time.."<<endl;\n')
    file.write(strtab + 'cout<<loop<<"\tloop time"<<endl;\n');
    file.write(strtab + "real_loop++;\n")
    file.write(strtab + "return 0;\n");
    file.write("}\n")  # exter"C"
    file.close()

    refile = open(gencode_output, "r")
    line_list = refile.readlines()
    refile.close()

    wifile = open(gencode_output, "w")
    # print(line_list[0].replace("_num_",str(i)))
    wifile.write('#include "fuzz.h"\n')
    wifile.write("using namespace std;\n")
    wifile.write(create_var.substitute(type='uint8_t', var='copydata[' + str(i) + ']'))

    for line in line_list:
        if "_num" in line:
            wifile.write(line.replace("_num_", str(i)))
        else:
            wifile.write(line)

    wifile.close()

if __name__ == '__main__':
    vartype_output = "vartype_output.xml"
    funname = "ssl3_send_server_done" #custom function name
    gencode_output = "fuzz_funlevel.cc" #genarated filename
    if os.path.exists(gencode_output):
        os.remove(gencode_output)
    file = open(gencode_output, "a")
    main_entry(vartype_output)



