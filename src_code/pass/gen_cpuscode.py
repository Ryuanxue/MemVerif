import os.path
from string import Template
from xml.dom.minidom import Document
from xml.dom.minidom import parse

# creare a variable
create_var = Template('${type} ${var};\n')
var_assign = Template('${var}=(${type})${data}[$num];\n')
ptrvar_assign = Template('${var}=(${type})&${data}[$num];\n')
struct_ptrfiledname = Template('${parent}->${child}')
struct_nonptrfiledname = Template('${parent}.${child}')
var_assign_setence = Template('${left} = ${right};\n')
i = 0
procecced_type = []
copydata_ele = []
args_byteslice_map = {}


def recur_typr(s, typedecl, name, rdata, strtab, trueptr, const):
    global i
    reftype = s.getAttribute("ref")
    if reftype in procecced_type:
        return
    procecced_type.append(reftype)
    for decl in typedecl:
        declname = decl.getAttribute("name")
        size = decl.getAttribute("size")
        if declname == reftype:
            par_indice = i
            ture_total_size = par_indice
            i = i + int(size)
            print(par_indice)
            print(".......par_indice")
            member_indice = par_indice
            presize = 0
            prerealsize = 0

            filedvar = decl.getElementsByTagName('filed')
            for var in filedvar:
                membername = var.getAttribute("name")
                print(membername)
                memberptr = var.getAttribute("ptr")
                membertype = var.getAttribute("type")
                memberconst = var.getAttribute("const")
                membersize = int(var.getAttribute("size"))

                if var == filedvar[0]:
                    prerealsize = membersize
                    ture_total_size = ture_total_size + membersize
                    print(".......the first element")
                else:
                    if ture_total_size // 8 == (ture_total_size + membersize) // 8:
                        print("?????")
                        member_indice = member_indice + prerealsize
                    elif ture_total_size // 8 != (ture_total_size + membersize) // 8:
                        print("******")
                        if (member_indice + prerealsize) % 8 == 0:
                            member_indice = (member_indice + prerealsize) // 8 * 8
                        else:
                            member_indice = (member_indice + prerealsize) // 8 * 8 + 8
                    prerealsize = membersize
                    ture_total_size = member_indice + membersize

                print(member_indice)
                print(membertype)

                if trueptr:
                    par = struct_ptrfiledname.substitute(parent=name, child=membername)
                else:
                    par = struct_nonptrfiledname.substitute(parent=name, child=membername)
                if var.hasAttribute("ref"):
                    refname = var.getAttribute("ref")
                    if refname == declname:
                        return
                if memberptr == "*" and var.hasAttribute("funptr") is False and const != "const":
                    file.write(
                        strtab + ptrvar_assign.substitute(var=par, type=membertype + memberptr, data=rdata, num=i))
                    if "char" in membertype or "void" in membertype:
                        i = i + 64

                if memberptr == "**":
                    file.write(
                        strtab + ptrvar_assign.substitute(var=par, type=membertype + memberptr, data=rdata, num=i))
                    i = i + 8
                    getvaluestr = Template('*(${name}) = (${type})&data[$num];\n')
                    file.write(strtab + getvaluestr.substitute(name=par, type=membertype + "*", num=i))
                    defptr = Template('${type}* ${vname}=*(${name});\n')
                    file.write(strtab + defptr.substitute(type=membertype, vname=membername + "__", name=par))
                    par = membername + "__"

                if memberptr == "*" and var.hasAttribute("funptr") is False and const == "const":
                    copydata_ele.append(member_indice)
                    copydata_ele.append(i)
                    if "char" in membertype or "void" in membertype:
                        i = i + 64

                # member_indice = member_indice + int(membersize)

                if var.hasAttribute("ref"):
                    if memberptr == "*" or memberptr == "**":
                        recur_typr(var, typedecl, par, rdata, strtab, True, memberconst)
                    else:
                        recur_typr(var, typedecl, par, rdata, strtab, False, memberconst)
            break


def gen_global_var(tabstr, copy):
    for s in args:
        name = s.getAttribute("name") + copy
        ptr = s.getAttribute("ptr")
        if ptr == "*":
            argname = name
        else:
            argname = "*" + name
        if copy == "" and argname not in fun_args:
            fun_args.append(argname)
        type = s.getAttribute("type")

        file.write(tabstr + create_var.substitute(type=type + "*", var=name))


def gen_global_var_low(tabstr):
    for s in args:
        name = s.getAttribute("name") + "low"
        ptr = s.getAttribute("ptr")

        type = s.getAttribute("type")

        wifile.write(tabstr + create_var.substitute(type=type + "*", var=name))


def only_var_assign(rdata, strtab, copy):
    global i
    for s in args:
        name = s.getAttribute("name") + copy
        type = s.getAttribute("type")
        size = s.getAttribute("size")

        args_byteslice_map[name] = [i, type]
        file.write(strtab + ptrvar_assign.substitute(var=name, type=type + "*", data=rdata, num=i))
        # else:
        #     file.write(strtab+var_assign.substitute(var=name, type=type + ptr,data=rdata, num=i))
        # judge a varible whether have a attributre"ref"
        if s.hasAttribute("ref"):
            # if ptr=="*":
            recur_typr(s, typedecl, name, rdata, strtab, True, None)
        # else:
        #     recur_typr(s, typedecl, name, rdata, strtab, False)
        else:
            if "char" in type or "void" in type:
                i = i + 64
            else:
                i = i + int(size)


def high_fun_arg_assign():
    global high_size
    for arg in args:
        name = arg.getAttribute("name")
        if name in hlevel_fun:
            vartype = arg.getAttribute("type")
            size = arg.getAttribute("size")
            if "char" in vartype or "void" in vartype:
                file.write(
                    twotabstr + ptrvar_assign.substitute(var=name, type=vartype + "*", data="data", num=high_size))
                high_size = high_size + 64
            else:
                file.write(
                    twotabstr + ptrvar_assign.substitute(var=name, type=vartype + "*", data="data", num=high_size))
                high_size = high_size + int(size)


def recur_high_struct_assign(s, name, rdata, strtab, trueptr):
    global high_size
    reftype = s.getAttribute("ref")
    if reftype in procecced_type:
        return
    procecced_type.append(reftype)
    for decl in typedecl:
        declname = decl.getAttribute("name")
        if declname == reftype:
            filedvar = decl.getElementsByTagName('filed')
            if declname in hlevel_decl.keys():
                high_var_list = hlevel_decl[declname]
            else:
                high_var_list = []
            for var in filedvar:
                membername = var.getAttribute("name")
                membersize = var.getAttribute("size")
                membertype = var.getAttribute("type")
                memberptr = var.getAttribute("ptr")
                if trueptr:
                    par = struct_ptrfiledname.substitute(parent=name, child=membername)
                else:
                    par = struct_nonptrfiledname.substitute(parent=name, child=membername)
                if len(high_var_list) > 0 and membername in high_var_list:
                    if "char" in membertype or "void" in membertype:
                        file.write(
                            twotabstr + ptrvar_assign.substitute(var=par, type=membertype + memberptr, data=rdata,
                                                                 num=high_size))
                        high_size = high_size + 64
                    else:
                        file.write(twotabstr + var_assign.substitute(var=par, type=membertype + memberptr, data=rdata,
                                                                     num=high_size))
                        high_size = high_size + int(membersize)
                else:
                    pass
                if var.hasAttribute("ref"):
                    memptr = var.getAttribute("ptr")
                    if memptr == "*":
                        recur_high_struct_assign(var, par, rdata, strtab, True)
                    else:
                        recur_high_struct_assign(var, par, rdata, strtab, False)
            break


def gen_call_fun_2_arg(numsize):
    paramstr = "(${var0},"
    for j in range(0, 2):
        # print(j)
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")

    file.write(threetabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1]))


def gen_call_fun_9_arg(numsize):
    paramstr = "(${var0},"
    for j in range(0, 9):
        # print(j)
        if j == 0:
            pass
        elif j == len(fun_args) - 1:
            paramstr = paramstr + "${var" + str(j) + "});"
        else:
            paramstr = paramstr + "${var" + str(j) + "},"
    print(paramstr)
    paramatrtemp = Template(paramstr + "\n")

    file.write(threetabstr + funname + paramatrtemp.substitute(var0=fun_args[0], var1=fun_args[1], var2=fun_args[2],
                                                               var3=fun_args[3],
                                                               var4=fun_args[4],
                                                               var5=fun_args[5], var6=fun_args[6], var7=fun_args[7],
                                                               var8=fun_args[8]))


copare_lowarg = Template('if(*(${left})==*(${right})){}else printf("insecure");\n')
copare_lowchar = Template('if(strcmp(${one},${two})==0){}else printf("insecure");\n')
copare_lowbasic = Template('if(${left}==${right}){}else printf("insecure");\n')


def recur_copare_low(s, name, lowname, trueptr):
    # typedecl
    # hlevel_decl = {}
    reftype = s.getAttribute("ref")
    if reftype in procecced_type:
        return
    procecced_type.append(reftype)
    for decl in typedecl:
        declname = decl.getAttribute("name")
        if declname == reftype:
            filedvar = decl.getElementsByTagName('filed')
            if declname in hlevel_decl.keys():
                high_var_list = hlevel_decl[declname]
            else:
                high_var_list = []
            for var in filedvar:
                membername = var.getAttribute("name")
                membertype = var.getAttribute("type")
                memberptr = var.getAttribute("ptr")
                if trueptr:
                    par = struct_ptrfiledname.substitute(parent=name, child=membername)
                    lowpar = struct_ptrfiledname.substitute(parent=lowname, child=membername)
                else:
                    par = struct_nonptrfiledname.substitute(parent=name, child=membername)
                    lowpar = struct_nonptrfiledname.substitute(parent=lowname, child=membername)
                if len(high_var_list) > 0 and membername in high_var_list:
                    continue
                elif var.hasAttribute("funptr"):
                    continue
                elif var.hasAttribute("ref") and memberptr == "*" or memberptr == "**":
                    recur_copare_low(var, par, lowpar, True)
                elif var.hasAttribute("ref") and memberptr == "":
                    recur_copare_low(var, par, lowpar, False)
                elif ('char' in membertype or "void" in membertype) and memberptr == "*":
                    file.write(threetabstr + copare_lowchar.substitute(one=par, two=lowpar))
                elif memberptr == "*":
                    file.write(threetabstr + copare_lowarg.substitute(left=par, right=lowpar))
                elif memberptr == "**":
                    pass
                else:
                    file.write(threetabstr + copare_lowbasic.substitute(left=par, right=lowpar))
            break

    pass


def compare_lowoutput(threestabstr):
    # args
    # typedecl
    # hlevel_fun = []
    # hlevel_decl = {}
    for arg in args:
        argname = arg.getAttribute("name")
        argtype = arg.getAttribute("type")
        argptr = arg.getAttribute("ptr")
        if argname in hlevel_fun:
            continue
        else:
            if arg.hasAttribute("ref") and argptr == "*":
                recur_copare_low(arg, argname, argname + "low", True)
                continue
            if arg.hasAttribute("ref") and argptr == "":
                recur_copare_low(arg, argname, argname + "low", False)
                continue
            elif 'char' in argtype:
                file.write(threetabstr + copare_lowchar.substitute(one=argname, two=argname + "low"))
            else:
                file.write(threestabstr + copare_lowarg.substitute(left=argname, right=argname + "low"))

        pass


if __name__ == '__main__':
    vartype_output = "vartype_output.xml"
    doc = parse(vartype_output)
    root = doc.documentElement
    args = root.getElementsByTagName('arg')
    typedecl = root.getElementsByTagName('typedecl')
    # funname = "s2_pkt610s2_pkt490_1"
    funname = "fuzztest"

    gencode_output = "fuzzcode.cc"
    if os.path.exists(gencode_output):
        os.remove(gencode_output)
    file = open(gencode_output, "a")

    fun_args = []
    strtab = "\t"
    twotabstr = "\t\t"
    threetabstr = "\t\t\t"

    """definete global varible"""

    # gen_global_var("","copy")
    file.write("int loop=0;\n")
    file.write("int real_loop=0;\n")

    """entry of fuzz LLVMFuzzerTestOneInput"""
    file.write("\n\n")
    file.write('extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)\n ')
    file.write("{\n")
    """generate local varible definition"""
    gen_global_var(strtab, "")

    """condition of loop,aissign of local varible"""
    file.write(strtab + "if (loop/1000==0)\n" + strtab + "{\n")  # if loop/1000==0
    file.write(twotabstr + "if (size>=_num_)\n")
    file.write(twotabstr + "{\n")  # is size
    rdata = "data"
    only_var_assign(rdata, twotabstr, "")

    """assign const in copydata"""
    varindice = 0
    for indice in range(0, len(copydata_ele), 2):
        point_loc = copydata_ele[indice]
        point_to = copydata_ele[indice + 1]
        file.write(twotabstr + "uint8_t *_point_" + str(varindice) + "=&copydata[" + str(point_loc) + "];\n")
        file.write(twotabstr + "long *_point_to_" + str(varindice) + "=(long*)_point_" + str(varindice) + ";\n")
        file.write(twotabstr + "*_point_to_" + str(varindice) + "=(long)&copydata[" + str(point_to) + "];\n")
        varindice = varindice + 1

    procecced_type.clear()
    memcpystr = Template("memcpy(copydata,${arg},size);\n")
    file.write(threetabstr + memcpystr.substitute(arg=fun_args[0]))

    """ call function that need to verify,updata local varible to global varible"""
    argsize = len(fun_args)
    if argsize == 2:
        gen_call_fun_2_arg(i)
    elif argsize == 9:
        gen_call_fun_9_arg(i)

    print(fun_args[0])
    memcpystronece = Template("memcpy(preoutlow,${arg},size);\n")
    file.write(threetabstr + memcpystronece.substitute(arg=fun_args[0]))
    # rdata = "copydata"
    # i = 0
    # only_var_assign(rdata, threetabstr,"copy")
    file.write(threetabstr + "loop++;\n")
    file.write(twotabstr + "}\n")  # if size
    file.write(strtab + "}else\n")  # if (loop/1000==0)

    # else part;when loop!=0
    file.write(strtab + "{\n")  # else entry {

    # assign local varible by global varible
    # for a in fun_args:
    #     glo_str=a+"copy"
    #     file.write(twotabstr+var_assign_setence.substitute(left=a,right=glo_str))

    # parse sec_filename.xml file
    sec_file = "../../meta_data/sec_xmlfile/" + funname + ".xml"
    print(sec_file)
    sec_doc = parse(sec_file)
    sec_root = sec_doc.documentElement
    functionele = sec_root.getElementsByTagName('function')
    declele = sec_root.getElementsByTagName("decl")
    hlevel_fun = []
    hlevel_decl = {}
    for f in functionele:
        paramele = f.getElementsByTagName("params")
        functionname = f.getAttribute("name")
        print(functionname)
        print(paramele)
        for par in paramele:
            if par.hasAttribute("level") and par.getAttribute("level") == "H":
                paraname = par.getAttribute("name")
                hlevel_fun.append(paraname)
    for decl in declele:
        varible_list = decl.getElementsByTagName("variable")
        declname = decl.getAttribute("name")
        for var in varible_list:
            if var.hasAttribute("level") and var.getAttribute("level") == "H":
                varname = var.getAttribute("name")
                if declname in hlevel_decl.keys():
                    hlevel_decl[declname].append(varname)
                else:
                    hlevel_decl[declname] = [varname]

    print(hlevel_decl)
    print(hlevel_fun)
    high_size = 0
    file.write(twotabstr + "if (size>=_highsize_)\n" + twotabstr + "{\n")
    varassignstr = Template("${var}=(${type}*)${name}[${num}];\n")
    for key in args_byteslice_map.keys():
        file.write(twotabstr + varassignstr.substitute(var=key, type=args_byteslice_map[key][1], name="copydata",
                                                       num=args_byteslice_map[key][0]))
        # file.write(twotabstr+key+'=&copydata['+str(args_byteslice_map[key])+"];\n")
        file.write(twotabstr+varassignstr.substitute(var=key + 'low', type=args_byteslice_map[key][1], name="preoutlow",
                                             num=args_byteslice_map[key][0]))
    high_fun_arg_assign()
    procecced_type.clear()
    for arg in args:
        if arg.hasAttribute("ref"):
            argname = arg.getAttribute("name")
            argptr = arg.getAttribute("ptr")
            # if argptr=="*":
            recur_high_struct_assign(arg, argname, "data", twotabstr, True)
            # else:
            #     recur_high_struct_assign(arg, argname, "data", twotabstr, False)
    if argsize == 2:
        gen_call_fun_2_arg(high_size)
    elif argsize == 9:
        gen_call_fun_9_arg(high_size)

    """copare low output..."""
    procecced_type.clear()
    compare_lowoutput(threetabstr)

    file.write(threetabstr + "loop++;\n")
    file.write(twotabstr + "}\n")  # if size>highsize
    # recur assign of high level's variable,need caculate the size

    file.write(strtab + "}\n")  # ele exit }
    file.write(strtab + 'cout<<real_loop<<"\trealloop time.."<<endl;\n')
    file.write(strtab + 'cout<<size<<"\tsize of every time.."<<endl;\n')
    file.write(strtab + "cout<<loop<<'\tloop time';\n");
    file.write(strtab + "return 0;\n");
    file.write(strtab + "real_loop++;\n")
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
    wifile.write(create_var.substitute(type='uint8_t', var='preoutlow[' + str(i) + ']'))
    gen_global_var_low("")
    # for key in args_byteslice_map.keys():
    #     wifile.write( varassignstr.substitute(var=key+'low', type=args_byteslice_map[key][1], name="preoutlow",
    #                                                      num=args_byteslice_map[key][0]))

    for line in line_list:
        if "_num" in line:
            wifile.write(line.replace("_num_", str(i)))
        elif "_highsize_" in line:
            wifile.write(line.replace("_highsize_", str(high_size)))
        else:
            wifile.write(line)

        # else:
        #     wifile.write(line)
    wifile.close()
    print(line_list[0])
    print(copydata_ele)
    print(args_byteslice_map)
