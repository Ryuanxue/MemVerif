import os
from xml.dom.minidom import parse
import pydot
import sys
sys.path.append("../")
from con_gen.cal_path_copy import main_entry, get_funname_and_funedgs


if __name__ == '__main__':
    dic = "/home/raoxue/Desktop/llvmref/Overread_Detect_Verify/test_c_source/openssl-1.0.1f/ssl"
    abspath = os.path.abspath(dic)
    dicpath = os.listdir(dic)
    sorce_info = []
    sink_info = []
    for file in dicpath:
        filename = os.path.basename(file)
        if filename.endswith(".xml"):
            if filename == "sink.xml":
                doc = parse(dic + "/" + filename)
                root = doc.documentElement
                ovreadsrc = root.getElementsByTagName("ovreadsrc")
                for overread in ovreadsrc:
                    c_filename = overread.getAttribute("c_filename")
                    sinkline = overread.getAttribute("linenum")
                    str1 = c_filename + "#" + sinkline + "#"
                    sink_info.append(str1)

            else:
                doc = parse(dic + "/" + filename)
                root = doc.documentElement
                ovreadsrc = root.getElementsByTagName("ovreadsrc")
                for overread in ovreadsrc:
                    c_filename = overread.getAttribute("c_filename")
                    srcline = overread.getAttribute("srcline")
                    str1 = c_filename + "#" + srcline + "#"
                    sorce_info.append(str1)

    # for i in sorce_info:
    #     print(i)
    #
    # print("\n"
    #       "\n3#######################\n")
    #
    # for i in sink_info:
    #     print(i)
    dot_file = "../../meta_data/_icfg.dot"
    (filedot,) = pydot.graph_from_dot_file(dot_file)

    nodes = filedot.get_nodes()
    edges = filedot.get_edges()
    get_funname_and_funedgs(nodes, edges)
    outdir = "../../meta_data/code_gened"
    # for source in sorce_info:
    #     for sink in sink_info:
    #         src_in=source.split("#")
    #         srcfile=src_in[0]
    #         srcline=src_in[1]
    #         sink_in=sink.split("#")
    #         sinkfile=sink_in[0]
    #         sinkline=sink_in[1]
    #         print(srcfile)
    #         print(srcline)
    #         print(sinkfile)
    #         print(sinkline)
    #         dot_file="../../meta_data/_icfg.dot"
    #         out_cfile=srcfile[:-2]+srcline+sinkfile[:-2]+sinkline+".c"
    #         gen_funname = srcfile[:-2] + srcline + sinkfile[:-2] + sinkline
    #         outfile=os.path.abspath(outdir)+"/"+out_cfile
    #         main_entry(srcfile,srcline,sinkfile,sinkline,filedot,nodes,edges, outfile,gen_funname)

    file = open("have_path.txt", "r")
    filelist = file.readlines()
    for line in filelist:
        linesplit = line.split("  ")
        srcinfo = linesplit[0].strip().split(":")
        sinkinfo = linesplit[1].strip().split(":")
        srcfile = srcinfo[0]
        srcline = srcinfo[1]
        # sink_in=
        sinkfile = sinkinfo[0]
        sinkline = sinkinfo[1]
        outdir = "../../meta_data/code_gened"
        out_cfile = srcfile[:-2] + srcline + sinkfile[:-2] + sinkline + ".c"
        gen_funname = srcfile[:-2] + srcline + sinkfile[:-2] + sinkline
        outfile = os.path.abspath(outdir) + "/" + out_cfile
        dot_file = "../../meta_data/_icfg.dot"
        main_entry(srcfile, srcline, sinkfile, sinkline, filedot, nodes, edges, outfile, gen_funname)


    # print(linesplit)

    # d1_pkt.c:1592   s3_pkt.c:881
    # src_in="d1_pkt.c"
    # srcfile = "s2_srvr.c"
    # srcline = "907"
    # # sink_in=
    # sinkfile = "s2_pkt.c"
    # sinkline = "490"
    # outdir = "../../meta_data/code_gened"
    # out_cfile = srcfile[:-2] + srcline + sinkfile[:-2] + sinkline + ".c"
    # gen_funname = srcfile[:-2] + srcline + sinkfile[:-2] + sinkline
    # outfile = os.path.abspath(outdir) + "/" + out_cfile
    # dot_file = "../../meta_data/_icfg.dot"
    # main_entry(srcfile, srcline, sinkfile, sinkline, filedot, nodes, edges, outfile, gen_funname)
