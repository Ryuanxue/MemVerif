import pydot

funnameset=['strlen','printLine']
indiret_call_dic={}
if __name__ == '__main__':
    filename='icfg_final.dot'
    (filedot,) = pydot.graph_from_dot_file(filename)
    nodes = filedot.get_nodes()
    edges = filedot.get_edges()
    for e in edges:
        src=e.get_source()
        if ":" in src:
            index=src.index(":")
            srcc=src[:index]
        else:
            srcc=src
        dest= e.get_destination()
        srcnode=filedot.get_node(srcc)
        destnode=filedot.get_node(dest)
        srclabel=srcnode[0].get_label()
        destlabel=destnode[0].get_label()
        if "fun" not in srclabel or "fun" not in destlabel:
            continue

        srcfunindex=srclabel.index("fun:")
        srclastindex=srclabel[srcfunindex:].index("\\")
        srcfunname=srclabel[srcfunindex:][5:srclastindex]
        # print(destlabel)

        destfunindex = destlabel.index("fun:")
        destlastindex = destlabel[destfunindex:].index("\\")
        destfunname = destlabel[destfunindex:][5:destlastindex]

        if srcfunname!=destfunname and not destfunname.startswith("llvm") and "call" in srclabel \
                and destfunname not in funnameset:
            if srcfunname not in indiret_call_dic.keys():
                indiret_call_dic[srcfunname]=[]
            indiret_call_dic[srcfunname].append(destfunname)

            # print(srclabel)
            # print(destlabel)
            # print("#######")
        # print(srcfunname)
        # print(destfunname)
    print(indiret_call_dic)

        # print(srcnode[0].get_label())
        # print(destnode[0].get_label())
