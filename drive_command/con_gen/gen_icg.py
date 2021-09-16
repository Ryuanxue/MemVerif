import json
import os

import pydot

Dir="llvm_out_cg"
path=os.path.abspath(Dir)
path_list = os.listdir(path)

fn_list=[]
for file in path_list:
    filename =os.path.basename(file)
    if filename.endswith(".dot"):
        fn_list.append(filename)


# for i in fn_list:
#     print(i)
#Node string map function name
node_funname={}
Node=[]
Edges=[]
#Node_name=[]
Edge_src_des=[]
m=0
for f in fn_list:

    # if m==4:
    #     break
    print(f)
    (filedot,) = pydot.graph_from_dot_file(str(Dir + "/" + f))
    nodes=filedot.get_nodes()
    edges=filedot.get_edges()
    for n in nodes:
        if str(n.get("label"))[2:-2] in node_funname:

            # print("11111111111")
            pass
        else:
            Node.append(n)
            #print(n.get("label"))
            node_funname[str(n.get("label"))[2:-2]] = []
            node_funname[str(n.get("label"))[2:-2]].append(n.get_name())
            #node_funname[str(n.get("lable"))[2:-2]]=n.get_name()
            #Node_name.append(n.get_name())

    # print(node_funname)
    for e in edges:

        # print(e)
        src=e.get_source()
        dest=e.get_destination()
        srcname=''
        destname=''
        for n in nodes:
            if n.get_name()==src:
                # print("+++++")
                srcname=str(n.get("label"))[2:-2]
            if n.get_name()==dest:
                destname=str(n.get("label"))[2:-2]
        if destname.startswith("llvm"):
            continue
        src=node_funname[srcname]
        dest=node_funname[destname]
        print(destname)
        # print(src)
        # print(dest)
        d=pydot.Edge(src[0],dest[0])
        # print(d)

        # if str(d.get_source()).join("-").join(str(d.get_destination())) in Edge_src_des:
        #     # print("2222222")
        #     pass
        # else:
        Edges.append(d)
        Edge_src_des.append(str(d.get_source()).join("-").join(str(d.get_destination())))
    m=m+1

g= pydot.Dot(graph_name='call graph', graph_type='digraph')
for n in Node:
    name=str(n.get("label"))[2:-2]
    if name.startswith("llvm"):
        continue
    g.add_node(n)
    # print(n)
j=0
for e in Edges:
    g.add_edge(e)
    j=j+1
    print(e)
print(j)
g.write("icg.dot")

# start_file=fn_list[0]
# print(start_file)
# (filedot,)=pydot.graph_from_dot_file(str(Dir+"/"+start_file))
# print(filedot)
# nodes=filedot.get_nodes()
# for f in nodes:
#     print(f.get_name())
#     print(f.get("label"))
#     if f.get_name() in node_funname.keys():
#         pass
#     else:
#         node_funname[f.get_name()]=f.get("label")[2:-2]
#     print(node_funname[f.get_name()])
#
#
#
# edges=filedot.get_edges()
# for e in edges:
#     print(e.get_source()+" "+e.get_destination())

# filedot.add_edge(pydot.Edge("ssl3_read_bytes","one"))
# filedot.add_edge(pydot.Edge("ssl3_read_bytes","Two"))
# filedot.write("ssl3_read_bytes.dot")

# (graph,) = pydot.graph_from_dot_file(str("/home/raoxue/Desktop/openssl-1.0.1f/ssl/callgraph.dot"))
# nodes = graph.get_nodes()
#print(graph)
#for e in nodes:


    #print(e.get_name())




