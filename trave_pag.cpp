//===- svf-ex.cpp -- A driver example of SVF-------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===-----------------------------------------------------------------------===//

/*
 // A driver program of SVF including usages of SVF APIs
 //
 // Author: Yulei Sui,
 */


#include "op_pag.h"




static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));

static llvm::cl::opt<bool> LEAKCHECKER("leak", llvm::cl::init(false),
                                       llvm::cl::desc("Memory Leak Detection"));


int main(int argc, char ** argv) {


    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "Whole Program Points-to Analysis\n");

    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);
    svfModule->buildSymbolTableInfo();
    
	/// Build Program Assignment Graph (PAG)
		PAGBuilder builder;
		PAG *pag = builder.build(svfModule);

		//添加间接调用边
		add_diretcall(pag,svfModule);


		//定义一些变量接收xml文件中解析的内容
		vector<string> functionset;
		string srcfun;
		int linenum;
		string varname;

		vector<PAGNode *> wite_deal_node;
		vector<PAGNode *>  dealed_node_set;
		vector<vector<string>> outstring;


		//获得xml中的内容
		string srcinfo_input_xml="dfa_input.xml";
		parse_input_xml(srcinfo_input_xml, functionset,srcfun,linenum,varname);


		//根据函数名，行号，变量名找到src_len所在的PAGNode
		int node_id = find_src_pagnode(pag,srcfun,linenum,varname,svfModule);

		if(node_id>0)
		{
			PAGNode* src_node=pag->getGNode(node_id);

			//将节点添加到wite_deal_node集合中
			//将节点添加到dealed_node_set集合中
			wite_deal_node.push_back(src_node);
			dealed_node_set.push_back(src_node);


			//如果wite_deal_node集合不为空，循环处理集合中的每一个节点
			string funname=functionset.at(0);
			loop_deal_node(pag,wite_deal_node,dealed_node_set,functionset,funname,outstring,svfModule);

			//处理outstring中的输出结果，保存到dfa_output.xml文件中
			string dfa_output="dfa_output.xml";
			create_xml(dfa_output,outstring);
		}else
		{
			SVFUtil::outs()<<"can't find target node....\n";
			exit(1);
		}
		
    return 0;
}

