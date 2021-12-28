#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/User.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/Pass.h>
#include <fstream>
#include <string>
#include "llvm/IR/DebugInfoMetadata.h"
#include <llvm/Analysis/CFG.h>
#include <stdio.h>
#include <map>
#include "llvm/Support/Casting.h"
 #include<set>
#include <iostream>
#include <algorithm>
#include "tinyxml2.h"
#include "llvm/Support/CommandLine.h"
using namespace llvm;
using namespace std;

using namespace tinyxml2;

/**
 * input：.ll file
 * 分析ll文件，获取要分析函数中参数变量涉及到的所有类型信息
 * output：vartype_output.xml
 * */

static cl::opt<std::string> getfunname("funname", cl::desc("Specify function name for this pass"), cl::value_desc("funname"));

/**
 * 编译.c文件到.ll文件
 * 输入.ll文件
 * 待分析的函数名funname
 * 
 * 生成vartype_output.xml
 * 
 * 执行opt-10 -load libvartypepass.so -vartype -funname realfunname filename.ll
 * opt-10 -load libvartypepass.so -vartype -funname d1_both1487s3_pkt881_1 d1_both.ll
 */

namespace 
{
	struct CFGPass : public FunctionPass 
	{
		static char ID;
		string str="_self_creat_";
		int self_num=0;
		CFGPass() : FunctionPass(ID)
		{
			// bbCount = 0;
		}





		template <class T>
		void recur_entry(T *dit,XMLElement *element,XMLElement *root,vector<string> &dealed_struct)
		{
			errs()<<*dit<<"  recur start\n";
			if (DIBasicType *bty=dyn_cast<DIBasicType>(dit))
    		{
    			string btyname=bty->getName().str();
    			if (element->FindAttribute("type")){} else
    			element->SetAttribute("type",btyname.c_str());
    			if(element->FindAttribute("const")){}else 
    			element->SetAttribute("const","");
    			if (element->FindAttribute("ptr")) {}else
    			element->SetAttribute("ptr","");
    			// if (element->FindAttribute("size")){} else
    			// {
    			// 	int size=bty->getSizeInBits()/8;
    			// 	element->SetAttribute("size",size);
    			// }
    			
    			return;


    		}else if(DIDerivedType *didt=dyn_cast<DIDerivedType>(dit))
    		{

    			/**
    			 * tag的值对应的意义
    			 * tag:22  DW_TAG_typedef
    			 * tag:15  DW_TAG_pointer_type,
    			 * tag:38	DW_TAG_const_type,
    			 * */
    			errs()<<*didt<<"\n";
    			unsigned int flag=didt->getTag();		        
    			errs()<<flag<<"  flag\n";

    			// DIDerivedType *opp=dyn_cast<DIDerivedType>(didt->getOperand(3));
    			const MDOperand &opp=didt->getOperand(3) ;
    			
    			// errs()<<*opp<<" opp ...\n";

    			//###########################################
    			if (flag==15)
    			{
    				//指针
    				if (element->FindAttribute("ptr"))
    				{
    					string ptr=element->Attribute("ptr");
    					string newptr=ptr+"*";
    					element->SetAttribute("ptr",newptr.c_str());
    				}else
    				{
    					element->SetAttribute("ptr","*");
    				}

    				// element->SetAttribute("size",8);
    				if (element->FindAttribute("type"))
    					element->SetAttribute("ptr","");
    				if (opp==NULL)
    				{
    					element->SetAttribute("type","void");
    					return;

    				}else
    				{
    					recur_entry(&*opp,element,root,dealed_struct);
    				}
    			

    			}else if(flag==22)
    			{
    				//结构体重命名
    				string tyname=didt->getName().str();
    				element->SetAttribute("type",tyname.c_str());
    				recur_entry(&*opp,element,root,dealed_struct);


    			}else if(flag==38)
    			{
    				//常量const
    				element->SetAttribute("const","const");
    				recur_entry(&*opp,element,root,dealed_struct);

    			}
    			//###########################################

    		}else if(DICompositeType *dict=dyn_cast<DICompositeType>(dit)ge)
    		{
    			int tag=dict->getTag();
    			int size=dict->getSizeInBits()/8;
    			errs()<<tag<<"   array tag\n";
    			if (tag==llvm::dwarf::DW_TAG_array_type){
    				// element->SetAttribute("size",size);
    				element->SetAttribute("type","array");
    				return;

    			}

    			string strname=dict->getName().str();
    			if (strname=="")
    			{
    				element->SetAttribute("ref",(str+to_string(self_num)).c_str());
    			}else
    				element->SetAttribute("ref",strname.c_str());
    			if(element->FindAttribute("type")){}else
    				element->SetAttribute("type",("struct "+strname).c_str());

    			auto stu_it=find(dealed_struct.begin(),dealed_struct.end(),strname);
    			if(stu_it!=dealed_struct.end())
    			{
    				
    				return;
    			}else if(strname==""){}else
    			dealed_struct.push_back(strname);
    			XMLElement *newelement=root->InsertNewChildElement("typedecl");
    			if (strname=="")
    			{
    				newelement->SetAttribute("name",(str+to_string(self_num)).c_str());
    				self_num++;

    			}else
    				newelement->SetAttribute("name",strname.c_str());
    			newelement->SetAttribute("size",size);

				DINodeArray narr=dict->	getElements ();
				for (int i=0;i<narr.size();i++)
				{
					
					DIDerivedType *memdidt=dyn_cast<DIDerivedType>(narr[i]);
					errs()<<*memdidt<< " member varible.....\n";
					XMLElement *filedelement=newelement->InsertNewChildElement("filed");
					string membername=memdidt->getName().str();
					int membersize=memdidt->getSizeInBits()/8;
					filedelement->SetAttribute("name",membername.c_str());
					filedelement->SetAttribute("size",membersize);
					// DIDerivedType *memopp=dyn_cast<DIDerivedType>(memdidt->getOperand(3));
					const MDOperand &memopp= memdidt->getOperand(3);
					recur_entry(&*memopp,filedelement,root,dealed_struct);
					if (tag==llvm::dwarf::DW_TAG_union_type) break;

				}

    		}else if(DISubroutineType *disb=dyn_cast<DISubroutineType>(dit))
    		{
    			element->SetAttribute("funptr","true");
    			return;
    		}else
    		{
    			errs()<<"unknow type........\n";
    			return;
    		}

		}


		bool runOnFunction(Function &F) override
		{
			//解析命令行的输入，获得输入的函数名
			string input_funname;
            for(auto &e : getfunname) 
            {
                string s(1,e);
                input_funname.append(s);         
            }

			//获得当前函数的函数名
			string curfunname=F.getName().str();
			if (curfunname==input_funname)
			{
				//获得函数的所有的参数名子保存在一个数组中
				vector<string> argsname;
				//迭代参数，获得参数名存储

				//遍历指令

				//#######################
				for (int i=0;i<F.arg_size();i++)
				{
					Argument * temparg=F.getArg(i);
					string argname=temparg->getName().str();
					argsname.push_back(argname);
				}

				for(int i=0;i<argsname.size();i++)
				{
					errs()<<argsname.at(i)<<"\n";
				}

				//迭代指令，找到dbgdclare指令

				//############################

				//创建一个xml doc
				XMLDocument doc;
				XMLElement * root ;
				
	  			XMLDeclaration * declaration = doc.NewDeclaration();
				doc.InsertFirstChild(declaration);
				root= doc.NewElement("Root");
				doc.InsertEndChild(root);
      
	 			

	 			//########################################

				for (Function::iterator B_iter = F.begin(); B_iter != F.end(); ++B_iter)
				{
					BasicBlock* curBB = &*B_iter;
					for (BasicBlock::iterator I_iter = curBB->begin(); I_iter != curBB->end(); ++I_iter) 
					{
						
						Instruction *inst = &*I_iter;
						// errs()<<*inst<<"\n";

						if(const DbgDeclareInst* dbgdeclare = dyn_cast<DbgDeclareInst>(inst))
		                {
		                	// errs()<<"covert dbgdeclare.....\n";
		                	//获得此dbgdeclare的Value
		                	//判断value是否与allcoval相等
		                	Value *val=dbgdeclare->getAddress();
		                	// errs()<<*val<<" covert dbgdeclare.....\n";
		                	string dbgname=val->getName().str();
		                	int pos=dbgname.find(".addr");
		                	if (pos>0)
		                	{
								dbgname.replace(pos,5,"");
		                	}
		                	errs()<<dbgname<<"  dbgname\n";
		                	auto ait=find(argsname.begin(),argsname.end(),dbgname);

		                	if(ait!=argsname.end())
		                	{

		                		//#############################

		                		//获得变量的名字，创建相应的arg xml元素
		                		XMLElement * element = root->InsertNewChildElement("arg");
								element->SetAttribute("name", dbgname.c_str());
								// int size=bty->getSizeInBits()/8;

		                		DILocalVariable *dlraw=dbgdeclare->getVariable ();//变量声明， wr p
		                		errs()<<*dlraw <<" metadata .....\n";
		                		DIType *dit=dlraw->getType(); //DIDerivedType
		                		int size=dit->getSizeInBits()/8;
		                		element->SetAttribute("size",size);
		                		//DIType的类型不同，可根据类型不同做不同的处理

		                		//1.基本类型basictype
		                		//2.派生类型DerivedType

		                		vector <string> dealed_struct;

		                	     recur_entry(dit,element,root,dealed_struct);

								
		                	}

		                	

		               
		            	}//if dbgdeclare
					}
	
				}
				const char* xmlPath="vartype_output.xml";
				ifstream fin(xmlPath);
				if(fin)
				{
					remove(xmlPath);

				}
				doc.SaveFile(xmlPath);				
			}//if curfunname==input_funname
			return true;
		}//runonfuncion

	};//struct
}// namespace

char CFGPass::ID = 0;
static RegisterPass<CFGPass> X("vartype", "CFG Pass Analyse",
	false, false);
