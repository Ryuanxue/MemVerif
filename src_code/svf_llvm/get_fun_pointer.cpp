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
 #include<set>
#include <map>
#include <iostream>
#include <algorithm>
#include "llvm/Support/CommandLine.h"
 
#include "llvm/Support/Casting.h"

using namespace llvm;
using namespace std;

static cl::opt<std::string> getxmlfilename("xmlfile", cl::desc("Specify function name for mypass"), cl::value_desc("xmlfilename"));



namespace 
{
	struct PProcessPass : public FunctionPass 
	{
		static char ID;
		std::string str;
	
		PProcessPass() : FunctionPass(ID)
		{
		}

		bool runOnFunction(Function &F) override
		{
      string funname=F.getName().str();
      // if (funname=="ssl3_send_server_key_exchange")
      // {
        for (auto bb_iter=F.begin();bb_iter!=F.end();++bb_iter)
        {
          for (auto ins_iter=bb_iter->begin();ins_iter!=bb_iter->end();++ins_iter)
          {
            if(StoreInst *storeinst=dyn_cast<StoreInst>(ins_iter))
            {
              Value *opvalue=ins_iter->getOperand(0);
              Value *sevalue=ins_iter->getOperand(1);
              Type *setype=sevalue->getType();
              // errs()<<*setype<<"\n";
              // errs()<<*opvalue<<"\n";



              if(Function *fun=dyn_cast<Function>(opvalue))
              {
                errs()<<fun->getName().str()<<"\n";
                errs()<<*storeinst<<"\n";
                if (DILocation *Loc = ins_iter->getDebugLoc())
                    {
                                                
                      
                      int Line = Loc->getLine();
                      errs()<<Line<<"\n";
                      // File = Loc->getFilename().str();
                      // Dir = Loc->getDirectory().str();
                    }
                errs()<<"\n";
              }
            // }

            /**
             * 获得所有数组类型分配的bound
             * */
            // if( AllocaInst *allo = dyn_cast<  AllocaInst>(ins_iter))
            // {
            //   Type *allotype=allo->getAllocatedType();
            //   if (ArrayType *arrtypr=dyn_cast<ArrayType>(allotype))
            //   {
            //     errs()<<*ins_iter<<"\n";
            //     errs()<<arrtypr->getNumElements()<<"\n";
            //     errs()<<ins_iter->getName().str()<<"\n";

            //     if (!ins_iter->use_empty())
            //     {
            //       for(auto uit=allo->user_begin();uit!=allo->user_end();uit++)
            //       {
            //         errs()<<**uit<<"\n";


            //         Instruction *ins=dyn_cast<Instruction>(*uit);
            //         if (DILocation *Loc = ins->getDebugLoc())
            //         {
                                                
                      
            //           int Line = Loc->getLine();
            //           errs()<<Line<<"\n";
            //           // File = Loc->getFilename().str();
            //           // Dir = Loc->getDirectory().str();
            //         }
            //       }
            //     }

            //   }
            // }


      

          }
        }

      }
      

			
			
			return false;
		}
			
	};
}

char PProcessPass::ID = 0;
static RegisterPass<PProcessPass> X("get_bound", "proprecess Analyse",
	false, false);
