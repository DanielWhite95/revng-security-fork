#ifndef INPUT_GENERATION_PASS
#define INPUT_GENERATION_PASS

#include "llvm/ADT/Statistic.h"
#define DEBUG_TYPE "InputGeneratorFunctionPass"
STATISTIC(ReachedFunctions, "Functions reached by at least one input generator");

#include "llvm/Pass.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Debug.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <deque>
#include <algorithm>
#include "RevngFunctionParamsPass.h"

using namespace llvm;

namespace revng {

	struct InputGeneratorPass : FunctionPass {
	public:
		static char ID;
		InputGeneratorPass();
		virtual bool doInitialization(Module &M) override;
		virtual bool doFinalization(Module &M) override;
		virtual ~InputGeneratorPass() {};
		virtual bool runOnFunction(Function &F) override;
		virtual  void getAnalysisUsage(AnalysisUsage &AU) const override;
		void print(raw_ostream &OS, const Module *M) const override;

	private:
		// methods

	        void markParentFunction(Function*F, bool status);


		// class variables

		CallGraph* currentCG;
		std::map<std::string, int> markedFunctions;
		std::map<std::string, std::string> relocationMappings;

		// RevngFunction result;


	};
}


#endif // INPUT_GENERATION_PASS
