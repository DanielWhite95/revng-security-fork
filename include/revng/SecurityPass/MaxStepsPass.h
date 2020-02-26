#ifndef MAX_STEPS_PASS
#define MAX_STEPS_PASS

#include "llvm/ADT/Statistic.h"

#define DEBUG_TYPE "MaxStepsPass"
STATISTIC(MaxLength, "Max length of branch or loop found");

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
#include "CommonDefinitions.h"


using namespace llvm;

namespace revng {

	static unsigned int SHARED_MAX_LENGTH = 0;

	struct MaxStepsPass : public CallGraphSCCPass {
	public:
		static char ID;

		MaxStepsPass();
		virtual bool doFinalization(CallGraph &CG) override;
		virtual ~MaxStepsPass() {};
		virtual bool runOnSCC(CallGraphSCC &SCC) override;
		virtual  void getAnalysisUsage(AnalysisUsage &AU) const override;
		void print(raw_ostream &OS, const Module *M) const override;
		unsigned int getLength() const { return this->maxLength; };

		static unsigned int getMaxLength() { return SHARED_MAX_LENGTH; }

	private:
		// methods
		unsigned int getSCCLength(CallGraphSCC &SCC);

		void dumpMaxLength();
	        void updateMaxLength(unsigned int );

		unsigned int maxLength = 0 ;
		// class variables

	};
}


#endif // MAX_STEPS_PASS
