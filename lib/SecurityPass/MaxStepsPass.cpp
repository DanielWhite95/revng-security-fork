#include "revng/SecurityPass/MaxStepsPass.h"


using namespace llvm;
using namespace revng;

char MaxStepsPass::ID = 0;

static RegisterPass<MaxStepsPass> X("revng-max-cg-length", "Search for the max length of cycles and branches in the callgraph",
					  false /* Only looks at CFG */,
					  true /* Analysis Pass */);

// find read function or input generator inside a single scc


MaxStepsPass::MaxStepsPass() : CallGraphSCCPass(ID) {

}
bool MaxStepsPass::runOnSCC(CallGraphSCC &SCC) {
	// Find callsite for read
	updateMaxLength(SCC.size());
	return false;
}


// Analyze whole CallGraph Deep First to propagate marked functions
bool MaxStepsPass::doFinalization(CallGraph& CG) {
	// should avoid cycles
	// traverse deep first the callgraph

	unsigned int counter = 0;
	for(auto it = df_begin(&CG), endIt = df_end(&CG); it!= endIt; it++) {
		// found a leaf
		if (it->empty()) {
			updateMaxLength(counter+1);
			counter = 1;
		} else {
			counter++;
		}
	}
	SHARED_MAX_LENGTH = maxLength;
	errs() << "Max Length found in module CG is " << maxLength << "\n";
	return false;
}


void MaxStepsPass::updateMaxLength(unsigned int newLength ) {
	if(newLength > maxLength){
		maxLength = newLength;
		MaxLength = maxLength;
	}
}

void MaxStepsPass::getAnalysisUsage(AnalysisUsage &AU) const {
	AU.setPreservesAll();
}

void MaxStepsPass::print(raw_ostream &OS, const Module *M) const {
	OS << "Max Length found in module CG is " << maxLength << "\n";
}
