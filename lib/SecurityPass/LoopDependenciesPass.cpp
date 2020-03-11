#include "revng/SecurityPass/LoopDependenciesPass.h"
#include "revng/SecurityPass/RevngFunctionParamsPass.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Debug.h"
#include <queue>

using namespace llvm;
using namespace revng;

char LoopDependenciesPass::ID = 0;

static RegisterPass<LoopDependenciesPass> Y("revng-loop-deps", "Analyze loops branch conditions dependencies",
					    false /* Only looks at CFG */,
					    true /* Analysis Pass */);




LoopDependenciesPass::LoopDependenciesPass() : FunctionPass(ID), candidateBranches(), vulnerableLoops()
{
}

bool LoopDependenciesPass::doInitialization(Module &M) {
	return false;
}


bool LoopDependenciesPass::doFinalization(Module &M) {
	return false;

}

bool LoopDependenciesPass::runOnFunction(Function &F) {
	errs() << "Starting LoopDependencies pass on " << F.getName() << "...\n";
	candidateBranches.clear();
	vulnerableLoops.clear();
	VulnerableLoopItem* currentVlItem = nullptr;
	std::pair<const StringRef, VulnerableLoopItem*> *vulnerableLoop = nullptr;
	currentRF = getAnalysis<RevngFunctionParamsPass>().getRevngFunction();
	if( !(currentRF->getFunctionName() == F.getName() && currentRF->getType() == RevngFunction::TYPE::ISOLATED)) {
		errs() << "Function arguments not found for "<< F.getName() <<"!\n";
		return false;
	} if ( isaSkippedFunction(&F) ) {
	  LDPSkippedFunctions++;
	  errs() << "Not a function in the scope of analysis, skipping...\n" ;
	  return false;
	}if (!isMarked(&F) && only_marked_funs) {
		LDPSkippedFunctions++;
		errs() << "Function not reached by any input, skipping analysis ...\n";
		return false;
	}
	OverallFunctions++;
	FunctionParamsUsagePass &FPU = getAnalysis<FunctionParamsUsagePass>();
	LoopInfo &functionLI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
	errs() << "Obtained LoopInfo for "<< F.getName() << "\n";
	for(const Loop *L : functionLI) {
		if(L->getName().empty()) {
			continue; // Skip unnamed loop because lead to infinite loops
		}
		currentVlItem = new VulnerableLoopItem();
		TotalLoops++;
		if (analyzeLoop(L, FPU, *currentVlItem))
		{
			errs() << "Loop " << L->getName() << " is vulnerable!\n";
			vulnerableLoop = new std::pair<const StringRef, VulnerableLoopItem*>(L->getName(), currentVlItem);
			vulnerableLoops.insert(std::move(*vulnerableLoop));
		}
		else {
			errs() << "Loop " << L->getName() << " is not vulnerable!\n";
			delete currentVlItem;
		}

	}
	if( !isFunctionSafe() ) {
	  VulnerableFunctions++;
	  if ( isMarked(&F)) {
	    InputVulnerableFunctions++;
	  }

	}
	return false;
}

bool LoopDependenciesPass::analyzeLoop(const Loop* L, FunctionParamsUsagePass& FPU, VulnerableLoopItem& vlItem) {

  BasicBlock* lHeader = nullptr;
  SmallVector<BasicBlock*, 6> loopLatches;
  std::vector<const Instruction*> &vlCandidateBranches = std::get<0>(vlItem);
  std::vector<const RiskyStore*> &riskyStores = std::get<1>(vlItem);

	bool analysisResult = false;
	errs() << "Analyzing loop " << L->getName() << "\n";

  lHeader = L->getHeader();


  if(lHeader == nullptr) {
    errs() << "No header for the loop (please apply -loop-simplify transformation)";
    return false;
  }  else {
	  if(analyzeLoopBasicBlock(lHeader, FPU)) {
		  analysisResult = true;
		  vlCandidateBranches.push_back(lHeader->getTerminator());
		  CandidateLoops++;
	  }
  }

  auto fpuRiskyStores = FPU.getRiskyStores();
  unsigned int loopStores = 0;
  if(analysisResult) {
	  errs() << "Analyzing Risky stores of Function Params Usage pass\n";
	  for(const BasicBlock* BB: L->getBlocks() ) {
		  errs() << "Searching stores inside Basic Block " << BB->getName() << "\n";
		  for( RiskyStore& R: fpuRiskyStores) {
			  if(R.getStoreInst()->getParent() == BB ) {
				  R.getStoreInst()->print(get_print_stream(3));
				  get_print_stream(3) << " is inside the Basic block!\n";
				  RiskyStore *clonedStore = new RiskyStore(R);
				  riskyStores.push_back(clonedStore);
				  loopStores++;
				  FilteredStores++;
			  }
		  }
	  }
  }
  if (loopStores > 0 ) {
	  return true;
  }
  else
	  return false;
}

bool LoopDependenciesPass::analyzeLoopBasicBlock(const BasicBlock* BB, FunctionParamsUsagePass& FPU) {
	assert(BB != nullptr && "Nullpointer passed to analyzeLoopBasicBlock");
	bool analysisResult = false;
	errs() << "Analyzing basic block " << BB->getName() << "...\n";
	const Instruction* tInst = BB->getTerminator();
	if(isa<BranchInst>(tInst)) {
		const BranchInst* bInst = dyn_cast<BranchInst>(tInst);
		if(bInst->isConditional()) {
			const Value* condition = bInst->getCondition();
			const CmpInst* cmp;
			if(isa<CmpInst>(condition)) {
				errs() << "Found compare instruction as terminator instruction in basic block\n";
				errs() << "Analyzing conditons for " ;
				const CmpInst* cmp = dyn_cast<CmpInst>(condition);
				cmp->print(errs());
				errs() << "...\n";
				analysisResult = analyzeLoopCondition(cmp, FPU);
			} else {
				if(const User* U = dyn_cast<User>(condition)) {
					auto backwardChain = traverseBackwardDefUseChain(U);
					for(auto DU : backwardChain) {
						const Value* inst = std::get<1>(DU);
						cmp = dyn_cast<CmpInst>(inst);
						if(cmp) {
							errs() << "Found compare instruction traverse back def use of terminator instruction\n";
							errs() << "Analyzing conditons for " ;
							cmp->print(errs());
							errs() << "...\n";
							analysisResult = analyzeLoopCondition(cmp, FPU);
						}
					}
				}
			}

		}
	}
	return analysisResult;
}

bool LoopDependenciesPass::analyzeLoopCondition(const CmpInst* condition, FunctionParamsUsagePass& FPU) {
	bool analysisResult;
	const Value* currInst = nullptr;
	const Value* currOp = nullptr;
	auto OPit = condition->op_begin();
	while(OPit != condition->op_end()) {
		currOp = *OPit;
		if(FPU.isaUserOfParams(dyn_cast<User>(currOp))) {
			errs() << "Condition uses one of the function parameters!\n";
			return true;
		}
		OPit++;
	}
	errs() << "No uses of parameters found for this condition!\n";
	return false;
}

void LoopDependenciesPass::getAnalysisUsage(AnalysisUsage &AU) const {
	AU.addRequired<LoopInfoWrapperPass>();
	AU.addRequired<FunctionParamsUsagePass>();
	AU.addRequired<RevngFunctionParamsPass>();
	AU.setPreservesAll();
}


void LoopDependenciesPass::print(raw_ostream &OS, const Module *M) const {
	int i= 0;
	if(!candidateBranches.empty()) {
		OS << "Vulnerable loops found for fucntion " << currentRF->getFunctionName() << "\n";
		for (auto TI : candidateBranches) {
			OS << "\t" << i << ") " << *TI << "\n";
			i++;
		}

	} else {
		OS << "No candidate loops found for " << currentRF->getFunctionName() << "\n";
	}
}



DefUseChain LoopDependenciesPass::traverseBackwardDefUseChain(const User *U) {
  assert(U != nullptr && "Null pointer in traverseDefUseChain\n");
  DefUseChain result;
  std::queue<const User *> nextUsers;
  nextUsers.push(U);
  const User* currentUser = U;
  const Use* use = currentUser->op_begin();
  while(!nextUsers.empty()) {
    currentUser = nextUsers.front();
    nextUsers.pop();
    use = currentUser->op_begin();
    while(use != currentUser->op_end()) {
	if (const Instruction *I = dyn_cast<Instruction>(use)) {
	    DefUse newDefUse(currentUser, cast<Value>(I));
	    result.push_back(newDefUse);
	    nextUsers.push(cast<User>(I));
	}
	use++;
      }
  }
  return result;
}


void LoopDependenciesPass::dumpAnalysis(raw_fd_ostream &FOS, Function&F) const {
  FOS << "Loop analysis for " << F.getName() << ":\n";
  int i= 0;
  if(!candidateBranches.empty()) {
    FOS << "Vulnerable loops found for fucntion " << currentRF->getFunctionName() << "\n";
    for (auto TI : candidateBranches) {
      FOS << "\t" << i << ") " << *TI << "\n";
      i++;
        }

  } else {
    FOS << "No candidate loops found for " << currentRF->getFunctionName() << "\n";
  }


}


json::Object LoopDependenciesPass::toJSON() const {
	json::Object result;
	json::ObjectKey vlsKey("vulnerableLoops");
	json::Object vlsVal;
	get_print_stream(1) << "Dumping "<< vulnerableLoops.size() << " vulnerable loops...\n";
	for(auto VL : vulnerableLoops) {
		json::ObjectKey vlKey(std::get<0>(VL));
		json::Object vlObj;
		VulnerableLoopItem* vlItem = std::get<1>(VL);
		json::ObjectKey brKey("candidateBranches");
		json::Array brVal;

		get_print_stream(2) << "Dumping " << std::get<0>(*vlItem).size() << " branches for "<< std::get<0>(VL) << " ...\n";
		for( const Instruction* TI : std::get<0>(*vlItem)) {
			std::string serializedTI;
			serializedTI = formatv("{0}", *TI);
			json::Value tiVal(serializedTI);
			brVal.push_back(tiVal);
		}
		vlObj.try_emplace(std::move(brKey), std::move(brVal));
		json::ObjectKey rsKey("riskyStores");
		json::Array rsVal;
		get_print_stream(2) << "Dumping " << std::get<1>(*vlItem).size() << " branches for "<< std::get<0>(VL) << " ...\n";
		for( auto RS : std::get<1>(*vlItem)) {
			json::Object& stObj = riskyStoreToJSON(RS);
			rsVal.push_back(json::Value(std::move(stObj)));
		}
		vlObj.try_emplace(std::move(rsKey), std::move(rsVal));
		vlsVal.try_emplace(std::move(vlKey), std::move(vlObj));
	}
	result.try_emplace(std::move(vlsKey), std::move(vlsVal));
	return result;
}


bool LoopDependenciesPass::isFunctionSafe() const {
	unsigned countStores = 0;
	for (auto VL : vulnerableLoops) {
		auto VLI = std::get<1>(VL);
		countStores += VLI->second.size();
	}
	if (countStores == 0)
		return true;
	else
		return false;
}
