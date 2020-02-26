#include "revng/SecurityPass/FunctionParamsUsagePass.h"

using namespace llvm;
using namespace revng;

char FunctionParamsUsagePass::ID = 0;

cl::opt<bool> VerboseFPAnalysis("verbose-fp-analysis", cl::desc("Write more informations about analysis"));


static RegisterPass<FunctionParamsUsagePass> Y("revng-params-usage", "Analyze function params of revng isolated functions",
					       false /* Only looks at CFG */,
					       true /* Analysis Pass */);

FunctionParamsUsagePass::FunctionParamsUsagePass() : FunctionPass(ID), currentVarsFlows(), currentStackVarsFlows() {
}



bool FunctionParamsUsagePass::doInitialization(Module &M) {
	return false;

}

bool FunctionParamsUsagePass::doFinalization(Module &M) {
  return false;
}

bool FunctionParamsUsagePass::runOnFunction(Function &F) {
	get_print_stream(1) << "Starting FunctionParamsUsage pass on function " << F.getName() << "...\n";
	currentF = &F;

  currentRF = getAnalysis<RevngFunctionParamsPass>().getRevngFunction();
  currentStackVarsFlows.clear();
  currentVarsFlows.clear();
  currentRiskyStores.clear();


  if( !(currentRF->getFunctionName() == F.getName() && currentRF->getType() == RevngFunction::TYPE::ISOLATED)) {
	  get_print_stream(1) << "Function arguments not found for "<< F.getName() <<"!\n";
    return false;
  }
  if( isaSkippedFunction(&F) ) {
    FPUSkippedFunctions++;
    get_print_stream(1) << "Not a function in the analysis scope, skipping FPU...\n";
    return false;
  }

  if (!isMarked(&F) && only_marked_funs) {
	  FPUSkippedFunctions++;
	  get_print_stream(1) << "Function not rached by input, skipping FPU...\n";
	  return false;
  }

  LVI = &getAnalysis<LazyValueInfoWrapperPass>().getLVI();
  SCEV = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();

  analyzePromotedArgsUsage(currentRF, &F);

  // analyzes uses of args
  analyzeArgsUsage(currentRF, &F);
  analyzeVSPUsage(currentRF,&F);

  // analyzes uses of stack painter
  // analyzeStackArgsUsage(currentRF, &F);

  findRiskyStores();
  return false;
}

void FunctionParamsUsagePass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<LazyValueInfoWrapperPass>();
  AU.addRequired<RevngFunctionParamsPass>();
  AU.addRequired<ScalarEvolutionWrapperPass>();
  AU.setPreservesAll();
}

bool FunctionParamsUsagePass::isaUserOfParameter(const User *UR, const Value *param) const {
  if (UR == nullptr || param == nullptr) {
    get_print_stream(1) << "Null pointer in isaUserOfParameter\n";
    return false;
  }
  for(auto OP = UR->op_begin(); OP!=UR->op_end(); OP++) {
    if(OP->get() == param)
      return true;
  }
  return false;
}


bool FunctionParamsUsagePass::isaUserOfParams(const User *UR) const {
  if (UR == nullptr) {
    get_print_stream(1) << "Null pointer in isaUserOfParameter\n";
    return false;
  }
  bool result = false;
  for (auto VFlow : currentVarsFlows) {
    const Value* GV = std::get<0>(VFlow);
    auto VChains = std::get<1>(VFlow);
    for(auto DUChain : VChains) {
	for (auto DU : DUChain) {
      const Instruction *user = cast<Instruction>(std::get<0>(DU));
      const Value *use = std::get<1>(DU);
      result =  result || isaUserOfParameter(UR, use);
      if(result) {
	return result;
      }
	}
    }
  }

  for (auto SVFlow : currentStackVarsFlows) {
    const Value *stackVar = std::get<0>(SVFlow)->getValue();
    auto SPChains  = std::get<1>(SVFlow);
      for (auto SPChain : SPChains) {
	for (auto DU : SPChain) {
	  const Value *use = std::get<1>(DU);
	  result =  result || isaUserOfParameter(UR, use);
	  if (result)
	    return result;
	}
      }
  }
  return result;
}

void FunctionParamsUsagePass::print(raw_ostream &OS, const Module *M) const {
  OS << "Revng Function arguments obtained \n";
  unsigned int i= 0;
  if(VerboseFPAnalysis) {
  for (auto VFlow : currentVarsFlows) {
     const Value* GV = std::get<0>(VFlow);
     auto VChains = std::get<1>(VFlow);
    if(VChains.empty()) {
       OS << "- paramter " << GV->getName() << " not used (maybe it is used by Qemu helper functions)\n";
     }
     else {
       OS << "- Value flows for parameter " << GV->getName() << ":\n";
       i = 0;
       for(auto DUChain : VChains) {
  	i++;
  	OS << "\t def-use-chain " << i << ")\n";
  	for (auto DU : DUChain) {
  	  OS << "\t\t- ";
  	  const Instruction *user = dyn_cast<Instruction>(std::get<0>(DU));
  	  const Value *use = std::get<1>(DU);
  	  use->print(OS);
  	  OS<< " used by ";
  	  user->print(OS);
  	  OS << "\n";
  	  printOperandsRange(OS, user);
  	}
  	OS << "\n";
      }
    }
  }

  if(currentStackVarsFlows.empty()) {
      OS << " No parameters pushed on stack\n";
  } else {
  for (StackVarFlow SVFlow : currentStackVarsFlows) {
	  const Value *stackVar = std::get<0>(SVFlow)->getValue();
    auto SPChains  = std::get<1>(SVFlow);
    if(SPChains.empty()) {
      OS << "No uses for " ;
  	    stackVar->print(OS);
  	    OS << "\n";
    }
    else {
      OS << "-Value flows for stack element ";
      stackVar->print(OS);
      OS << ":\n";
      i=0;
      for (auto SPChain : SPChains) {
  	i++;
  	OS << "\t def-use-chain " << i << ")\n";
  	for (auto DU : SPChain) {
  	  OS << "\t\t- ";
  	  const Instruction *user = dyn_cast<Instruction>(std::get<0>(DU));
  	  const Value *use = std::get<1>(DU);
  	  use->print(OS);
  	  OS<< " used by ";
  	  user->print(OS);
  	  OS << "\n";
  	  printOperandsRange(OS, user);
  	}
  	OS << "\n";
      }
    }
  }
  }

}

  if(currentRiskyStores.empty()) {
    OS << " No risky stores found\n";
  } else {
    OS << "Possible risky stores found: \n";
    for (auto RS : currentRiskyStores) {
	    OS << "\t" << "Value deriving from " << *(RS.getPointedValue()) << " used in " << (RS.getStoreInst()) << "\n";
    }
  }
}


std::vector<DefUseChain> FunctionParamsUsagePass::getValueFlows(const Value* startValue) const {
	std::vector<DefUseChain> result;
	DefUseChain currentChain;
	for(const User* U: startValue->users()) {
		currentChain.clear();
		if(const Instruction *I = dyn_cast<Instruction>(U)) {
			if(I->getFunction() == currentF) {
				DefUse newDefUse(&cast<User>(*I), startValue);
				currentChain.push_back(newDefUse);
				std::vector<DefUse> tempDefUse = traverseDefUseChain(&cast<Value>(*I)); // try to find new def-uses
				for (auto DU : tempDefUse) {
					currentChain.push_back(DU);
				}
				result.push_back(currentChain);
			}
		}
	}
	get_print_stream(2) << "Found " << result.size() << " flows for " << startValue->getName() << "\n";
	return result;
}



std::vector<DefUse> FunctionParamsUsagePass::traverseDefUseChain(const Value *V) const  {
  std::vector<DefUse> result;
  if (V == nullptr || currentF == nullptr) {
    get_print_stream(3) << "Null pointer in traverseDefUseChain\n";
    return result;
  }
  std::queue<const Value *> nextValues;
  nextValues.push(V);
  const Value* currentValue;
  bool cycleDetected=false;
  while(!nextValues.empty()) {
     currentValue = nextValues.front();
     nextValues.pop();
      for(const Use& use : currentValue->uses()) {
	      const User* U = use.getUser();
	      if (const Instruction *I = dyn_cast<Instruction>(U)) {
		      if (I->getFunction() == currentF) {
			      DefUse *newDefUse = nullptr;
			      if (const StoreInst *SI = dyn_cast<StoreInst>(I)) {
				      const Value* destVal = SI->getPointerOperand();
				      newDefUse = new DefUse(&cast<User>(*I), destVal);
			      } else {
				      newDefUse = new DefUse(&cast<User>(*I), currentValue);
			      }
			      // avoid having duplicates in chain
			      if(!isInChain(result, *newDefUse)) {
				      result.push_back(*newDefUse);
				      nextValues.push(&cast<Value>(*I));
			      }
		      }
	      }
      }
  }
  return result;

}

bool FunctionParamsUsagePass::isInChain(std::vector<DefUse> &chain, DefUse &V) const {
	for(auto DU : chain) {
		auto l_user = std::get<0>(DU);
		auto r_user = std::get<0>(V);
		auto l_value = std::get<1>(DU);
		auto r_value = std::get<1>(V);
		if (l_user == r_user && l_value == r_value)
			return true;
	}
	return false;
}


void FunctionParamsUsagePass::printOperandsRange(raw_ostream &OS, const Instruction *UR) const { // instruction is treated as a user, but we need its type to get back basic block
	assert(UR != nullptr && "Nullptr passed t printOperandsRange");
	assert(LVI != nullptr && "LVI analysis not obtained");
	assert(SCEV != nullptr && "Scalar Evolution analysis not obtained");
	for(auto OP = UR->op_begin(); OP!=UR->op_end(); OP++) {
		Value *OPV = OP->get();
		OS << "\t\tOperand " << OPV->getName() << ": ";
		printValueRange(OS, OPV, UR->getParent());
		OS << "\n";
	}
}


void FunctionParamsUsagePass::printValueRange(raw_ostream &OS, Value *V, const BasicBlock* context) const { // instruction is treated as a user, but we need its type to get back basic block
	assert(V != nullptr && "Nullptr passed t printValueRange");
	assert(LVI != nullptr && "LVI analysis not obtained");
	assert(SCEV != nullptr && "Scalar Evolution analysis not obtained");
	if (SCEV->isSCEVable(V->getType())){
		auto SCEVexp = SCEV->getSCEV(V);
		if(SCEVexp->getType()->isIntegerTy()) {
			ConstantRange SCEVRange = SCEV->getUnsignedRange(SCEVexp);
			OS << SCEVRange;
		} else if(SCEVexp->getType()->isPointerTy()) {
			ConstantRange SCEVRange = SCEV->getUnsignedRange(SCEVexp);
			OS << SCEVRange << " (pointer base:  " ;
			SCEV->getPointerBase(SCEVexp)->print(OS);
			OS << " )";
		}
	} else {
		OS << "range not available for this type";
	}
}

void FunctionParamsUsagePass::deallocDefUseChains() {
	// for(DefUseChain P : currentDefUseChains) {
	//   auto v = std::get<1>(P);
	//   v.clear();
	// }
	// currentDefUseChains.clear();
}

// Sample structure
// functionParamsUsageAnalysis: {
//         variblesFlows: {
//             var1: {
//             	     chain1 : [ inst1, inst2, inst3,...],
//             	     chain2 : [ inst1, inst2, inst3, ...],
//             	     ...
//
//             }
//             var2: {
//             	     chain1 : [ inst1, inst2, inst3,...],
//             	     chain2 : [ inst1, inst2, inst3, ...],
//             	     ...
//             }
//         }
//˘}
json::Object FunctionParamsUsagePass::toJSON() {
	json::Object fobj;
	json::Object varsFlows;
	unsigned int chainNum ;
	get_print_stream(1) << "Dumping " << currentVarsFlows.size() << " variables flows to json...";
	for(auto VF : currentVarsFlows) {
		chainNum = 1;
		const Value* GVvar = std::get<0>(VF);
		json::ObjectKey GVKey ( GVvar->getName());
		json::Object GVobj;
		get_print_stream(2) << "Converting a list of " << std::get<1>(VF).size() << " def-use chains for " << GVvar->getName() << " ...\n";
		for( auto DFC: std::get<1>(VF)) {
			get_print_stream(3) << "Traversing a def-use chain of " << DFC.size() << " def-uses for " << GVvar->getName() << "...\n";
			json::ObjectKey defChainsKey(formatv("chain{0}", chainNum));
			json::Array defChainsVal;
			for( auto DF : DFC) {
				auto inst = std::get<0>(DF);
				json::Value defVal (formatv("{0}", *inst));
				defChainsVal.push_back(std::move(defVal));
			}
			GVobj.try_emplace(std::move(defChainsKey), std::move(defChainsVal));
			chainNum++;
		}
		varsFlows.try_emplace(std::move(GVKey), std::move(GVobj));
	}
	fobj.try_emplace("variablesFlows", std::move(varsFlows));
	get_print_stream(1) << "Dumping " << currentVarsFlows.size() << " stack variables flows to json...\n";
	json::Object stackVarsFlows;
	for(auto SVF : currentStackVarsFlows) {
		const VirtualStackParam* SVvar = std::get<0>(SVF);
		json::ObjectKey SVKey ( SVvar->getName());
		json::Object SVobj;
		for( auto DFC: std::get<1>(SVF)) {
			json::ObjectKey defChainsKey(formatv("chain{0}", chainNum));
			json::Array defChainsVal;
			for( auto DF : DFC) {
				auto inst = std::get<0>(DF);
				json::Value defVal (formatv("{0}", *inst));
				defChainsVal.push_back(std::move(defVal));
			}
			SVobj.try_emplace(std::move(defChainsKey), std::move(defChainsVal));
			chainNum++;
		}
		stackVarsFlows.try_emplace(std::move(SVKey), std::move(SVobj));
	}
	get_print_stream(1) << "Done!\n";
	fobj.try_emplace("stackVariablesFlows", std::move(stackVarsFlows));
	return fobj;
}

void FunctionParamsUsagePass::findRiskyStores() {
	const Value* GV = nullptr;
	for(VariableFlow VF: currentVarsFlows) {
		GV = std::get<0>(VF);
		for (auto DUChain : std::get<1>(VF)) {
			for(auto DU : DUChain) {
				const User* U = std::get<0>(DU);
				if(isaRiskyStore(DU)) {
					if(!(containsRiskyStore(currentRiskyStores, dyn_cast<StoreInst>(U)))) {
						RiskyStore tempRiskyStore ( cast<Value>(GV), dyn_cast<StoreInst>(U) );

						currentRiskyStores.push_back(tempRiskyStore);
						TotalStores++;
					}
				}
			}
		}
	}

	const Value* V = nullptr;
	for(StackVarFlow SVF: currentStackVarsFlows) {
		V = std::get<0>(SVF)->getValue();
		for (auto DUChain : std::get<1>(SVF)) {
			for(auto DU : DUChain) {
				const User* U = std::get<0>(DU);
				if(isaRiskyStore(DU)) {
					if(!(containsRiskyStore(currentRiskyStores, dyn_cast<StoreInst>(U)))) {
						RiskyStore tempRiskyStore (V, dyn_cast<StoreInst>(U) );
						currentRiskyStores.push_back(tempRiskyStore);
						TotalStores++;
					}
				}
			}
		}
	}

}

bool FunctionParamsUsagePass::isaRiskyStore(const DefUse &DU) const {
	const User* U = std::get<0>(DU);
	const Value* V = std::get<1>(DU);
	if(isa<StoreInst>(U)) {
		const StoreInst* store = dyn_cast<StoreInst>(U);
		if (store->getPointerOperand() == V)
			return true;
	}
	return false;

}

bool FunctionParamsUsagePass::containsRiskyStore(std::vector<RiskyStore>& vector, const StoreInst* store) const {
	const StoreInst* currStore = nullptr;
	for(auto RS : vector) {
		currStore = RS->getStoreInst();
		if(currStore == store)
			return true;
	}
	return false;
}

void FunctionParamsUsagePass::dumpAnalysis(raw_fd_ostream &FOS, Function &F) const {

	FOS << "Parameters analysis for " << F.getName() << ":\n";
	unsigned int i= 0;
	if(VerboseFPAnalysis) {
		for (auto VFlow : currentVarsFlows) {
			const Value* GV = std::get<0>(VFlow);
			auto VChains = std::get<1>(VFlow);
			if(VChains.empty()) {
				FOS << "- paramter " << GV->getName() << " not used (maybe it is used by Qemu helper functions)\n";
			}
			else {
				FOS << "- Value flows for parameter " << GV->getName() << ":\n";
				i = 0;
				for(auto DUChain : VChains) {
					i++;
					FOS << "\t def-use-chain " << i << ")\n";
					for (auto DU : DUChain) {
						FOS << "\t\t- ";
						const Instruction *user = cast<Instruction>(std::get<0>(DU));
						const Value *use = std::get<1>(DU);
						use->print(FOS);
						FOS<< " used by ";
						user->print(FOS);
						FOS << "\n";
						printOperandsRange(FOS, user);
					}
					FOS << "\n";
				}
			}
		}

		if(currentStackVarsFlows.empty()) {
			FOS << " No parameters pushed on stack\n";
		} else {
			for (StackVarFlow SVFlow : currentStackVarsFlows) {
				const Value *stackVar = std::get<0>(SVFlow)->getValue();
				auto SPChains  = std::get<1>(SVFlow);
				if(SPChains.empty()) {
					FOS << "No uses for " ;
					stackVar->print(FOS);
					FOS << "\n";
				}
				else {
					FOS << "-Value flows for stack element ";
					stackVar->print(FOS);
					FOS << ":\n";
					i=0;
					for (auto SPChain : SPChains) {
						i++;
						FOS << "\t def-use-chain " << i << ")\n";
						for (auto DU : SPChain) {
							FOS << "\t\t- ";
							const Instruction *user = cast<Instruction>(std::get<0>(DU));
							const Value *use = std::get<1>(DU);
							use->print(FOS);
							FOS<< " used by ";
							user->print(FOS);
							FOS << "\n";
							printOperandsRange(FOS, user);
						}
						FOS << "\n";
					}
				}
			}
		}

	}

	if(currentRiskyStores.empty()) {
		FOS << " No risky stores found\n";
	} else {
		FOS << "Possible risky stores found: \n";
		for (auto RS : currentRiskyStores) {
			FOS << "\t" << "Value deriving from " << *(RS.getPointedValue()) << " used in " << *(RS.getStoreInst()) << "\n";
		}
	}
}

void FunctionParamsUsagePass::analyzeArgsUsage(const RevngFunction* currentRF, Function *F) {

	get_print_stream(1) << "Analyzing arguments for " << F->getName() << "\n";
	bool firstUsageFound = false;
	for(const GlobalVariable *GV: currentRF->getArguments()) {
		// Reinitialize
		std::vector<DefUseChain> defUseChains = analyzeSingleArgUsage(F, GV);
		VariableFlow vflow(GV, defUseChains);
		currentVarsFlows.push_back(vflow);
		TotalVarChains++;
	}
}

void FunctionParamsUsagePass::analyzePromotedArgsUsage(const RevngFunction* currentRF, Function *F) {
	get_print_stream(3) << F->getName() << " has " << F->arg_size() << " promoted arguments\n";
	for( Function::arg_iterator A = F->arg_begin(), A_end = F->arg_end(); A != A_end ;  A++) {
		std::vector<DefUseChain> defUseChains = analyzeSingleArgUsage(F, dyn_cast<Value>(A));
		VariableFlow vflow(dyn_cast<Value>(A), defUseChains);
		currentVarsFlows.push_back(vflow);
		TotalVarChains++;
	}
}


std::vector<DefUseChain> FunctionParamsUsagePass::getSSAValueFlows(const Value* V) const {
	std::vector<DefUseChain> nullResult;
	const Value* startValue = nullptr;
	auto symTable = currentF->getValueSymbolTable();
	if(symTable) {
		StringRef initName((V->getName() + ".0").str());
		startValue =  symTable->lookup(initName);
	}
	if ( startValue != nullptr) {
		get_print_stream(2) << "Found an inital memoryssa value for " << V->getName() << ": " << startValue->getName() << "\n";
		return getValueFlows(startValue);
	} else {
		return nullResult;
	}
}


std::vector<DefUseChain> FunctionParamsUsagePass::analyzeSingleArgUsage(Function* F, const Value* var) {
	std::vector<DefUseChain> defUseChains;
	DefUseChain defUseChain;
	Value* initialValue = nullptr;
	return getValueFlows(var);
}

void FunctionParamsUsagePass::analyzeVSPUsage(const RevngFunction* currentRF, Function* F) {

	std::vector<DefUseChain> defUseChains;
	DefUseChain defUseChain;


	const GlobalVariable* stackPointer = currentRF->getStackPointer();
	if (stackPointer == nullptr) {
		get_print_stream(3) << "stack pointer variable not found\n";
	}
	else {
		VariableFlow vflow(stackPointer, getValueFlows(dyn_cast<Value>(stackPointer)));
		currentVarsFlows.push_back(vflow);
	}
}

void FunctionParamsUsagePass::analyzeStackArgsUsage(const RevngFunction* currentRF, Function* F) {
  std::vector<DefUseChain> defUseChains;
  DefUseChain defUseChain;
  for(const VirtualStackParam *VSP: currentRF->getStackParams()) {
    // Reinitialize variables
    const Value* VSPval = VSP->getValue();
    StackVarFlow svflow(VSP, getValueFlows(VSPval));
    currentStackVarsFlows.push_back(svflow);
    TotalStackChains++;
  }
}
