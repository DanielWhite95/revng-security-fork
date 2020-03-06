#include "revng/SecurityPass/BackwardPropagationPass.h"

using namespace llvm;
using namespace revng;

char BackwardPropagationPass::ID = 3;


cl::opt<std::string> MarkedFunctionsInputFile("input-functions-csv", cl::desc("Specify the csv that defines function name and arguments  for the marked source function"), cl::value_desc("filename"));

cl::opt<std::string> RelocationsMappingsInputFile("dyn-rel-maps", cl::desc("Specify the csv that contains mappings of relocation section to function names"), cl::value_desc("filename"));

// cl::opt<int> MaxSteps("backward-upper-bound", cl::desc("Specify the upper bound of the reiteration of backward propagation"),  cl::Required);

static RegisterPass<BackwardPropagationPass> Y("revng-backward-prop", "Analyze function reached by vulnerable points and propagate input to callers (1-step)",
					       false /* Only looks at CFG */,
					       false /* Analysis Pass */);

BackwardPropagationPass::BackwardPropagationPass() : ModulePass(ID) {
}

void BackwardPropagationPass::getAnalysisUsage(AnalysisUsage &AU) const {
	// AU.addRequired<MaxStepsPass>();
	AU.setPreservesAll();
}


bool BackwardPropagationPass::runOnModule(Module &M) {
	unsigned int itCounter = 0;
	unsigned int MaxSteps = MaxStepsPass::getMaxLength();
	std::map<Function*, MarkedFunInfo> *newCallers;
	do {
		get_print_stream(3) << "\n\n\nPropagating to caller for the " << itCounter+1 << " time...\n";
		printNextCallers();
		newCallers = new std::map<Function*, MarkedFunInfo>();
		for( auto KV : *nextCallers) {
			Function* caller = std::get<0>(KV);
			MarkedFunInfo &calledInfo = std::get<1>(KV);
			// nextCallers.erase(caller);
			if( caller == nullptr) {
				continue;
			}
			get_print_stream(3) << "Analizing " << caller->getName() << " calling " << "<" << std::get<0>(calledInfo) << "," << std::get<1>(calledInfo) <<"," << std::get<2>(calledInfo) << ">...\n";
			fScraper.analyze(caller);
			const Value* inputValue = getInputValue(*caller, calledInfo);
			if( inputValue == nullptr) {
				get_print_stream(3) << "ERROR! Caller " << caller->getName() << " has no input value!!!\n";
				continue;
			}
			int argIndex = 0;
			std::string argName;
			std::tie(std::ignore, argIndex, argName) =  isReturnedByFun(*caller, inputValue);
			if(argIndex == -1) {
				if (addMarkedFunction(caller, argIndex, argName, newCallers) ) {
					auto callers = findCallersInCG(caller);
					continue;
				}
			}
			std::tie( std::ignore, argIndex, argName) = getReachedParamIndex(*caller,inputValue);
			if( argIndex > 0 ) {
				if (addMarkedFunction(caller, argIndex, argName, newCallers) ) {
					continue;
				}
			}
			get_print_stream(3) << "Function " << caller->getName() << " does not propagate the input\n";
		}
		delete nextCallers;
		nextCallers = newCallers;
		itCounter++;
	} while(itCounter != MaxSteps && !nextCallers->empty());
	return false;
}

void BackwardPropagationPass::print(raw_ostream &OS, const Module *M) const {


}


bool BackwardPropagationPass::doInitialization(Module &M) {
	moduleCG = new CallGraph(M);
	parseInputFiles(M);
	markInputFunctions(M);
	nextCallers = new std::map<Function*, MarkedFunInfo>();
	for(auto P : markedFunctions) {
		Function *inF = std::get<0>(P);
		MarkedFunInfo &mfInfo = std::get<1>(P) ;
		if( inF == nullptr) {
			get_print_stream(3) << "ERROR! Null function in marked Functions inside do initialization!!!\n";
			continue;
		}
		auto callers = findCallersInCG(inF);
		for( Function* F: callers ) {
			nextCallers->emplace(F, mfInfo);
			markPassFunction(F, true, mfInfo);
		}
	}
	printMarkedFunctions();
	printNextCallers();
	while( MaxStepsPass::getMaxLength == 0 ) {};  // Naive synchronization
	return false;
}

void BackwardPropagationPass::parseInputFiles(Module &M) {
	RelocationsMap relocationMappings;
	std::error_code FileError;
	get_print_stream(1) << "Reading input functions from file " << MarkedFunctionsInputFile.c_str() << "...\n";
	std::ifstream namesFile (MarkedFunctionsInputFile.c_str());
	std::string fileLine;
	std::map<std::string, MarkedFunInfo> tempMap;
	if(namesFile.is_open()) {
		while( std::getline(namesFile, fileLine) ) {
			std::vector<std::string> fields;
			std::stringstream ss(fileLine);
			std::array<char, 128> token;
			while (ss.getline(&token[0], 128, ',')) {
				fields.push_back(std::string(&token[0]));
			}
			std::string name(fields[0]);
			int index = std::stoi(fields[1]);
			std::string argName(fields[2]);

			MarkedFunInfo newInfo(name, index, argName);
			tempMap.emplace(name, newInfo);

		}
		namesFile.close();
	}

	// parse relocation mappings
	get_print_stream(1) << "Reading relocations from file " << MarkedFunctionsInputFile.c_str() << "...\n";
	std::ifstream relocsFile (RelocationsMappingsInputFile.c_str());
	if(relocsFile.is_open()) {
		while( std::getline(relocsFile, fileLine) ) {
			std::vector<std::string> fields;
			std::stringstream ss(fileLine);
			std::array<char, 128> token;
			while (ss.getline(&token[0], 128, ',')) {
				fields.push_back(std::string(&token[0]));
			}
			std::string address(fields[0])  ;
			// std::remove_if(address.begin(), address.end(), isspace);
			address.erase(std::remove(address.begin(), address.end(), ' '), address.end());
			std::string name(fields[1]);
			relocationMappings.emplace(address,name);
		}
		relocsFile.close();
	}

	// merge relocations and function names

	for(auto P : tempMap) {
		std::string fName = std::get<0>(P);
		MarkedFunInfo &fInfo = std::get<1>(P);
		if( M.getFunction(fName) != nullptr) {
			markedFunctions.emplace(M.getFunction(fName), fInfo);
		} else if (M.getFunction("bb." + fName) != nullptr ){
			MarkedFunInfo wrappedfInfo { "bb." + fName, std::get<1>(fInfo), std::get<2>(fInfo) };
			markedFunctions.emplace(M.getFunction("bb." + fName), wrappedfInfo);
		} else {
			get_print_stream(2) << "No module function found for " << fName << " or bb." << fName << "!\n";

		}
		get_print_stream(1) << "Searching plt for " << fName << "...\n";
		for( auto P2 : relocationMappings) {


			std::string bb = std::get<0>(P2);
			std::string relName = std::get<1>(P2);

 			get_print_stream(2) << "Analyzing relocation <" << bb << ", " << relName << ">... ";
			Function *F = searchFunctionByAddress(M, bb);

			if ( fName.compare(relName) == 0 && F != nullptr ) {

				MarkedFunInfo &oldInfo = std::get<1>(P);
				int argIndex = std::get<1>(oldInfo);

				std::string argName = std::get<2>(oldInfo);

				MarkedFunInfo newInfo {F->getName().str(), argIndex, argName} ;
				get_print_stream(2) << "Found module function " << F->getName() <<"!";
				auto ins_res = markedFunctions.emplace(F, newInfo);
			}
			get_print_stream(2) << "\n";
		}
	}
}

Function* BackwardPropagationPass::searchFunctionByAddress(Module &M, std::string address) {
	Function *F = M.getFunction("bb.0x" + address);
	if ( F != nullptr ) {
		return F;
	}
	F = M.getFunction("bb.0x5000" + address);
	if ( F != nullptr ) {
		return F;
	}
	return nullptr;
}


void BackwardPropagationPass::markInputFunctions(Module &M) {
	for(Function &F: M) {
		std::string fName = F.getName().str();
		if(markedFunctions.find(&F) != markedFunctions.end()) {
			get_print_stream(3) << F.getName() << " is a marked function!\n";
			markInputFunction(&F);
		}
	}

}


std::vector<Function*> BackwardPropagationPass::findCallersInCG(Function *F) {
	assert(this->moduleCG && "Null CG pointer, findCallersInCG cannot be performed!\n");
	std::vector<Function*> res;
	for(auto it= df_begin(moduleCG), it_end=df_end(moduleCG); it!=it_end; it++) {

		Function *nodeF = it->getFunction();
		if( nodeF == nullptr) {
		        continue;
		}
		for(auto calledIt=it->begin(), called_end=it->end(); calledIt != called_end ; calledIt++) {
			CallGraphNode *calledNode = calledIt->second;
			Function* calledF = calledNode->getFunction();
			if( calledF == nullptr) {
				continue;
			}
			if( calledF == F ) {
			        res.push_back(nodeF);
			}
		}
	}
	if (res.empty() ) {
		get_print_stream(3) << "No callers for " << F->getName() << "\n";
	} else {
		get_print_stream(3) << "Found " << res.size() << " callers for " << F->getName() << "\n";
	}
	return res;
}

bool BackwardPropagationPass::doFinalization(Module &M) {
	printMarkedFunctions();
	printNextCallers();
	return false;
}

bool BackwardPropagationPass::toAnalyze(Function *F) {
	MDNode *toanalizeMD;
	return false;
}

MarkedFunInfo  BackwardPropagationPass::getReachedParamIndex(Function &F, const Value* V){
	MarkedFunInfo nullResult {F.getName().str(), -1, "unknown" };
	if (V == nullptr) {
		return nullResult;
	}
	std::deque<const Value*> nextValues;
	nextValues.push_back(V);
	do {
		const User* currentUser = dyn_cast<User>(nextValues.front());
		nextValues.pop_front();
		if(currentUser == nullptr) {
			continue;
		}
		int index = getArgIndex(F,dyn_cast<Value>(currentUser));
		if( index > 0 )  {
			MarkedFunInfo res { F.getName().str(), index, currentUser->getName().str()};
			return res;
		}
		for( const Value* usedVal : currentUser->operand_values()) {

			if(std::find(nextValues.begin(), nextValues.end(), usedVal) == nextValues.end() ) {
				nextValues.push_back(usedVal);
			}
		}
	} while(! nextValues.empty());
	return nullResult;

}

const Value* BackwardPropagationPass::searchForNamedParameter(Function &F, const Value* startPoint, std::string name) {
	if (startPoint == nullptr) {
		return nullptr;
	}
	std::deque<const Value*> nextValues;
	nextValues.push_back(startPoint);
	do {
		const User* currentUser = dyn_cast<User>(nextValues.front());
		nextValues.pop_front();
		if(currentUser == nullptr) {
			continue;
		}
		if( currentUser->getName().compare(name) == 0 ) {
			return dyn_cast<Value>(currentUser);
		}

		for( const Value* usedVal : currentUser->operand_values()) {

			if(std::find(nextValues.begin(), nextValues.end(), usedVal) == nextValues.end() ) {
				nextValues.push_back(usedVal);
			}
		}
	} while(! nextValues.empty());
	return nullptr;

}

MarkedFunInfo BackwardPropagationPass::isReturnedByFun(Function &F, const Value* V) {
	MarkedFunInfo nullResult { F.getName().str(), 0, "" };
	if(V == nullptr) {
		return nullResult;
	}
	std::deque<const Value*> nextValues;
	nextValues.push_back(V);
	do {
		const Value* currentVal = nextValues.front();
		nextValues.pop_front();
		if (currentVal == nullptr) {
			continue;
		}
		if ( isa<ReturnInst>(currentVal) ) {
			MarkedFunInfo res { F.getName().str(), -1, "rax" };
			return res;
		}

		for( const Use &U : currentVal->uses()) {
			if(U.getUser() == nullptr) {
				continue;
			}
			const User* currentUser = U.getUser();
			if( ! isa<Instruction>(currentUser) )
				continue;
			if( dyn_cast<Instruction>(currentUser)->getFunction() != &F) {
				continue;
			}
			const Value* nextVal = dyn_cast<Value>(currentUser);
			if(std::find(nextValues.begin(), nextValues.end(), nextVal) == nextValues.end() ) {
				nextValues.push_back(nextVal);

			}
		}
	} while( !nextValues.empty() );
	return nullResult;
}



// Copied from isReturnedByFun
const Value*  BackwardPropagationPass::searchForReturnRegister(Function &F, const Value* startPoint, std::string resReg = "rax") {
	if( !isa<Instruction>(startPoint) ) {
		return nullptr;
	}
	Function::iterator itBB;
	BasicBlock::iterator itInst;
	const Instruction *currentInst = nullptr;
	for( Function::iterator itF =F.begin(), f_end=F.end(); f_end != itF; itF++ ) {
		BasicBlock &currBB = *itF;
		itBB = itF;
		for( BasicBlock::iterator it = currBB.begin(), bb_end=currBB.end(); it!= bb_end; it++) {
			const Instruction &I = *it;
			currentInst = &I;
			itInst = it;
			if ( currentInst == startPoint ) {
				break;
			}
		}
		if ( currentInst == startPoint ) {
			break;
		}
	}
	if( itBB == F.end() ){
		return nullptr;
	}
	do{
		BasicBlock &currBB = *itBB;
		while(itInst != currBB.end()) {
			Instruction &I = *itInst;
			LoadInst *LI = dyn_cast<LoadInst>(&I);
			if( LI == nullptr) {
				itInst++;
				continue;
			}
			const Value *loadedVal = LI->getPointerOperand();
			if(loadedVal != nullptr && loadedVal->getName().compare(resReg) == 0) {
				return dyn_cast<Value>(LI);
			}
			itInst++;
		}
		itBB++;
		if( itBB != F.end()) {
			itInst = itBB->begin();
		}
	} while( itBB != F.end() );
	return nullptr;
}


int BackwardPropagationPass::getArgIndex(Function &F, const Value* V) {
	if(V == nullptr) {
		return -1;
	}
	int index = 1;
	for( Argument &A: F.args()) {
		if( V == dyn_cast<Value>(&A)) {
			get_print_stream(3) << "Found function "  <<F.getName() << " argument!\n";
			return index;
		}
		index++;
	}
	return -1;
}


void BackwardPropagationPass::markInputFunction(Function* F) {
	LLVMContext& C = F->getContext();
	bool alreadyMarked = isInputFunction(F);
      	MDNode* N = nullptr;
	if(alreadyMarked) {
		return;
	}
	N = MDNode::get(C, MDString::get(C, "true"));
	F->setMetadata(REVNG_INPUT_MD, N);
}


void BackwardPropagationPass::markPassFunction(Function* F, bool status, MarkedFunInfo &mfInfo) {
	LLVMContext& C = F->getContext();
      	MDNode* N = nullptr;
	std::string formattedStatus =  formatv("{0}", status);
	N = MDNode::get(C, MDString::get(C, formattedStatus));
	F->setMetadata(REVNG_SECURITY_MARKED_MD, N);
	MarkedFunctions++;
	auto searchIt = taintAnalysis.find(F);
	if (searchIt == taintAnalysis.end() ) {
		taintAnalysis.emplace(F, std::vector<MarkedFunInfo>(mfInfo));
	} else {
		searchIt->second.push_back(inputFunction);
	}
}

const Value* BackwardPropagationPass::getInputValue(Function &F, MarkedFunInfo &mfInfo) {
	std::string markedName = std::get<0>(mfInfo);
	int argIndex = std::get<1>(mfInfo);
	for( BasicBlock &BB : F) {
		for(const Instruction &I : BB) {
			if( const CallInst *CI = dyn_cast<CallInst>(&I) ) {
				const Function* calledF = CI->getCalledFunction();
				if( calledF == nullptr)
					continue;
				if(calledF->getName().compare(markedName) != 0) {
					continue;
				}
				get_print_stream(3) << "Found call site for " << markedName << " in " << F.getName() << ", input value is : ";
				if( argIndex > 0 ) {
					const Value* res = nullptr;
					if( argIndex >= CI->getNumArgOperands()) {
						get_print_stream(3) << "WARNING! ";
						CI->print(get_print_stream(3));
						get_print_stream(3) << " has not argument number " << argIndex;
					} else {
						res = CI->getArgOperand(argIndex-1);
					}
					if( res != nullptr) {
						res->print(get_print_stream(3));
						get_print_stream(3) << "\n";
						return res;

					}
					get_print_stream(3) << "WARNING! Argument " << argIndex << "for call to " << F.getName() << " is null, searching by name... ";
					res = searchForNamedParameter(F,dyn_cast<Value>(&I),std::get<2>(mfInfo));
					if( res != nullptr) {
						res->print(get_print_stream(3));
						get_print_stream(3) << "\n";
						return res;
					}
					get_print_stream(3) << "ERROR! Argument was not found even with name " << std::get<2>(mfInfo) << "!!!\n";
					return res;
				} else {
					const Value *res = nullptr;
					FunctionType *fType = CI->getFunctionType();
					if( fType == nullptr) {
						return nullptr;
					}
					Type *resType = fType->getReturnType() ;
					if(resType == nullptr) {
						return nullptr;
					}
					if( resType->isVoidTy()) {
						get_print_stream(3) << "WARNING! Actual return type for call " ;
						CI->print(get_print_stream(3));
						get_print_stream(3) << " is void, searching for return register... ";
						res = searchForReturnRegister(F,dyn_cast<Value>(&I),std::get<2>(mfInfo));
					} else {
						res = dyn_cast<Value>(&I);
					}
					if( res == nullptr) {
						get_print_stream(3) << "ERROR! Return value not found for call to " << F.getName() << "\n";

					} else {
						res->print(get_print_stream(3));
						get_print_stream(3) << "\n";
					}
					return res;

				}
			}
		}
	}
	return nullptr;
}


bool BackwardPropagationPass::addMarkedFunction(Function *markedF, int argIndex, std::string argName, std::map<Function*,MarkedFunInfo> *newCallers = nullptr) {
	if( markedF == nullptr) {
		get_print_stream(3) << "Not adding a nullptr function\n";
		return false;
	}
	get_print_stream(3) << markedF->getName() << " is a new markedFunctions with input argument " << argIndex << " with name " << argName << "...\n";

	std::string fName = markedF->getName().str();
	MarkedFunInfo newInfo { fName,  argIndex, argName };
	markedFunctions.emplace(markedF,  newInfo);
	markInputFunction(markedF);
	InputFunctions++;
	if(newCallers != nullptr) {
		auto callers = findCallersInCG(markedF);
		for (Function* newCaller : callers) {
			if( newCaller == nullptr) {
				continue;
			}
			newCallers->emplace(newCaller, newInfo);
			markPassFunction(newCaller, true, newInfo);
		}
	}
	return true;
}

// DEBUG ONLY
void BackwardPropagationPass::printMarkedFunctions() {

	// // debug
	get_print_stream(3) << "Input marked functions: \n";
	for(auto P : markedFunctions) {
		MarkedFunInfo &info = std::get<1>(P);
		get_print_stream(3) << "- " << std::get<0>(info) << " : argumentPos=" << std::get<1>(info) << ", argumentName=" << std::get<2>(info) << "\n";
	}
}

void BackwardPropagationPass::printNextCallers() {
	if(nextCallers->empty()) {
		get_print_stream(3) << "No callers!\n";
		return;
	}
	for(auto P : *nextCallers) {
		Function* F = std::get<0>(P);
		MarkedFunInfo &mfInfo = std::get<1>(P);
		if (F == nullptr) {
			get_print_stream(3) << "ERROR! Null function in nextCallers as key!!!\n";
		} else {
			get_print_stream(3) << "Function " << F->getName() << " calls marked function " << std::get<0>(mfInfo) << ", input value on " << std::get<2>(mfInfo) << "(CALL_POS = " << std::get<1>(mfInfo) << ")\n";

		}

	}
}


FunctionScraper::FunctionScraper() {
}

bool FunctionScraper::analyze(const Function *F) {
	if (F == nullptr) {
		return false;
	}
	currentF = F;
	rgScraper.runOnFunction(*F);
	currentRF = rgScraper.getRevngFunction();

	get_print_stream(3) << "Scraping Function " << currentF->getName() << "...\n";
	currentStackVarsFlows.clear();
	currentVarsFlows.clear();
	currentRiskyStores.clear();



	if( !(currentRF->getFunctionName() == currentF->getName() && currentRF->getType() == RevngFunction::TYPE::ISOLATED)) {
		get_print_stream(3) << "Function arguments not found for "<< currentF->getName() <<"!\n";
		return false;
	}
	analyzePromotedArgsUsage(currentRF, currentF);

	// analyzes uses of args
	analyzeArgsUsage(currentRF, currentF);

	analyzeVSPUsage(currentRF, currentF);

	// analyzes uses of stack painter
	// analyzeStackArgsUsage(currentRF, &F);

	findRiskyStores();
	return false;
}

bool FunctionScraper::isaUserOfParameter(const User *UR, const Value *param) const {
	if (UR == nullptr || param == nullptr) {
		get_print_stream(3) << "Null pointer in isaUserOfParameter\n";
		return false;
	}
	for(auto OP = UR->op_begin(); OP!=UR->op_end(); OP++) {
		if(OP->get() == param)
			return true;
	}
	return false;
}


bool FunctionScraper::isaUserOfParams(const User *UR) const {
	if (UR == nullptr) {
		get_print_stream(3) << "Null pointer in isaUserOfParameter\n";
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

void FunctionScraper::print(raw_ostream &OS, const Module *M) const {
	OS << "Revng Function arguments obtained \n";
	unsigned int i= 0;

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

	if(currentRiskyStores.empty()) {
		OS << " No risky stores found\n";
	} else {
		OS << "Possible risky stores found: \n";
		for (auto RS : currentRiskyStores) {
			OS << "\t" << "Value deriving from " << *(RS.getPointedValue()) << " used in " << *(RS.getStoreInst()) << "\n";
		}
	}
}


std::vector<DefUseChain> FunctionScraper::getValueFlows(const Value* startValue) const {
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
	get_print_stream(3) << "Found " << result.size() << " flows for " << startValue->getName() << "\n";
	return result;
}



std::vector<DefUse> FunctionScraper::traverseDefUseChain(const Value *V) const  {
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

bool FunctionScraper::isInChain(std::vector<DefUse> &chain, DefUse &V) const {
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


void FunctionScraper::printOperandsRange(raw_ostream &OS, const Instruction *UR) const { // instruction is treated as a user, but we need its type to get back basic block
	assert(UR != nullptr && "Nullptr passed t printOperandsRange");
	// assert(LVI != nullptr && "LVI analysis not obtained");

	for(auto OP = UR->op_begin(); OP!=UR->op_end(); OP++) {
		Value *OPV = OP->get();
		OS << "\t\tOperand " << OPV->getName() << ": ";
		printValueRange(OS, OPV, UR->getParent());
		OS << "\n";
	}
}


void FunctionScraper::printValueRange(raw_ostream &OS, Value *V, const BasicBlock* context) const { // instruction is treated as a user, but we need its type to get back basic block
	assert(V != nullptr && "Nullptr passed t printValueRange");
	// assert(LVI != nullptr && "LVI analysis not obtained");

}

void FunctionScraper::findRiskyStores() {
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

bool FunctionScraper::isaRiskyStore(const DefUse &DU) const {
	const User* U = std::get<0>(DU);
	const Value* V = std::get<1>(DU);
	if(isa<StoreInst>(U)) {
		const StoreInst* store = dyn_cast<StoreInst>(U);
		if (store->getPointerOperand() == V)
			return true;
	}
	return false;

}

bool FunctionScraper::containsRiskyStore(std::vector<RiskyStore>& vector, const StoreInst* store) const {
	const StoreInst* currStore = nullptr;
	for(auto RS : vector) {
		currStore = RS.getStoreInst();
		if(currStore == store)
			return true;
	}
	return false;
}

void FunctionScraper::analyzeArgsUsage(const RevngFunction* currentRF, const Function *F) {

	get_print_stream(3) << "Analyzing arguments for " << F->getName() << "\n";
	bool firstUsageFound = false;
	for(const GlobalVariable *GV: currentRF->getArguments()) {
		// Reinitialize
		std::vector<DefUseChain> defUseChains = analyzeSingleArgUsage(F, GV);
		VariableFlow vflow(GV, defUseChains);
		currentVarsFlows.push_back(vflow);
		TotalVarChains++;
	}
}

void FunctionScraper::analyzePromotedArgsUsage(const RevngFunction* currentRF, const Function *F) {
	get_print_stream(3) << F->getName() << " has " << F->arg_size() << " promoted arguments\n";
	for( Function::const_arg_iterator A = F->arg_begin(), A_end = F->arg_end(); A != A_end ;  A++) {
		std::vector<DefUseChain> defUseChains = analyzeSingleArgUsage(F, dyn_cast<Value>(A));
		VariableFlow vflow(dyn_cast<Value>(A), defUseChains);
		currentVarsFlows.push_back(vflow);
		TotalVarChains++;
	}
}


std::vector<DefUseChain> FunctionScraper::getSSAValueFlows(const Value* V) const {
	std::vector<DefUseChain> nullResult;
	const Value* startValue = nullptr;
	auto symTable = currentF->getValueSymbolTable();
	if(symTable) {
		StringRef initName((V->getName() + ".0").str());
		startValue =  symTable->lookup(initName);
	}
	if ( startValue != nullptr) {
		get_print_stream(3) << "Found an inital memoryssa value for " << V->getName() << ": " << startValue->getName() << "\n";
		return getValueFlows(startValue);
	} else {
		return nullResult;
	}
}


std::vector<DefUseChain> FunctionScraper::analyzeSingleArgUsage(const Function* F, const Value* var) {
	std::vector<DefUseChain> defUseChains;
	DefUseChain defUseChain;
	Value* initialValue = nullptr;
	return getValueFlows(var);
}

void FunctionScraper::analyzeVSPUsage(const RevngFunction* currentRF, const Function* F) {

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

void FunctionScraper::analyzeStackArgsUsage(const RevngFunction* currentRF, const Function* F) {
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

RevngFunctionScraper::RevngFunctionScraper() {
}


void RevngFunctionScraper::parseMDTuple(std::vector<const GlobalVariable*> &res, MDTuple &tuple) {
  const MDOperand *op= tuple.op_begin();
  while (op != tuple.op_end()) {
    Metadata* meta = op->get();
    if (isa<ValueAsMetadata>(meta)) {
      ValueAsMetadata* metaval = dyn_cast<ValueAsMetadata>(meta);
      Value* val = metaval->getValue();
      Type* tval = metaval->getType();
      if(isa<GlobalVariable>(val) && tval->isPointerTy()) { // Found a global register used as parameter by function
	GlobalVariable *gval = dyn_cast<GlobalVariable>(val) ;
	if(std::find(res.begin(), res.end(), gval) == res.end()) {
	  res.push_back(gval); // Found a new argument
	}
      }
    }
    else if(isa<MDTuple>(meta))
      parseMDTuple(res, *(dyn_cast<MDTuple>(meta)));
    op++;
  }
}

void RevngFunctionScraper::scanVirtualStack(std::vector<const VirtualStackParam*> &res,  const GlobalVariable *virtRSP) {
	int virtualStackParamIndex = 0;
	auto vRSPusers = virtRSP->users();
	for( const User* U:  vRSPusers) {
		const Value *virtVar = findVirtStackParam(U);
		if( virtVar ) {
			virtualStackParamIndex++;
			res.push_back(new VirtualStackParam(virtVar, virtualStackParamIndex, 0));
		}
	}
}

const Value* RevngFunctionScraper::findVirtStackParam(const User *U) {
	const Value *res = nullptr;
	bool endSearch = false;
	std::vector<const User*> alreadyVisited;
	std::deque<const User*> nextUsers;
	if(const Instruction* I = dyn_cast<Instruction>(U)) {
		if ( I->getFunction() == scrapedFun) {
			nextUsers.push_back(U);
		}
	}
       	const User* currentUser = nullptr;
	while(!nextUsers.empty()) {
		get_print_stream(3) << "Remaining users: " << nextUsers.size() << "\n";
		currentUser = nextUsers.front();
		nextUsers.pop_front();
		if (const Instruction* I = dyn_cast<Instruction>(currentUser)) {
			if( I->getFunction() == scrapedFun) {
				// going outside the function
				if( const IntToPtrInst* popInst = dyn_cast<IntToPtrInst>(I)) {
					res = cast<Value>(popInst);
					return res;
				}
				for(const User* U2:  I->users()) {
					if(std::find(alreadyVisited.begin(), alreadyVisited.end(), U2) == alreadyVisited.end()) {
						if( isa<Instruction>(U2) && dyn_cast<Instruction>(U2)->getFunction() == scrapedFun)
							nextUsers.push_back(U2);
					}
				}
			}
		}
		alreadyVisited.push_back(currentUser);
	}
	return nullptr;
}




void RevngFunctionScraper::printMDTuple(raw_ostream &OS, MDTuple &tuple) {
  const MDOperand *op= tuple.op_begin();
  while (op != tuple.op_end()) {
    Metadata* meta = op->get();
    OS << "\t";
    if (isa<ValueAsMetadata>(meta)) {
      OS << "Value metadata " ;
      ValueAsMetadata* metaval = dyn_cast<ValueAsMetadata>(meta);
      Value* val = metaval->getValue();
      Type* tval = metaval->getType();
      if(tval->isPointerTy()) {
	OS << "pointer ";
      }
      if(isa<GlobalVariable>(val)) {
	OS << "to global variable ";
      }
      OS  << val->getName();
    }
    else if (isa<ConstantAsMetadata>(meta)) {
      OS << "Constant metadata ";
      meta->print(OS);
    }
    else if(isa<MDTuple>(meta))
      printMDTuple(OS, *(dyn_cast<MDTuple>(meta)));
    OS << " ;\n";
    op++;
  }
}

bool RevngFunctionScraper::runOnFunction(const Function &F) {
	get_print_stream(3) << "Starting RevngFunctionScraper on function" << F.getName() << "...\n";

  res.functionName = F.getName();
  res.functionArguments.clear();
  res.functionVirtStackParams.clear();
  MDNode *funcMetadata = F.getMetadata("revng.func.entry");
  get_print_stream(3) << "Analyzing " << F.getName() << "...\n";
  if (funcMetadata == nullptr || F.isDeclaration()) {
    get_print_stream(3) << F.getName() <<  " is not a revng isolated function\n";
    res.type = RevngFunction::TYPE::NOT_ISOLATED;
    return false;
  }
  if (!revngFunctionRegex.match(F.getName())) {
	      get_print_stream(3) << F.getName() <<  " does not start with \"bb.\", maybe is a QEMU helper\n";
    res.type = RevngFunction::TYPE::NOT_ISOLATED;
    return false;
  }
  scrapedFun = &F;
  res.type = RevngFunction::TYPE::ISOLATED;
  const MDOperand *op_it = funcMetadata->op_begin(); // Metadata for name
  // Metadata operand for Address
  op_it++;
  // Metadata operand for type
  op_it++;
  // Metadata operand for clobbered CSVs
  op_it++;
  // Metadata operand for first argument
  int index = 3;
  while (op_it != funcMetadata->op_end()) {
    index++;

    Metadata *meta = op_it->get(); // print metadata operand
    if( isa<MDString>(meta) ) {
      get_print_stream(3) << "Metadata string ";
    }
    else if (isa<ValueAsMetadata>(meta)){
      get_print_stream(3) << "value as metadata";
      ValueAsMetadata* valueMD = dyn_cast<ValueAsMetadata>(meta);
    }
    else if (isa<MDTuple>(meta)) {
      MDTuple *tuple = dyn_cast<MDTuple>(meta);
      parseMDTuple(res.functionArguments, *tuple);
    }
    op_it++;
  }
   for(const GlobalVariable &GV: scrapedFun->getParent()->globals() ) {
	   if(GV.getName() == "rsp") res.virtStackPointer = &GV;
	   if(GV.getName() == "esp") res.virtStackPointer = &GV;
   }

  if(res.virtStackPointer){
       get_print_stream(3) << "Scanning virtual stack for passed arguments \n";
       scanVirtualStack(res.functionVirtStackParams, res.virtStackPointer);
  }

  filterOutRevngVars();
  get_print_stream(3) << "Function params found for " << scrapedFun->getName() << ": \n";
  for (const GlobalVariable *GV: res.functionArguments) {
   get_print_stream(3) << "- ";
   GV->print(get_print_stream(3));
   get_print_stream(3) << "\n";
  }
  get_print_stream(3) << "Function stack params found for " << scrapedFun->getName() << ": \n";
  return false;
}



const RevngFunction* RevngFunctionScraper::getRevngFunction() const {
  return &(this->res);
}

void RevngFunctionScraper::print(raw_ostream &OS, const Module *M) const {
}


StringRef RevngFunctionScraper::printInstruction(Instruction *I) {
  StringRef result;
  if(I == nullptr) {
    return "Null input function pointer";
  }
  else {
    std::string tempString = "discardx"; // Fillin firsts slots that are discarded by StringRef
    if(I->getName() == "") {
      tempString += "Unnamed instruction";
    }
    else {
      tempString += I->getName().str();
    }
    tempString += " of type ";
    tempString += getInstructionTypeString(I).str();
    result= tempString;
    return result;
  }
}

StringRef RevngFunctionScraper::getInstructionTypeString(Instruction *I) {
	if (isa<BinaryOperator>(I)) {
	  return "Binary";
	}
	else if (isa<BranchInst>(I)) {
	  return "Branch";
	}
	else if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
	  return "Call";

	}
	else if (isa<CmpInst>(I)) {
	  return "Compare";
	}

	else if (isa<UnaryInstruction>(I)) {
	  return "Unary";
	}

	else if (isa<CatchReturnInst>(I)) {
	  return "CatchReturn";
	}

	else if (isa<CatchSwitchInst>(I)) {
	  return "CatchSwitch";
	}
	else if (isa<ExtractElementInst>(I)) {
	  return "ExtractElement";
	}
	else if (isa<FenceInst>(I)) {
	  return "Fence";
	}

	else if (isa<GetElementPtrInst>(I)) {
	  return "GetElementPointer";
	}
	else if (isa<FuncletPadInst>(I)) {
	  return "Funclet Pad";
	}

	else if (isa<IndirectBrInst>(I)) {
	  return "Indirect Branch";
	}

	else if (isa<LandingPadInst>(I)) {
	  return "LandingPad";
	}

	else if (isa<PHINode>(I)) {
	  return "PHI";
	}

	else if (isa<ResumeInst>(I)) {
	  return "Resume";
	}

	else if (isa<ReturnInst>(I)) {
	  return "Return";
	}

	else if (isa<SelectInst>(I)) {
	  return "Select";
	}

	else if (isa<SwitchInst>(I)) {
	  return "Switch";
	}

	else if (isa<UnreachableInst>(I)) {
	  return "Unreachable";
	}

	else if (isa<StoreInst>(I)) {
	  return "Store";
	}

	else if (isa<ShuffleVectorInst>(I)) {
	  return "ShuffleVector";
	}
	else {
	  return "Unknown" ;
	}
}

void RevngFunctionScraper::filterOutRevngVars() {
  auto GVit = res.functionArguments.begin();
  while(GVit != res.functionArguments.end()) {
    if(isaRevngVar(cast<Value>(*GVit))){
      res.functionArguments.erase(GVit);
    } else {
      GVit++;
    }
  }
}

bool RevngFunctionScraper::isaRevngVar(const Value* V) {
  assert(V != nullptr && "Nullptr passed to isaRevngVar");
  StringRef name = V->getName();
  get_print_stream(3) << "Variable name : " << name << "\n";
  if(name.equals("ExceptionFlag")) {
    return true;
  }
  if(name.equals("pc")) {
    return true;
  }
  if(name.equals("cc_op")) {
    return true;
  }
  if(name.equals("cc_src")) {
    return true;
  }
  if(name.equals("cc_dst")) {
    return true;
  }
  if(name.equals("")) {
    return true;
  }
  return false;

}

json::Object RevngFunctionScraper::toJSON() {
	json::Object result;
	json::Array fVars;
	for(const GlobalVariable* GV : this->res.functionArguments) {
		fVars.push_back(std::move(json::Value(GV->getName())));
	}
	result.try_emplace("functionArguments", std::move(fVars));
	json::Array fVirtStackVars;
	for(const VirtualStackParam* VSP : this->res.functionVirtStackParams) {
		std::string formattedValue = formatv("{0}", *(VSP->getValue()));

		json::Object fVirStackVar;
		fVirStackVar.try_emplace(VSP->getName(), std::move(json::Value(formattedValue)));
		fVirtStackVars.push_back(std::move(fVirStackVar));
	}
	result.try_emplace("functionVirtStackParams", std::move(fVirtStackVars));
	return result;
}
