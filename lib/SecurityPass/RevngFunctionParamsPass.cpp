#include "revng/SecurityPass/RevngFunctionParamsPass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/JSON.h"


using namespace llvm;
using namespace revng;

char RevngFunctionParamsPass::ID = 0;

static RegisterPass<RevngFunctionParamsPass> X("revng-func-params", "Analyze function params of revng isolated functions",
					       false /* Only looks at CFG */,
					       true /* Analysis Pass */);

RevngFunctionParamsPass::RevngFunctionParamsPass() : FunctionPass(ID) {
}


void RevngFunctionParamsPass::parseMDTuple(std::vector<const GlobalVariable*> &res, MDTuple &tuple) {
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

void RevngFunctionParamsPass::scanVirtualStack(Function &F,std::vector<const VirtualStackParam*> &res,  const GlobalVariable *virtRSP) {
	int virtualStackParamIndex = 0;
	auto vRSPusers = virtRSP->users();
	for( const User* U:  vRSPusers) {
		const Value *virtVar = findVirtStackParam(F, U);
		if( virtVar ) {
			virtualStackParamIndex++;
			res.push_back(new VirtualStackParam(virtVar, virtualStackParamIndex, 0));
		}
	}
}

const Value* RevngFunctionParamsPass::findVirtStackParam(Function &F, const User *U) {
	const Value *res = nullptr;
	bool endSearch = false;
	std::vector<const User*> alreadyVisited;
	std::deque<const User*> nextUsers;
	if(const Instruction* I = dyn_cast<Instruction>(U)) {
		if ( I->getFunction() == &F) {
			nextUsers.push_back(U);
		}
	}
       	const User* currentUser = nullptr;
	while(!nextUsers.empty()) {
			get_print_stream(3) << "Remaining users: " << nextUsers.size() << "\n";
			currentUser = nextUsers.front();
			nextUsers.pop_front();
			if (const Instruction* I = dyn_cast<Instruction>(currentUser)) {
				if( I->getFunction() == &F) {
					// going outside the function
					if( const IntToPtrInst* popInst = dyn_cast<IntToPtrInst>(I)) {
						res = cast<Value>(popInst);
						return res;
					}
					for(const User* U2:  I->users()) {
						if(std::find(alreadyVisited.begin(), alreadyVisited.end(), U2) == alreadyVisited.end()) {
							if( isa<Instruction>(U2) && dyn_cast<Instruction>(U2)->getFunction() == &F)
								nextUsers.push_back(U2);
						}
					}
				}
			}
			alreadyVisited.push_back(currentUser);
		}
		return nullptr;
	}



void RevngFunctionParamsPass::printMDTuple(raw_ostream &OS, MDTuple &tuple) {
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

bool RevngFunctionParamsPass::doInitialization(Module &M) {
	   for(const GlobalVariable &GV: M.globals() ) {
		   if(GV.getName() == "rsp") { // x86-64
			   virtualStackPointer = &GV;
		   }
		   if(GV.getName() == "esp") { // i386
			   virtualStackPointer = &GV;
		   }

   }
	   return false;
}

bool RevngFunctionParamsPass::runOnFunction(Function &F) {
	get_print_stream(3) << "Starting RevngFunctionParamsPass on function" << F.getName() << "...\n";
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
  res.type = RevngFunction::TYPE::ISOLATED;
  res.virtStackPointer = virtualStackPointer;
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

  if(res.virtStackPointer){
       get_print_stream(3) << "Scanning virtual stack for passed arguments \n";
       scanVirtualStack(F, res.functionVirtStackParams, res.virtStackPointer);
  }

  filterOutRevngVars();
  get_print_stream(3) << "Function params found for " << F.getName() << ": \n";
  for (const GlobalVariable *GV: res.functionArguments) {
   get_print_stream(3) << "- ";
   GV->print(get_print_stream(3));
   get_print_stream(3) << "\n";
  }
  get_print_stream(3) << "Function stack params found for " << F.getName() << ": \n";
  return false;
}



const RevngFunction* RevngFunctionParamsPass::getRevngFunction() const {
  return &(this->res);
}

void RevngFunctionParamsPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
}


void RevngFunctionParamsPass::print(raw_ostream &OS, const Module *M) const {

  getRevngFunction();
}


StringRef RevngFunctionParamsPass::printInstruction(Instruction *I) {
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

StringRef RevngFunctionParamsPass::getInstructionTypeString(Instruction *I) {
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

void RevngFunctionParamsPass::filterOutRevngVars() {
  auto GVit = res.functionArguments.begin();
  while(GVit != res.functionArguments.end()) {
    if(isaRevngVar(cast<Value>(*GVit))){
      res.functionArguments.erase(GVit);
    } else {
      GVit++;
    }
  }
}

bool RevngFunctionParamsPass::isaRevngVar(const Value* V) {
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

json::Object RevngFunctionParamsPass::toJSON() {
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
