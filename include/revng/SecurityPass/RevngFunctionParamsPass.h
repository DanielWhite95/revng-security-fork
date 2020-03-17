#ifndef REVNG_FUNCTION_PARAMS_PASS
#define REVNG_FUNCTION_PARAMS_PASS

#define DEBUG_TYPE "RevngFunctionParamsPass"

#include "llvm/Pass.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Regex.h"
#include <ostream>
#include <vector>

#include "revng/Support/SecurityDefinitions.h"
#include "revng/Support/CommandLine.h"

using namespace llvm;

  /// Collect information about translated and isolated functions
namespace revng {


  struct RevngFunctionParamsPass : public FunctionPass {
  public:
    static char ID;
    RevngFunctionParamsPass();
    virtual ~RevngFunctionParamsPass() {};
	  virtual bool doInitialization(Module &M) override;
	  virtual bool runOnFunction(Function &F) override;
	  virtual  void getAnalysisUsage(AnalysisUsage &AU) const override;
	  void print(raw_ostream &OS, const Module *M) const override;
	  const RevngFunction* getRevngFunction() const;
	  json::Object toJSON();

	  static StringRef getInstructionTypeString(Instruction* I);
	  static StringRef printInstruction(Instruction* I);

  private:
	  void printMDTuple(raw_ostream &OS, MDTuple &tuple);
	  void parseMDTuple(std::vector<const GlobalVariable*> &res, MDTuple &tuple);
	  const Value* findVirtStackParam(Function &F, const User *U);
	  void scanVirtualStack(Function &F, std::vector<const VirtualStackParam*> &res,  const GlobalVariable *virtRSP);
	  void filterOutRevngVars();
	  bool isaRevngVar(const Value*);
	  RevngFunction res;
	  Regex revngFunctionRegex = { "bb..*" };
	  const GlobalVariable* virtualStackPointer;

    // RevngFunction result;
 };



}


#endif // REVNG_FUNCTION_PARAMS_PASS
