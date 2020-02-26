#ifndef REVNG_FILTER_FUNCTIONS_PASS
#define REVNG_FILTER_FUNCTIONS_PASS


#include "llvm/Pass.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include "RevngFunctionParamsPass.h"
#include <ostream>
#include <vector>

using namespace llvm;

  /// Collect information about translated and isolated functions
namespace revng {

  struct FilterAdditionalFunctionsPass : public ModulePass { 
  
    static char ID;
    FilterAdditionalFunctionsPass();
    virtual ~FilterAdditionalFunctionsPass() {};
    virtual bool runOnModule(Module &M) override;
    virtual  void getAnalysisUsage(AnalysisUsage &AU) const override;
    void print(raw_ostream &OS, const Module *M) const override;

  private:
    bool isaUsefulFunction(const RevngFunction &RF);
    // RevngFunction result;
 };



}


#endif // REVNG_FILTER_FUNCTIONS_PASS
