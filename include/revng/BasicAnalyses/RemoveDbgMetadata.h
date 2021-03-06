#ifndef REVNG_REMOVEDBGMETADATA_H
#define REVNG_REMOVEDBGMETADATA_H

//
// This file is distributed under the MIT License. See LICENSE.md for details.
//

// LLVM includes
#include "llvm/Pass.h"

class RemoveDbgMetadata : public llvm::FunctionPass {
public:
  static char ID;

public:
  RemoveDbgMetadata() : llvm::FunctionPass(ID) {}

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }

  bool runOnFunction(llvm::Function &F) override;
};

#endif // REVNG_REMOVEDBGMETADATA_H
