#ifndef CACHE_H
#define CACHE_H

// Local includes
#include "Element.h"
#include "IntraproceduralFunctionSummary.h"

class GeneratedCodeBasicInfo;

namespace StackAnalysis {

/// \brief Cache for the result of the analysis of a function
///
/// This cache keeps track of three pieces of information:
///
/// * the result of the analysis of a function.
/// * the set of "fake", "noreturn" and "indirect tail call" functions.
/// * the association between each function and its return register.
class Cache {
private:
  /// \brief For each function, the result of the intraprocedural analysis
  std::map<llvm::BasicBlock *, IntraproceduralFunctionSummary> Results;

  /// \brief For each function, its link register (or nullptr for top of the
  ///        stack)
  std::map<llvm::BasicBlock *, llvm::GlobalVariable *> LinkRegisters;

  /// \brief The elected default link register (i.e., the most common)
  llvm::GlobalVariable *DefaultLinkRegister;

  std::set<llvm::BasicBlock *> FakeFunctions;
  std::set<llvm::BasicBlock *> NoReturnFunctions;
  std::set<llvm::BasicBlock *> IndirectTailCallFunctions;

  std::set<const llvm::LoadInst *> IdentityLoads;
  std::set<const llvm::StoreInst *> IdentityStores;

  std::map<const llvm::User *, int32_t> CSVToIndexMap;
  std::map<int32_t, llvm::User *> IndexToCSVMap;
  int32_t CSVCount;

public:
  /// \brief Identify default storage for link register, identity loads
  Cache(llvm::Function *F, GeneratedCodeBasicInfo *GCBI);

  int32_t getCPUIndex(const llvm::User *U) const { return CSVToIndexMap.at(U); }
  bool isCPU(const llvm::User *U) const { return CSVToIndexMap.count(U) != 0; }
  bool isCSV(const llvm::User *U) const {
    return CSVToIndexMap.count(U) != 0 and CSVToIndexMap.at(U) < CSVCount;
  }
  llvm::GlobalVariable *getCSVByIndex(int32_t I) const {
    return llvm::cast<llvm::GlobalVariable>(IndexToCSVMap.at(I));
  }
  bool isCSVIndex(int32_t I) const {
    return IndexToCSVMap.count(I) != 0 and I < CSVCount;
  }

  bool isFakeFunction(llvm::BasicBlock *Function) const {
    return FakeFunctions.count(Function) != 0;
  }

  void markAsFake(llvm::BasicBlock *Function) {
    FakeFunctions.insert(Function);
  }

  bool isNoReturnFunction(llvm::BasicBlock *Function) const {
    return NoReturnFunctions.count(Function) != 0;
  }

  void markAsNoReturn(llvm::BasicBlock *Function) {
    NoReturnFunctions.insert(Function);
  }

  /// \brief Query the cache for the result of the analysis for a specific
  ///        function
  ///
  /// \return the matching result, if available.
  llvm::Optional<const IntraproceduralFunctionSummary *>
  get(llvm::BasicBlock *Function) const;

  /// \brief Insert (or update) in the cache an entry for the function
  ///        \p Function
  bool update(llvm::BasicBlock *Function,
              const IntraproceduralFunctionSummary &Result);

  /// \brief Get the link register for the function identified by \p Function
  ///
  /// \return a pointer to the CSV representing the link register for
  ///         \p Function or nullptr, in case there's no link register (i.e.,
  ///         return addresses are stored on the stack).
  llvm::GlobalVariable *getLinkRegister(llvm::BasicBlock *Function) const {
    if (DefaultLinkRegister == nullptr)
      return nullptr;

    if (LinkRegisters.size() == 0) {
      return DefaultLinkRegister;
    } else {
      auto It = LinkRegisters.find(Function);
      if (It == LinkRegisters.end())
        return DefaultLinkRegister;
      else
        return It->second;
    }
  }

  /// An identity load is a load from a CSV whose value ends up (potentially
  /// truncated and/or in OR with another value) exclusively in the same CSV.
  ///
  /// Such loads should not be considered as actually "reading" a register.
  bool isIdentityLoad(const llvm::LoadInst *L) const {
    return IdentityLoads.count(L) != 0;
  }

  /// An identity store is a store associated to an identity load.
  bool isIdentityStore(const llvm::StoreInst *S) const {
    return IdentityStores.count(S) != 0;
  }

private:
  void assignCPUIndices(llvm::Function *F, GeneratedCodeBasicInfo *GCBI);
  void identifyPartialStores(const llvm::Function *F);
  void identifyIdentityLoads(const llvm::Function *F);
  void identifyLinkRegisters(const llvm::Module *M);
};

} // namespace StackAnalysis

#endif // CACHE_H
