#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include <iostream>

using namespace clang;
using namespace ento;

namespace {

class HytFmtStrChecker : public Checker<check::PreCall> {
//CallDescription ScanFn;
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &Ctx) const;

private:
  mutable std::unique_ptr<BugType> BT;
};

} // anonymous namespace



typedef llvm::ImmutableList<SVal>::iterator iterator;

void HytFmtStrChecker::checkPreCall(const CallEvent &Call,
                                   CheckerContext &Ctx) const {
  if (const IdentifierInfo *II = Call.getCalleeIdentifier()) {
    
    if (II->isStr("printf")) {
    	unsigned NumArgs = Call.getNumArgs();
    	if(NumArgs == 1){
    	  BT.reset(new BugType(this, "May lead to format string vulnerability", "Example checker"));
        ExplodedNode *Node = Ctx.generateErrorNode();
        auto Report = std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), Node);
        Ctx.emitReport(std::move(Report));
      }
      
    }  
  }
}

void ento::registerHytFmtStrChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<HytFmtStrChecker>();
}

bool ento::shouldRegisterHytFmtStrChecker(const CheckerManager &mgr) {
  return true;
}
