#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include <iostream>

using namespace clang;
using namespace ento;

using std::cout;
using std::endl;
using std::string;

namespace {

class HytScanfCallChecker : public Checker<check::PreCall> {
//CallDescription ScanFn;
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &Ctx) const;

private:
  mutable std::unique_ptr<BugType> BT;
};

} // anonymous namespace



typedef llvm::ImmutableList<SVal>::iterator iterator;

void HytScanfCallChecker::checkPreCall(const CallEvent &Call,
                                   CheckerContext &Ctx) const {
  if (const IdentifierInfo *II = Call.getCalleeIdentifier()) {
    if (II->isStr("__isoc99_scanf")) {	    
      SVal ArgVal = Call.getArgSVal(0);
      const MemRegion *MR = ArgVal.getAsRegion(); 
      if (!MR)
        return;
      string FmtStr = MR->getString();
      //cout << FmtStr <<endl;
      
      string s = "%s";
      string::size_type idx=FmtStr.find(s); //find %s in FmtStr.
      if (idx == string::npos ){ // no
          //cout <<  "no bugs\n";
          return;
      }
      else{ //
          //cout << "found bugs\n" ; 
          BT.reset(new BugType(this, "Call to scanf with %s, may cause stack overflow!", "Example checker"));
          ExplodedNode *Node = Ctx.generateErrorNode();
          auto Report
            = std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), Node);
          Ctx.emitReport(std::move(Report));
      }
      	    
    }
  }
}

void ento::registerHytScanfCallChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<HytScanfCallChecker>();
}

bool ento::shouldRegisterHytScanfCallChecker(const CheckerManager &mgr) {
  return true;
}
