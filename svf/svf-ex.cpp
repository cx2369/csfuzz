//===- svf-ex.cpp -- A driver example of SVF-------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===-----------------------------------------------------------------------===//

/*
 // A driver program of SVF including usages of SVF APIs
 //
 // Author: Yulei Sui,
 */

#include "SVF-LLVM/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/Options.h"

using namespace llvm;
using namespace std;
using namespace SVF;

/*!
 * An example to query alias results of two LLVM values
 */
SVF::AliasResult aliasQuery(PointerAnalysis *pta, Value *v1, Value *v2)
{
    SVFValue *val1 = LLVMModuleSet::getLLVMModuleSet()->getSVFValue(v1);
    SVFValue *val2 = LLVMModuleSet::getLLVMModuleSet()->getSVFValue(v2);

    return pta->alias(val1, val2);
}

/*!
 * An example to print points-to set of an LLVM value
 */
std::string printPts(PointerAnalysis *pta, Value *val)
{

    std::string str;
    raw_string_ostream rawstr(str);
    SVFValue *svfval = LLVMModuleSet::getLLVMModuleSet()->getSVFValue(val);

    NodeID pNodeId = pta->getPAG()->getValueNode(svfval);
    const PointsTo &pts = pta->getPts(pNodeId);
    for (PointsTo::iterator ii = pts.begin(), ie = pts.end();
         ii != ie; ii++)
    {
        rawstr << " " << *ii << " ";
        PAGNode *targetObj = pta->getPAG()->getGNode(*ii);
        if (targetObj->hasValue())
        {
            rawstr << "(" << targetObj->getValue()->toString() << ")\t ";
        }
    }

    return rawstr.str();
}

/*!
 * An example to query/collect all successor nodes from a ICFGNode (iNode) along control-flow graph (ICFG)
 */
void traverseOnICFG(ICFG *icfg, const Instruction *inst)
{
    const ICFGNode *iNode = LLVMModuleSet::getLLVMModuleSet()->getICFGNode(inst);

    FIFOWorkList<const ICFGNode *> worklist;
    Set<const ICFGNode *> visited;
    worklist.push(iNode);

    /// Traverse along VFG
    while (!worklist.empty())
    {
        const ICFGNode *iNode = worklist.pop();
        for (ICFGNode::const_iterator it = iNode->OutEdgeBegin(), eit =
                                                                      iNode->OutEdgeEnd();
             it != eit; ++it)
        {
            ICFGEdge *edge = *it;
            ICFGNode *succNode = edge->getDstNode();
            if (visited.find(succNode) == visited.end())
            {
                visited.insert(succNode);
                worklist.push(succNode);
            }
        }
    }
}

/*!
 * An example to query/collect all the uses of a definition of a value along value-flow graph (VFG)
 */
void traverseOnVFG(const SVFG *vfg, Value *val)
{
    SVFIR *pag = SVFIR::getPAG();
    SVFValue *svfval = LLVMModuleSet::getLLVMModuleSet()->getSVFValue(val);

    PAGNode *pNode = pag->getGNode(pag->getValueNode(svfval));
    const VFGNode *vNode = vfg->getDefSVFGNode(pNode);
    FIFOWorkList<const VFGNode *> worklist;
    Set<const VFGNode *> visited;
    worklist.push(vNode);

    /// Traverse along VFG
    while (!worklist.empty())
    {
        const VFGNode *vNode = worklist.pop();
        for (VFGNode::const_iterator it = vNode->OutEdgeBegin(), eit =
                                                                     vNode->OutEdgeEnd();
             it != eit; ++it)
        {
            VFGEdge *edge = *it;
            VFGNode *succNode = edge->getDstNode();
            if (visited.find(succNode) == visited.end())
            {
                visited.insert(succNode);
                worklist.push(succNode);
            }
        }
    }

    /// Collect all LLVM Values
    for (Set<const VFGNode *>::const_iterator it = visited.begin(), eit = visited.end(); it != eit; ++it)
    {
        const VFGNode *node = *it;
        /// can only query VFGNode involving top-level pointers (starting with % or @ in LLVM IR)
        /// PAGNode* pNode = vfg->getLHSTopLevPtr(node);
        /// Value* val = pNode->getValue();
    }
}

int main(int argc, char **argv)
{

    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(
        argc, argv, "Whole Program Points-to Analysis", "[options] <input-bitcode...>");

    if (Options::WriteAnder() == "ir_annotator")
    {
        LLVMModuleSet::preProcessBCs(moduleNameVec);
    }

    SVFModule *svfModule = LLVMModuleSet::buildSVFModule(moduleNameVec);

    /// Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder(svfModule);
    SVFIR *pag = builder.build();

    /// Create Andersen's pointer analysis
    Andersen *ander = AndersenWaveDiff::createAndersenWaveDiff(pag);

    /// ICFG
    ICFG *icfg = pag->getICFG();

    /// Sparse value-flow graph (SVFG)
    SVFGBuilder svfBuilder;
    SVFG *svfg = svfBuilder.buildFullSVFG(ander);

    //  cxteststart
    std::cout << "test:" << std::endl;

    PTACallGraph *callgraph = ander->getCallGraph();
    icfg->updateCallGraph(callgraph);

    SVFModule::FunctionSetType functionset = svfModule->getFunctionSet();
    for (auto func : functionset)
    {
        for (auto it = func->begin(); it != func->end(); ++it)
        {
            const SVFBasicBlock *SVFBB = *it;
            std::vector<const ICFGNode *> icfgnodes = SVFBB->getICFGNodeList();
            for (auto icfgnode : icfgnodes)
            {
                if (const auto *callNode = SVFUtil::dyn_cast<CallICFGNode>(icfgnode))
                {
                    if (callNode->isVirtualCall())
                    {
                        for (ICFGNode::const_iterator it = icfgnode->OutEdgeBegin(), eit = icfgnode->OutEdgeEnd(); it != eit; ++it)
                        {
                            ICFGEdge *edge = *it;
                            ICFGNode *succNode = edge->getDstNode();
                            const SVFFunction *calleefunc = succNode->getFun();
                            const SVFValue *svfValue = static_cast<const SVFValue *>(SVFBB);
                            const Value *BB = LLVMModuleSet::getLLVMModuleSet()->getLLVMValue(svfValue);
                            const llvm::BasicBlock *basicBlock = llvm::dyn_cast<llvm::BasicBlock>(BB);
                            uint32_t ret_debug_line = 0;
                            StringRef dbg_filename;
                            for (auto &I : *basicBlock)
                            {
                                unsigned int dbg_lineNumber = 0;
                                DebugLoc debugLoc = I.getDebugLoc();
                                if (debugLoc)
                                {
                                    DILocation *location = debugLoc.get();
                                    dbg_lineNumber = location->getLine();
                                    dbg_filename = location->getFilename();
                                    if (dbg_lineNumber != 0)
                                    {
                                        ret_debug_line = dbg_lineNumber;
                                        break;
                                    }
                                }
                            }
                            outs() << "func:" << func->getName() << ";file:" << dbg_filename.str() << ";callsite_line:" << ret_debug_line << "\n";
                            outs() << "indiract call:" << calleefunc->getName() << "\n\n";
                        }
                    }
                }
            }
        }
    }

    // cxtestend

    // clean up memory
    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();

    LLVMModuleSet::getLLVMModuleSet()->dumpModulesToFile(".svf.bc");
    SVF::LLVMModuleSet::releaseLLVMModuleSet();

    llvm::llvm_shutdown();
    return 0;
}
