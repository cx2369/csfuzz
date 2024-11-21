
#define AFL_LLVM_PASS

#include "lib/config.h"
#include "lib/debug.h"

#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <jsoncpp/json/json.h>
#include "nlohmann/json.hpp"
#include <queue>
#include <set>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unordered_set>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

cl::opt<std::string> Rfunc(
    "rfunc",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("rfunc"));

namespace
{
    class AFLCoverage : public ModulePass
    {
    public:
        static char ID;
        AFLCoverage() : ModulePass(ID) {}
        bool runOnModule(Module &M) override;
    };
}

char AFLCoverage::ID = 0;

// cx-func
//  for pass dir
void get_library_path()
{
}
// get debug line with BB(minimum debug line)
static u32 get_debug_line_with_BB(const BasicBlock *BB)
{
    u32 ret_debug_line = 0;
    for (auto &I : *BB)
    {
        StringRef dbg_filename;
        unsigned int dbg_lineNumber = 0;
        DebugLoc debugLoc = I.getDebugLoc();
        if (debugLoc)
        {
            DILocation *location = debugLoc.get();
            dbg_lineNumber = location->getLine();
            if (dbg_lineNumber != 0)
            {
                ret_debug_line = dbg_lineNumber;
                return ret_debug_line;
            }
        }
    }
    return ret_debug_line;
}
/* Skip blacklist function */
static bool isBlacklisted(const Function *F)
{
    static const SmallVector<std::string, 8> Blacklist = {
        "asan.",
        "llvm.",
        "sancov.",
        "__ubsan_handle_",
        "__asan_report",
        "free",
        "malloc",
        "calloc",
        "realloc"};

    for (auto const &BlacklistFunc : Blacklist)
    {
        if (F->getName().startswith(BlacklistFunc))
        {
            return true;
        }
    }
    return false;
}

static inline bool is_llvm_dbg_intrinsic(Instruction &instr)
{
    const bool is_call = instr.getOpcode() == Instruction::Invoke ||
                         instr.getOpcode() == Instruction::Call;
    if (!is_call)
    {
        return false;
    }
    auto call = dyn_cast<CallInst>(&instr);
    Function *calledFunc = call->getCalledFunction();
    if (calledFunc != NULL)
    {
        const bool ret = calledFunc->isIntrinsic() && calledFunc->getName().startswith("llvm.");
        return ret;
    }
    else
    {
        return false;
    }
}

static inline uint16_t get_block_id(BasicBlock &bb)
{
    uint16_t bbid = 0;
    MDNode *bb_node = nullptr;
    for (auto &ins : bb)
    {
        if ((bb_node = ins.getMetadata("afl_cur_loc")))
            break;
    }
    if (bb_node)
    {
        bbid = cast<ConstantInt>(cast<ValueAsMetadata>(bb_node->getOperand(0))->getValue())->getZExtValue();
    }
    return bbid;
}

static inline uint16_t get_edge_id(BasicBlock &src, BasicBlock &dst)
{
    uint16_t src_bbid = 0, dst_bbid = 0;
    src_bbid = get_block_id(src);
    dst_bbid = get_block_id(dst);
    if (src_bbid && dst_bbid)
    {
        return ((src_bbid >> 1) ^ dst_bbid);
    }
    return 0;
}

// cx targets,use for cx_cv
class CX_T
{
public:
    Function *F;
    std::vector<Instruction *> arg0; // should exclude arg0?
    std::vector<Instruction *> arg0_arg0;
};

// cx critical variables
class CX_CV
{
public:
    Instruction *instm;
    u16 index = 0;    //[1,CX_STATE_UNIT]
    u16 bitwidth = 0; // 8/16/32/64
    std::string type; // integer or pointer
};

bool AFLCoverage::runOnModule(Module &M)
{

    LLVMContext &C = M.getContext();
    DataLayout DL = M.getDataLayout();

    IRBuilder<> builder(C);

    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

    // cx-var
    std::string pass_path; // get pass path
    std::string funcid_file;
    std::string targets_file;
    std::string funcdist_file;

    std::unordered_set<std::string> targets;
    std::vector<CX_T> cx_ts;
    std::vector<CX_CV> cx_cvs;

    std::unordered_set<u16> assigned_indexs;
    std::map<std::string, u32> func2id;                                // func and id
    std::map<u32, std::map<u32, u32>> func_dist_map;                   // funcs dist map
    std::map<std::string, u32> targets_cvnum;                          // record targets fun and corresponding cv nums(original)
    std::map<std::string, u32> targets_cvnum_filter;                   // record targets fun and corresponding cv nums(final filter)
    std::map<std::string, u32> targets_cvnum_filter1;                  // record targets fun and corresponding cv nums(after filter1,before debug line)
    std::map<std::string, u32> targets_cvnum_filter2;                  // record targets fun and corresponding cv nums(after filter2,reachable to debug line)
    std::map<std::string, std::unordered_set<u32>> targets_func_lines; // record targets lines for filter
    std::unordered_set<std::string> targets_func_use_filter0;
    std::unordered_set<std::string> targets_func_use_filter1;
    std::unordered_set<std::string> targets_func_use_filter2;
    std::unordered_set<std::string> targets_func_use_filter3;

    uint32_t func_nums = 0, bb_nums = 0, inst_nums = 0;

    srandom((unsigned int)time(NULL));
    srand((unsigned int)time(NULL));

    // check ptr bitwidth
    int ptr_size = DL.getPointerSizeInBits();
    if (ptr_size != 64)
    {
        FATAL("ptr size is not 64");
    }

    /* Show a banner */
    char be_quiet = 0;
    if (isatty(2) && !getenv("AFL_QUIET"))
    {
        std::time_t current_time = std::time(nullptr);
        std::tm *local_time = std::localtime(&current_time);
        int year = local_time->tm_year + 1900;
        int month = local_time->tm_mon + 1;
        int day = local_time->tm_mday;
        int hour = local_time->tm_hour;
        int minute = local_time->tm_min;
        outs() << "--------------------------------------------------\ncxpass1:" << year << "-" << month << "-" << day << " " << hour << ":" << minute << "\n";
    }
    else
    {
        be_quiet = 1;
    }

    uint8_t rfunc = 0;
    // deal option
    if (Rfunc.compare("true") == 0)
    {
        rfunc = 1;
        // outs() << "rfunc is 1. \n";
    }
    else if (Rfunc.compare("false") == 0)
    {
        rfunc = 0;
        // outs() << "rfunc is 0. \n";
    }
    else if (Rfunc.empty())
    {
        rfunc = 0;
        // outs() << "rfunc not provide,will set 0.\n";
    }
    else
    {
        FATAL("rfunc option not right");
    }

    // extract put path
    std::string Filename = M.getSourceFileName();
    llvm::SmallString<1024> FilenameVec = StringRef(Filename);
    llvm::sys::fs::make_absolute(FilenameVec);
    llvm::StringRef FilenameRef = FilenameVec;
    std::string FilenameStr = FilenameRef.str();
    std::string putname = FilenameStr.substr(FilenameStr.find_last_of('/') + 1);
    putname = putname.substr(0, putname.find_last_of('.'));
    FilenameStr = FilenameStr.substr(0, FilenameStr.find_last_of('/'));
    FilenameStr = FilenameStr + "/";
    // outs() << "done-" << __LINE__ << "\n";

    // get pass dir
    Dl_info info;
    char pass_dir[1024];
    char absolute_pass_path[1024];
    if (int rc = dladdr((void *)get_library_path, &info) != 0)
    {
        strcpy(pass_dir, info.dli_fname);
        if (realpath(pass_dir, absolute_pass_path) != nullptr)
        {
        }
        else
        {
            FATAL("failed to resolve pass path\n");
        }
    }
    else
    {
        FATAL("failed to get pass path\n");
    }
    char *cx_pass_path = strrchr(absolute_pass_path, '/');
    if (cx_pass_path != nullptr)
    {
        *cx_pass_path = 0;
        pass_path = std::string(absolute_pass_path) + "/";
    }
    else
    {
        FATAL("failed to get txt and json dir");
    }
    // outs() << "done-" << __LINE__ << "\n";

    /* Decide instrumentation ratio */
    char *inst_ratio_str = getenv("AFL_INST_RATIO");
    unsigned int inst_ratio = 100;
    if (inst_ratio_str)
    {
        if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
            inst_ratio > 100)
            FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
    }

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */
    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    // func touched
    GlobalVariable *CXMapPtr1 =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__cx_area_ptr_1");
    // state
    GlobalVariable *CXMapPtr2 =
        new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__cx_area_ptr_2");

    // cx-analysis
    for (auto &F : M)
    {
        if (F.empty() || isBlacklisted(&F))
        {
            continue;
        }
        func_nums++;
        // outs()<<"func_name:"<<F.getName().str()<<"\n";
        for (auto &BB : F)
        {
            bb_nums++;
            for (auto &I : BB)
            {
                inst_nums++;
            }
        }
    }

    // load file,funcid,targets
    funcid_file = FilenameStr + "funcid.csv";
    targets_file = FilenameStr + "targets.txt";
    funcdist_file = FilenameStr + "calldst.json";

    // funcid
    std::ifstream fi(funcid_file);
    if (fi.is_open())
    {
        std::string line;
        while (getline(fi, line))
        {
            std::size_t dis_pos = line.find(",");
            std::string fname = line.substr(dis_pos + 1, line.length() - dis_pos);
            std::string idx_str = line.substr(0, dis_pos);
            func2id.emplace(fname, atoi(idx_str.c_str()));
        }
        fi.close();
    }
    else
    {
        FATAL("function id file not found!");
    }
    if (func2id.size() > CX_FUNC_UNIT)
    {
        FATAL("func size too lagrge");
    }

    // targets
    std::ifstream file(targets_file);
    if (file.is_open())
    {
        std::string line;
        while (std::getline(file, line))
        {
            std::string tem_function_name, tem_file_name, tem_line_number, tem_use_filter_str;
            std::istringstream tem_iss(line);
            std::getline(tem_iss, tem_function_name, ':');
            std::getline(tem_iss, tem_file_name, ':');
            std::getline(tem_iss, tem_line_number, ':');
            std::getline(tem_iss, tem_use_filter_str, ':');
            // outs() << tem_function_name << "  " << tem_file_name << "  " << tem_line_number << "  " << tem_use_filter3 << "\n";
            if (targets_func_lines.count(tem_function_name) > 0)
            {
                if (tem_file_name.empty() && tem_line_number.empty())
                {
                    std::unordered_set<u32> tem_lines;
                    tem_lines = targets_func_lines[tem_function_name];
                    tem_lines.insert(0);
                    targets_func_lines[tem_function_name] = tem_lines;
                }
                else
                {
                    std::unordered_set<u32> tem_lines;
                    tem_lines = targets_func_lines[tem_function_name];
                    u32 tem_u32_line_number = static_cast<u32>(std::stoi(tem_line_number));
                    tem_lines.insert(tem_u32_line_number);
                    targets_func_lines[tem_function_name] = tem_lines;
                }
            }
            else
            {
                if (tem_file_name.empty() && tem_line_number.empty())
                {
                    std::unordered_set<u32> tem_lines;
                    tem_lines.insert(0);
                    targets_func_lines[tem_function_name] = tem_lines;
                }
                else
                {
                    std::unordered_set<u32> tem_lines;
                    u32 tem_u32_line_number = static_cast<u32>(std::stoi(tem_line_number));
                    tem_lines.insert(tem_u32_line_number);
                    targets_func_lines[tem_function_name] = tem_lines;
                }
            }

            // should verify no joint element
            if (tem_use_filter_str.empty())
            {
                targets_func_use_filter2.insert(tem_function_name);
            }
            else if (tem_use_filter_str == "0")
            {
                targets_func_use_filter0.insert(tem_function_name);
            }
            else if (tem_use_filter_str == "1")
            {
                targets_func_use_filter1.insert(tem_function_name);
            }
            else if (tem_use_filter_str == "2")
            {
                targets_func_use_filter2.insert(tem_function_name);
            }
            else if (tem_use_filter_str == "3")
            {
                targets_func_use_filter3.insert(tem_function_name);
            }
            else
            {
                FATAL("unknown : args");
            }

            targets.insert(tem_function_name);
        }
        file.close();
    }
    else
    {
        FATAL("targets file not found!");
    }
    if (targets.size() > func2id.size())
    {
        FATAL("target num more than func num?");
    }
    // verify here
    for (auto element : targets)
    {
        u8 tem_joint_check = 0; // should not appear at targets_func_not_use_filter1 or targets_func_not_use_filter2 or ... more than once
        if (targets_func_use_filter0.count(element) > 0)
        {
            tem_joint_check++;
        }
        if (targets_func_use_filter1.count(element) > 0)
        {
            tem_joint_check++;
        }
        if (targets_func_use_filter2.count(element) > 0)
        {
            tem_joint_check++;
        }
        if (targets_func_use_filter3.count(element) > 0)
        {
            tem_joint_check++;
        }
        if (tem_joint_check > 1)
        {
            FATAL("verify error");
        }
    }

    // funcdist
    Json::Value shortest_dist_map;
    Json::Reader reader;
    std::ifstream dist_map(funcdist_file, std::ifstream::binary);
    if (!reader.parse(dist_map, shortest_dist_map, false))
        PFATAL("Failed loading dist map !");
    for (auto dst_s : shortest_dist_map.getMemberNames())
    {
        std::map<u32, u32> func_shortest;
        Json::Value func_shortest_value = shortest_dist_map[dst_s];
        for (auto src_s : func_shortest_value.getMemberNames())
        {
            func_shortest.insert(std::make_pair(std::stoi(src_s), func_shortest_value[src_s].asInt()));
        }
        func_dist_map.insert(std::make_pair(std::stoi(dst_s), func_shortest));
    }

    // print targets and targets_func_file_line
    outs() << "targets:\n";
    for (auto string : targets)
    {
        outs() << string << "\n";
    }
    outs() << "\n";

    outs() << "targets_func_lines:\n";
    for (auto &entry : targets_func_lines)
    {
        outs() << "func:" << entry.first << ";lines:";
        for (auto &nestedEntry : entry.second)
        {
            outs() << nestedEntry << ";";
        }
        outs() << "\n";
    }
    outs() << "\n";

    // outs() << "done-" << __LINE__ << "\n";

    // extension targets
    std::unordered_set<std::string> tem_targets;
    std::unordered_set<std::string> caller_funcs;
    std::map<std::string, std::vector<std::string>> caller_funcs_file_and_line;
    for (auto &F : M)
    {
        if (F.empty() || isBlacklisted(&F))
        {
            continue;
        }
        // which func call target func
        for (auto &BB : F)
        {
            for (auto &I : BB)
            {
                if (auto call = dyn_cast<CallInst>(&I))
                {
                    if (auto calledFunc = call->getCalledFunction())
                    {
                        if (calledFunc->empty() || calledFunc == NULL || isBlacklisted(calledFunc))
                        {
                            continue;
                        }
                        std::string calledFunc_str = calledFunc->getName().str();
                        auto it1 = std::find(targets.begin(), targets.end(), calledFunc_str);
                        if (it1 != targets.end())
                        {
                            caller_funcs.insert(F.getName().str());
                            StringRef dbg_filename;
                            unsigned int dbg_lineNumber = 0;
                            DebugLoc debugLoc = I.getDebugLoc();
                            if (debugLoc)
                            {
                                DILocation *location = debugLoc.get();
                                dbg_filename = location->getFilename();
                                dbg_lineNumber = location->getLine();
                                std::string combined = std::string(dbg_filename) + ":" + std::to_string(dbg_lineNumber);
                                caller_funcs_file_and_line[F.getName().str()].push_back(combined);
                            }
                        }
                    }
                }
            }
        }
    }

    outs() << "target funcs caller:\n";
    for (auto it : caller_funcs)
    {
        // outs() << it << "\n";
    }

    for (const auto &entry : caller_funcs_file_and_line)
    {
        const std::string &func_name = entry.first;
        const std::vector<std::string> &file_lines = entry.second;
        std::cout << "Function:" << func_name << ";Lines:";
        for (const auto &line : file_lines)
        {
            std::cout << line << ";";
        }
        std::cout << std::endl;
    }
    outs() << "\n";

    // for dominator test
    for (auto &F : M)
    {
        if (F.empty() || isBlacklisted(&F))
        {
            continue;
        }
        auto it = std::find(targets.begin(), targets.end(), F.getName().str());
        if (it != targets.end())
        {
            // DominatorTree DT(F);
            // DT.recalculate(F);
            // BasicBlock *EntryBlock = &F.getEntryBlock();
        }
    }
    // outs() << "done-" << __LINE__ << "\n";

    // get cx_ts
    for (auto &F : M)
    {
        if (F.empty() || isBlacklisted(&F))
        {
            continue;
        }
        auto it = std::find(targets.begin(), targets.end(), F.getName().str());
        if (it != targets.end())
        {
            CX_T cx_t;
            cx_t.F = &F;
            cx_ts.push_back(cx_t);
        }
    }
    // outs() << "done-" << __LINE__ << "\n";

    // deal cx_ts for arg_0,arg0_arg0
    for (auto &cx_t : cx_ts)
    {
        for (auto &BB : *cx_t.F)
        {
            for (auto &I : BB)
            {
                if (auto call = dyn_cast<CallInst>(&I))
                {
                    if (auto calledFunc = call->getCalledFunction())
                    {
                        if (calledFunc->getName().startswith("__asan_report"))
                        {
                            Value *arg0_value = call->getArgOperand(0);
                            if (auto arg0_inst = dyn_cast<Instruction>(arg0_value))
                            {
                                cx_t.arg0.push_back(arg0_inst);
                                Value *arg0_arg0_value = arg0_inst->getOperand(0);
                                if (auto arg0_arg0_inst = dyn_cast<Instruction>(arg0_arg0_value))
                                {
                                    cx_t.arg0_arg0.push_back(arg0_arg0_inst);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // outs() << "done-" << __LINE__ << "\n";

    // get cx_cv
    for (auto &cx_t : cx_ts)
    {
        std::unordered_set<llvm::Instruction *> cx_t_cv_num;         // record cv nums corresponding to this cx_t,no filter
        std::unordered_set<llvm::Instruction *> cx_t_cv_num_filter1; // after filter1 by before debug lines
        std::unordered_set<llvm::Instruction *> cx_t_cv_num_filter2; // after filter2 by reachable to debug lines
        std::unordered_set<llvm::Instruction *> cx_t_cv_num_filter3; // after filter3 by data flow based on filter2
        std::unordered_set<llvm::Instruction *> cx_t_cv_num_final;   // final choosed cv nums
        std::unordered_set<llvm::BasicBlock *> total_bbs_0;          // all bb in this func
        std::unordered_set<llvm::BasicBlock *> total_bbs_1;          // all bb before target site debug line filter1
        std::unordered_set<llvm::BasicBlock *> total_bbs_2;          // all bb reacheable to targetsite filter2
        std::unordered_set<llvm::BasicBlock *> target_site_bbs;      // in this func,bbs respond to target_site debug line
        std::unordered_set<u32> tem_targets_lines = targets_func_lines[cx_t.F->getName().str()];
        if (tem_targets_lines.size() < 1)
        {
            FATAL("no target lines?");
        }
        // deal total_bbs_0,total_bbs_1
        u32 tem_max_line = 0;
        for (auto tem_targets_line : tem_targets_lines)
        {
            if (tem_targets_line > tem_max_line)
            {
                tem_max_line = tem_targets_line;
            }
        }
        for (auto &BB : *(cx_t.F))
        {
            if (tem_targets_lines.count(0) > 0)
            {
                total_bbs_0.insert(&BB);
                total_bbs_1.insert(&BB);
                continue;
            }
            total_bbs_0.insert(&BB);
            u32 tem_bb_line = 0;
            tem_bb_line = get_debug_line_with_BB(&BB);
            if (tem_bb_line <= tem_max_line)
            {
                total_bbs_1.insert(&BB);
            }
        }
        // deal target_site_bbs
        for (auto &BB : *(cx_t.F))
        {
            if (tem_targets_lines.count(0) > 0)
            {
                target_site_bbs.insert(&BB);
                continue;
            }
            for (auto &I : BB)
            {
                u32 tem_bb_line = 0;
                StringRef dbg_filename;
                unsigned int dbg_lineNumber = 0;
                DebugLoc debugLoc = I.getDebugLoc();
                if (debugLoc)
                {
                    DILocation *location = debugLoc.get();
                    dbg_filename = location->getFilename();
                    dbg_lineNumber = location->getLine();
                    tem_bb_line = dbg_lineNumber;
                }
                else
                {
                    u32 tem_bb_line = get_debug_line_with_BB(&BB);
                }
                if (tem_bb_line != 0 && tem_targets_lines.count(tem_bb_line) > 0)
                {
                    target_site_bbs.insert(&BB);
                    break;
                }
            }
        }
        // deal total_bbs_2,find all bb in this func are reachable to any target site bb
        total_bbs_2 = target_site_bbs;
        if (tem_targets_lines.count(0) == 0)
        {
            std::queue<llvm::BasicBlock *> tem_work_list_1; // work list
            for (auto BB : target_site_bbs)
            {
                tem_work_list_1.push(BB);
            }
            while (!tem_work_list_1.empty())
            {
                llvm::BasicBlock *front = tem_work_list_1.front();
                tem_work_list_1.pop();
                for (llvm::BasicBlock *pred : predecessors(front))
                {
                    if (total_bbs_2.count(pred) == 0)
                    {
                        total_bbs_2.insert(pred);
                        tem_work_list_1.push(pred);
                    }
                }
            }
        }

        if (tem_targets_lines.count(0) == 0)
        {

            for (auto &tem_BB : target_site_bbs)
            {

                for (auto &tem_I : *tem_BB)
                {
                    // outs() << tem_I << "\n";
                }
            }
        }

        // deal cx_t_cv_num
        for (auto &BB : *(cx_t.F))
        {
            for (auto &I : BB)
            {
                if (!isa<InvokeInst>(I) && ((dyn_cast<PointerType>(I.getType())) || (dyn_cast<IntegerType>(I.getType()))))
                {
                    if (std::find(cx_t.arg0_arg0.begin(), cx_t.arg0_arg0.end(), &I) != cx_t.arg0_arg0.end())
                    {
                        cx_t_cv_num.insert(&I);
                    }
                    else
                    {
                        for (unsigned i = 0; i < I.getNumOperands(); i++)
                        {
                            Value *operand = I.getOperand(i);
                            if (Instruction *operand_inst = dyn_cast<Instruction>(operand))
                            {
                                if (std::find(cx_t.arg0_arg0.begin(), cx_t.arg0_arg0.end(), operand_inst) != cx_t.arg0_arg0.end())
                                {
                                    // operand_inst in cx_t.arg0_arg0
                                    if (!(std::find(cx_t.arg0.begin(), cx_t.arg0.end(), &I) != cx_t.arg0.end()))
                                    {
                                        // I not in cx_t.arg0
                                        cx_t_cv_num.insert(&I);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // deal cx_t_cv_num_filter1
        if (tem_targets_lines.count(0) > 0)
        {
            cx_t_cv_num_filter1 = cx_t_cv_num;
        }
        else
        {
            for (auto &tem_BB : total_bbs_1)
            {
                for (auto &tem_I : *tem_BB)
                {
                    if (cx_t_cv_num.count(&tem_I) > 0)
                    {
                        cx_t_cv_num_filter1.insert(&tem_I);
                    }
                }
            }
        }
        // deal cx_t_cv_num_filter2
        if (tem_targets_lines.count(0) > 0)
        {
            cx_t_cv_num_filter2 = cx_t_cv_num;
        }
        else
        {
            for (auto &tem_BB : total_bbs_2)
            {
                for (auto &tem_I : *tem_BB)
                {
                    if (cx_t_cv_num.count(&tem_I) > 0)
                    {
                        cx_t_cv_num_filter2.insert(&tem_I);
                    }
                }
            }
        }

        // deal cx_t_cv_num_filter3
        std::unordered_set<llvm::Instruction *> tem_total_insts_1;
        std::unordered_set<llvm::Instruction *> tem_target_insts;
        std::queue<llvm::Instruction *> tem_work_list_2;
        // init tem_total_insts_1
        for (auto &BB : total_bbs_2)
        {
            for (auto &tem_I : *BB)
            {
                tem_total_insts_1.insert(&tem_I);
            }
        }
        // init tem_target_insts,tem_work_list_2
        for (auto &BB : target_site_bbs)
        {
            for (auto &tem_I : (*BB))
            {
                if (cx_t_cv_num_filter2.find(&tem_I) != cx_t_cv_num_filter2.end())
                {
                    // outs() << tem_I << "\n";
                }
                tem_target_insts.insert(&tem_I);
                tem_work_list_2.push(&tem_I);
            }
        }
        if (tem_targets_lines.count(0) > 0)
        {
            ;
        }
        else
        {
            while (!tem_work_list_2.empty())
            {
                outs() << "progress:" << tem_work_list_2.size() << "\r";
                // for update tem_d_target_insts = tem_total_insts_1 - tem_target_insts
                std::unordered_set<llvm::Instruction *> tem_d_target_insts;
                for (auto inst : tem_total_insts_1)
                {
                    if (tem_target_insts.find(inst) == tem_target_insts.end())
                    {
                        tem_d_target_insts.insert(inst);
                    }
                }

                llvm::Instruction *front = tem_work_list_2.front();
                tem_work_list_2.pop();

                // for update tem_op_insts
                std::unordered_set<llvm::Value *> tem_op_insts;
                for (unsigned i = 0, e = front->getNumOperands(); i != e; ++i)
                {
                    llvm::Value *Operand = front->getOperand(i);
                    if (!llvm::isa<llvm::Constant>(Operand))
                    {
                        tem_op_insts.insert(Operand);
                    }
                }
                // is this ok?
                // llvm::Value *inst_value = llvm::dyn_cast<llvm::Value>(front);
                // if (inst_value != nullptr)
                // {
                //   tem_op_insts.insert(inst_value);
                // }

                for (auto inst : tem_d_target_insts)
                {
                    llvm::Value *inst_V = llvm::cast<llvm::Value>(inst);
                    if (tem_op_insts.find(inst_V) != tem_op_insts.end())
                    {
                        if (tem_target_insts.count(inst) == 0)
                        {
                            tem_target_insts.insert(inst);
                            tem_work_list_2.push(inst);
                        }
                    }
                    for (unsigned i = 0, e = inst->getNumOperands(); i != e; ++i)
                    {
                        llvm::Value *Operand = inst->getOperand(i);
                        if (!llvm::isa<llvm::Constant>(Operand) && tem_op_insts.find(Operand) != tem_op_insts.end())
                        {
                            if (tem_target_insts.count(inst) == 0)
                            {
                                tem_target_insts.insert(inst);
                                tem_work_list_2.push(inst);
                            }
                        }
                    }
                }
            }
        }

        for (auto &tem_I : cx_t_cv_num_filter2)
        {
            if (tem_target_insts.find(tem_I) != tem_target_insts.end())
            {
                cx_t_cv_num_filter3.insert(tem_I);
            }
        }
        // deal cx_t_cv_num_final
        if (targets_func_use_filter0.count(cx_t.F->getName().str()) > 0)
        {
            cx_t_cv_num_final = cx_t_cv_num;
        }
        else if (targets_func_use_filter1.count(cx_t.F->getName().str()) > 0)
        {
            cx_t_cv_num_final = cx_t_cv_num_filter1;
        }
        else if (targets_func_use_filter2.count(cx_t.F->getName().str()) > 0)
        {
            cx_t_cv_num_final = cx_t_cv_num_filter2;
        }
        else if (targets_func_use_filter3.count(cx_t.F->getName().str()) > 0)
        {
            cx_t_cv_num_final = cx_t_cv_num_filter3;
        }
        else
        {
            FATAL("fatal at deal cx_t_cv_num_final");
        }
        targets_cvnum_filter[cx_t.F->getName().str()] = cx_t_cv_num_final.size();
        // deal cx_cv
        for (auto &cx_t_cv : cx_t_cv_num_final)
        {
            CX_CV cx_cv;
            cx_cv.instm = cx_t_cv;
            cx_cvs.push_back(cx_cv);
        }
    }

    uint8_t cx_flag1 = 0; // if there are funcs in targets but not in cx_ts or func targets is 0,should print cx_ts
    u32 max_func_targets_nums = 0;
    std::string max_func_targets_func;
    for (auto &cx_t : cx_ts)
    {
        if (targets_cvnum_filter[cx_t.F->getName().str()] > max_func_targets_nums)
        {
            max_func_targets_nums = targets_cvnum_filter[cx_t.F->getName().str()];
            max_func_targets_func = cx_t.F->getName().str();
        }
        if (targets_cvnum_filter[cx_t.F->getName().str()] == 0)
        {
            cx_flag1 = 1;
        }
    }

    // for funcs and cvs nums
    outs() << "these are funcs and cvs:\n";
    for (auto &tem_pair : targets_cvnum_filter)
    {
        outs() << "func:" << tem_pair.first << ";cv nums:" << tem_pair.second << "\n";
    }
    outs() << "\n";
    // for funcs in targets but not in cx_ts
    std::unordered_set<std::string> tem_strings;
    for (auto cx_t : cx_ts)
    {
        std::string tem_string = cx_t.F->getName().str();
        tem_strings.insert(tem_string);
    }
    std::unordered_set<std::string> diff_strings;
    for (auto element : targets)
    {
        if (tem_strings.find(element) == tem_strings.end())
        {
            diff_strings.insert(element);
        }
    }
    // outs() << "these funcs in targets but not not in cx_ts:\n";

    for (auto element : diff_strings)
    {
        // outs() << element << "\n";
        cx_flag1 = 1;
    }
    // outs() << "\n";
    //  for funcs in targets but not in fun2id
    // outs() << "these funcs in targets but not not in fun2id:\n";

    for (auto element : targets)
    {
        auto iter = func2id.find(element);
        if (iter == func2id.end())
        {
            // outs() << element << "\n";
            cx_flag1 = 1;
        }
    }
    // outs() << "\n";
    if (cx_flag1 == 1)
    {
        // outs() << "these are cx_ts in func2id(cx_ts with 0 cv exclude);(not in func2id may be also ok?):\n";

        for (auto cx_t : cx_ts)
        {
            std::string tem_string = cx_t.F->getName().str();
            auto iter = func2id.find(tem_string);
            if (iter != func2id.end() && targets_cvnum_filter[tem_string] != 0)
            {
                // outs() << tem_string << "\n";
            }
        }
        // outs() << "\n";
    }
    // outs() << "these funcs in calldst:\n";

    for (auto element : targets)
    {
        auto iter1 = func2id.find(element);
        if (iter1 != func2id.end())
        {
            u32 id = iter1->second;
            auto iter2 = func_dist_map.find(id);
            if (iter2 != func_dist_map.end())
            {
                // outs() << element << "\n";
            }
        }
    }
    outs() << "\n";

    // deal cx_cv
    for (auto &cx_cv : cx_cvs)
    {
        // asign index
        if (assigned_indexs.size() < (CX_STATE_UNIT * 0.8))
        {
            u16 tem_index;
            do
            {
                tem_index = 1 + AFL_R(CX_STATE_UNIT);
            } while (assigned_indexs.count(tem_index) > 0);
            cx_cv.index = tem_index;
            assigned_indexs.insert(tem_index);
        }
        else
        {
            outs() << "assigned indexs:" << assigned_indexs.size() << "\n";
            outs() << "max func targets:" << max_func_targets_func << ":" << max_func_targets_nums << "\n";
            outs() << "critival variable nums:" << cx_cvs.size() << "\n";
            FATAL("too many assigned indexs");
        }

        // bitwidth and type
        if (cx_cv.instm->getType()->isIntegerTy())
        {
            std::string instm_type = "integer";
            cx_cv.type = instm_type;
            if (auto int_type = dyn_cast<IntegerType>(cx_cv.instm->getType()))
            {
                unsigned int bit_width = int_type->getBitWidth();
                cx_cv.bitwidth = bit_width;
            }
        }
        else if (dyn_cast<PointerType>(cx_cv.instm->getType()))
        {
            std::string instm_type = "pointer";
            cx_cv.type = instm_type;
            cx_cv.bitwidth = 64;
        }
        else
        {
            outs() << *(cx_cv.instm) << "\n";
            FATAL("unexpected type");
        }
    }
    // outs() << "done-" << __LINE__ << "\n";

    // cx-instrument
    // func touched
    for (auto &F : M)
    {
        if (F.empty() || isBlacklisted(&F))
        {
            continue;
        }
        auto iter = func2id.find(F.getName().str());
        if (iter != func2id.end())
        {
            BasicBlock::iterator IP = F.front().getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));
            LoadInst *FuncMapPtr = IRB.CreateLoad(CXMapPtr1);
            FuncMapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *FuncPtrIdx = IRB.CreateGEP(FuncMapPtr, ConstantInt::get(Int32Ty, iter->second));
            LoadInst *Counter = IRB.CreateLoad(FuncPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            IRB.CreateStore(ConstantInt::get(Int8Ty, 1), FuncPtrIdx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        }
    }
    // state
    for (auto &cx_cv : cx_cvs)
    {
        IRBuilder<> builder(C);
        Value *instm_value = dyn_cast<Value>(cx_cv.instm);
        if (isa<PHINode>(instm_value))
        {
            BasicBlock::iterator IP = cx_cv.instm->getParent()->getFirstInsertionPt();
            builder.SetInsertPoint(cx_cv.instm->getParent(), IP);
        }
        else
        {
            builder.SetInsertPoint(cx_cv.instm->getNextNode());
        }

        ConstantInt *Cur_V_Loc = ConstantInt::get(Int32Ty, cx_cv.index);

        // variable no path;(need close the store inst to prev at the end)
        LoadInst *V_Map_Ptr = builder.CreateLoad(CXMapPtr2);
        V_Map_Ptr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Cur_V_Loc_value = llvm::cast<Value>(Cur_V_Loc);
        Value *V_Map_Ptr_Idx = builder.CreateGEP(V_Map_Ptr, Cur_V_Loc_value);
        if (cx_cv.type == "integer")
        {
            if (Value *inst_value = dyn_cast<Value>(cx_cv.instm))
            {
                if (cx_cv.bitwidth < 32)
                {
                    Value *casted = builder.CreateZExt(inst_value, builder.getInt32Ty());
                    builder.CreateStore(casted, V_Map_Ptr_Idx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                }
                else if (cx_cv.bitwidth == 32)
                {
                    builder.CreateStore(inst_value, V_Map_Ptr_Idx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                }
                else if (cx_cv.bitwidth > 32)
                {
                    Value *casted = builder.CreateTrunc(inst_value, Int32Ty, "low32bits");
                    builder.CreateStore(casted, V_Map_Ptr_Idx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                }
            }
            else
            {
                FATAL("dyn_cast failed");
            }
        }
        else if (cx_cv.type == "pointer")
        {
            if (Value *inst_value = dyn_cast<Value>(cx_cv.instm))
            {
                Value *ptr2int = builder.CreatePtrToInt(inst_value, Int64Ty);
                Value *casted = builder.CreateTrunc(ptr2int, Int32Ty, "low32bits");
                builder.CreateStore(casted, V_Map_Ptr_Idx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            }
            else
            {
                FATAL("dyn_cast failed");
            }
        }
        else
        {
            outs() << *(cx_cv.instm) << "\n";
            FATAL("unexpected type");
        }
    }
    // outs() << "done-" << __LINE__ << "\n";

    /* Instrument all the things! */
    int inst_blocks = 0;
    for (auto &F : M)
        for (auto &BB : F)
        {
            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));
            if (AFL_R(100) >= inst_ratio)
                continue;
            /* Make up cur_loc */
            unsigned int cur_loc = AFL_R(MAP_SIZE);
            ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);
            /* Load prev_loc */
            LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
            PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());
            /* Load SHM pointer */
            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *MapPtrIdx =
                IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));
            /* Update bitmap */
            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(Incr, MapPtrIdx)
                ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            /* Set prev_loc to cur_loc >> 1 */
            StoreInst *Store =
                IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
            Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            /* set afl_cur_loc in debuging info for further analysis */
            auto meta_loc = MDNode::get(C, ConstantAsMetadata::get(CurLoc));
            for (Instruction &instr : BB.getInstList())
            {
                if (!is_llvm_dbg_intrinsic(instr))
                {
                    // this only insert the meta for the first non-llvm dbg
                    instr.setMetadata("afl_cur_loc", meta_loc);
                    break;
                }
            }

            inst_blocks++;
        }

    /* Say something nice. */
    if (!be_quiet)
    {
        if (!inst_blocks)
        {
            WARNF("No instrumentation targets found.");
        }
        else
        {
            outs() << "Instrumented:" << inst_blocks << ".locations\n";
        }

        // cx-outs
        if (targets_cvnum_filter.size() != cx_ts.size())
        {
            outs() << "error at line:" << __LINE__ << "\n";
            FATAL("not equal");
        }

        outs() << "func_nums:" << func_nums << "\n";
        outs() << "bb_nums:" << bb_nums << "\n";
        outs() << "inst_nums:" << inst_nums << "\n";
        outs() << "target_nums:" << targets.size() << "\n";
        outs() << "cx_t_nums:" << cx_ts.size() << "\n";
        outs() << "critical variable nums:" << cx_cvs.size() << "\n";
    }
    // outs() << "done-" << __LINE__ << "\n";

    return true;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM)
{

    PM.add(new AFLCoverage());
}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
