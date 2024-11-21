//time to reach, partial code for refer.
//instrument for targets, if reached, store 1 to corresponding position
//Cancel the instrumentation of afl

//store 1 operation
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
std::string targets_file;
targets_file = FilenameStr + "targets.txt";
std::vector<std::string> targets_vec;
std::ifstream file(targets_file);
if (file.is_open())
{
    std::string line;
    while (std::getline(file, line))
    {
        targets_vec.push_back(line);
    }
}
else
{
    FATAL("targets file not found!");
}
outs() << "print here+++++\n";
for (const auto &target : targets_vec)
{
    std::cout << target << std::endl;
}


//  TTR
u32 cx_ttr_instrumented_bb = 0;
std::unordered_set<BasicBlock *> instrumented_bb;
std::unordered_set<std::string> test1;
for (auto &F : M)
{
    for (auto &BB : F)
    {
        for (auto &I : BB)
        {
            if (instrumented_bb.find(&BB) == instrumented_bb.end())
            {
                StringRef dbg_filename;
                unsigned int dbg_lineNumber = 0;
                DebugLoc debugLoc = I.getDebugLoc();
                if (debugLoc)
                {
                    DILocation *location = debugLoc.get();
                    dbg_filename = location->getFilename();
                    dbg_lineNumber = location->getLine();
                }
                u32 tem_idx = 0;
                for (auto &target : targets_vec)
                {
                    std::size_t first_colon = target.find(':');
                    std::size_t second_colon = target.find(':', first_colon + 1);
                    std::string file_name = target.substr(first_colon + 1, second_colon - first_colon - 1);
                    unsigned int line_number = static_cast<unsigned int>(std::stoi(target.substr(second_colon + 1)));
                    if (dbg_lineNumber == line_number)
                    {
                        if (test1.find(dbg_filename.str()) == test1.end())
                        {
                            outs() << dbg_filename.str() << "\n";
                            test1.insert(dbg_filename.str());
                        }
                    }
                    if (dbg_filename == file_name && dbg_lineNumber == line_number)
                    {
                        outs() << dbg_filename << ":" << dbg_lineNumber << ",128+" << tem_idx << "\n";
                        instrumented_bb.insert(&BB);
                        BasicBlock::iterator IP = BB.getFirstInsertionPt();
                        IRBuilder<> IRB(&(*IP));
                        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, 128 + tem_idx);
                        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
                        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                        Value *MapPtrIdx = IRB.CreateGEP(MapPtr, CurLoc);
                        IRB.CreateStore(ConstantInt::get(Int32Ty, 1), MapPtrIdx)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                        cx_ttr_instrumented_bb++;
                        break;
                    }
                    tem_idx++;
                }
            }
        }
    }
}
outs() << "instrumented bb:" << cx_ttr_instrumented_bb << "\n";

//run fuzz to record first queue reach target. And Reaching the target site for the first time can be a crash seed that requires special treatment.
//get targets
char targets_path[1024];
const char *last_slash = strrchr(argv[optind], '/');
if (last_slash != NULL)
{
    size_t path_length = last_slash - argv[optind];
    strncpy(targets_path, argv[optind], path_length);
    targets_path[path_length] = '\0';
    strcat(targets_path, "/targets.txt");
    printf("targets Path: %s\n", targets_path);
}
else
{
    FATAL("");
}

FILE *file = fopen(targets_path, "r");
if (file == NULL)
{
    FATAL("");
}
unsigned int line_count = 0;
char ch;
while ((ch = fgetc(file)) != EOF)
{
    if (ch == '\n')
    {
        line_count++;
    }
}
fclose(file);
printf("Number of lines: %d\n", line_count);

uint32_t targets_ttr[line_count];
for (unsigned int i = 0; i < line_count; i++)
{
    targets_ttr[i] = UINT32_MAX;
}
printf("Initialized targets_tte with UINT32_MAX:\n");
for (unsigned int i = 0; i < line_count; i++)
{
    printf("targets_tte[%u] = %u\n", i, targets_ttr[i]);
}

while (q)
{
uint32_t id_value = 0;
const char *id_prefix = "id:";
char *id_start = strstr((const char *)q->fname, id_prefix);
if (id_start != NULL)
{
    id_start += strlen(id_prefix);
    char *id_end = strchr(id_start, ',');
    if (id_end != NULL)
    {
        size_t length = id_end - id_start;
        char id_str[24];
        strncpy(id_str, id_start, length);
        id_str[length] = '\0';
        id_value = (uint32_t)strtol(id_str, NULL, 10);
        // printf("Converted ID to uint32_t: %u\n", id_value);
    }
    else
    {
        FATAL("");
    }
}
else
{
    FATAL("");
}

//run queue

for (uint32_t cxi = 0; cxi < line_count; cxi++)
{
    if (*(trace_bits + 128 + cxi))
    {
        if (id_value < targets_ttr[cxi])
        {
            targets_ttr[cxi] = id_value;
        }
    }
}
q = q->next;
}

printf(" targets_tte:\n");
for (unsigned int i = 0; i < line_count; i++)
{
    printf("targets_tte[%u] = %u\n", i, targets_ttr[i]);
}


