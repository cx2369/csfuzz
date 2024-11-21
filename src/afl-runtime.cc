#include "lib/config.h"
#include "lib/types.h"
#include "lib/debug.h"

#include <algorithm>
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>
#include <map>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unordered_set>

#define UNREACHABLE_DIST 0xFFFFFFFF

extern "C"
{
    std::map<std::string, u32> func2id; // func and id
    std::unordered_set<std::string> targets;
    std::unordered_set<u32> targets_id;
    std::map<u32, std::map<u32, u32>> func_dist_map;
    std::vector<u32> seed_length;

    u32 *best_perf;

    int cx_test()
    {
        return 1;
    }

    u32 get_pos_length(u32 pos)
    {
        std::sort(seed_length.begin(), seed_length.end());
        return seed_length[pos];
    }
    void add_to_vector(u32 length)
    {
        seed_length.push_back(length);
    }

    void cx_deal_files(char cx_targets[], char cx_calldst[], char cx_funcid[])
    {
        // targets
        std::string targets_file(cx_targets);
        std::ifstream file1(targets_file);
        if (file1.is_open())
        {
            std::string line;
            while (std::getline(file1, line))
            {
                targets.insert(line);
            }
            file1.close();
        }
        else
        {
            FATAL("targets file not found!");
        }

        // funcid
        std::string funcid_file(cx_funcid);
        std::ifstream file2(funcid_file);
        if (file2.is_open())
        {
            std::string line;
            while (getline(file2, line))
            {
                std::size_t dis_pos = line.find(",");
                std::string fname = line.substr(dis_pos + 1, line.length() - dis_pos);
                std::string idx_str = line.substr(0, dis_pos);
                func2id.emplace(fname, atoi(idx_str.c_str()));
            }
            file2.close();
        }
        else
        {
            FATAL("function id file not found!");
        }
        if (func2id.size() > CX_FUNC_UNIT)
        {
            FATAL("func size too lagrge");
        }
        if (targets.size() > func2id.size())
        {
            FATAL("target num more than func num?");
        }

        // targets_id
        for (auto target : targets)
        {
            if (func2id.count(target) > 0)
            {
                u32 funcid = func2id[target];
                targets_id.insert(funcid);
            }
            else
            {
                std::cout << "target:" << target << std::endl;
                FATAL("target not in fun2id");
            }
        }

        // calldst
        Json::Value shortest_dist_map;
        Json::Reader reader;
        std::string myString(cx_calldst);
        std::ifstream dist_map(myString, std::ifstream::binary);

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
    }

    int cx_uptate_favored(struct queue_entry **top_rated_func, struct queue_entry *queue)
    {
        int ret = 0;

        if (!best_perf)
        {
            best_perf = (u32 *)malloc(sizeof(u32) * CX_FUNC_BYTE * CX_DIST_Y);
            memset(best_perf, 255, CX_FUNC_BYTE * CX_DIST_Y * sizeof(u32));
        }

        // clear top_rated_func
        for (auto i : targets_id)
        {
            for (u32 y = 0; y < CX_DIST_Y; y++)
            {
                top_rated_func[i * CX_DIST_Y + y] = NULL;
            }
        }

        for (auto i : targets_id)
        {
            for (struct queue_entry *q = queue; q; q = q->next)
            {

                if (q->was_fuzzed || !q->favored)
                {
                    continue;
                }
                int flag = 0;

                u32 fexp_score = 0, shortest_dist = UNREACHABLE_DIST;
                for (auto iter = func_dist_map[i].begin(); iter != func_dist_map[i].end(); iter++)
                {
                    if (q->trace_func[iter->first])
                    {
                        if (iter->second < shortest_dist)
                        {
                            shortest_dist = iter->second;
                        }
                    }
                }
                if (shortest_dist != UNREACHABLE_DIST)
                {
                    fexp_score = shortest_dist * 100;
                }
                if (fexp_score)
                {
                    ret = 1;

                    for (u32 y = 0; y < CX_DIST_Y; y++)
                    {
                        if (!top_rated_func[i * CX_DIST_Y + y])
                        {
                            top_rated_func[i * CX_DIST_Y + y] = q;
                            best_perf[i * CX_DIST_Y + y] = fexp_score;
                            flag = 1; // There is an empty space, insert q
                            break;
                        }
                    }

                    if (!flag)
                    {
                        // There is no empty space, if q has better distance , insert q
                        u32 max_dist = 0;
                        for (u32 y = 0; y < CX_DIST_Y; y++)
                        {
                            if (best_perf[i * CX_DIST_Y + y] > max_dist)
                            {
                                max_dist = best_perf[i * CX_DIST_Y + y];
                            }
                        }
                        u32 worst_queue_id = CX_DIST_Y;
                        u64 worst_score = 0;
                        for (u32 y = 0; y < CX_DIST_Y; y++)
                        {
                            if (best_perf[i * CX_DIST_Y + y] == max_dist)
                            {
                                if (top_rated_func[i * CX_DIST_Y + y]->exec_us * top_rated_func[i * CX_DIST_Y + y]->len > worst_score)
                                {
                                    worst_score = top_rated_func[i * CX_DIST_Y + y]->exec_us * top_rated_func[i * CX_DIST_Y + y]->len;
                                    worst_queue_id = y;
                                }
                            }
                        }

                        for (u32 y = 0; y < CX_DIST_Y; y++)
                        {
                            if (y == worst_queue_id)
                            {
                                if (fexp_score < best_perf[i * CX_DIST_Y + y])
                                {
                                    top_rated_func[i * CX_DIST_Y + y] = q;
                                    best_perf[i * CX_DIST_Y + y] = fexp_score;
                                    break;
                                }
                                if (fexp_score == best_perf[i * CX_DIST_Y + y] && q->exec_us * q->len < top_rated_func[i * CX_DIST_Y + y]->exec_us * top_rated_func[i * CX_DIST_Y + y]->len)
                                {
                                    top_rated_func[i * CX_DIST_Y + y] = q;
                                    best_perf[i * CX_DIST_Y + y] = fexp_score;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        return ret;
    }
}
