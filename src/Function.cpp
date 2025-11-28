/** *************************************************************/
// @Name: Function.cpp
// @Function: Load 5D rules from file, split into IP and Port tables
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-11-27
/************************************************************* */

#include <bits/stdc++.h>
#include <iostream>

#include "Loader.hpp"
#include "Function.hpp"

using namespace std;


void merge_same_ip_entry(
    const std::vector<IPRule>& ip_table,
    std::vector<MergrdR>& merged_ip_table
) {
    merged_ip_table.clear();

    std::map<
        std::tuple<uint32_t,uint32_t,uint32_t,uint32_t,uint8_t>,
        size_t
    > key_to_index;

    // Step 1: 合并相同的 Src_IP, Dst_IP, Protocol 的规则
    for (size_t i = 0; i < ip_table.size(); ++i) {
        const auto &rule = ip_table[i];
        auto key = std::make_tuple(
            rule.src_ip_lo, rule.src_ip_hi,
            rule.dst_ip_lo, rule.dst_ip_hi,
            rule.proto
        );

        auto it = key_to_index.find(key);
        if (it == key_to_index.end()) {
            // 创建新的 MergrdR 规则
            MergrdR new_rule;
            new_rule.Src_IP_lo = rule.src_ip_lo;
            new_rule.Src_IP_hi = rule.src_ip_hi;
            new_rule.Dst_IP_lo = rule.dst_ip_lo;
            new_rule.Dst_IP_hi = rule.dst_ip_hi;
            new_rule.Proto = rule.proto;
            new_rule.LRMID = 0;  // 稍后分配
            new_rule.merged_R.clear();
            new_rule.merged_R.push_back(i);  // 记录原始规则索引

            merged_ip_table.push_back(new_rule);
            key_to_index[key] = merged_ip_table.size() - 1;
        } else {
            // 添加到已存在的合并规则中
            size_t idx = it->second;
            merged_ip_table[idx].merged_R.push_back(i);
        }
    }

    // Step 2: 按顺序分配 LRMID（从 0 开始）
    for (size_t i = 0; i < merged_ip_table.size(); ++i) {
        merged_ip_table[i].LRMID = static_cast<uint32_t>(i);
    }

    std::cout << "[merge_same_ip_entry] Original IP rules = " << ip_table.size()
              << ", merged = " << merged_ip_table.size() << std::endl;
}



void laod_and_create_IP_table(
    std::vector<IPRule>& ip_table,
    std::vector<PortRule>& port_table, 
    std::vector<MergrdR>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem>& mateifno
) {
    // 1) merge identical IP entries
    merge_same_ip_entry(ip_table, merged_ip_table);

    
}





#ifdef DEMO_LOADER_MAIN
int main(int argc, char **argv) {
    return 0;
}
#endif /* COMPILE_AS_LIB */