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


void Create_metainfo(
    const std::vector<MergrdR>& merged_ip_table,
    const std::vector<PortRule>& port_table,
    std::map<uint32_t, std::vector<MergedItem>>& metainfo
) {
    metainfo.clear();

    // 遍历每个合并后的 IP 规则
    for (const auto& merged_rule : merged_ip_table) {
        // 1) 提取 LRMID
        uint32_t lrmid = merged_rule.LRMID;
        
        // 为这个 LRMID 创建 MergedItem 向量
        std::vector<MergedItem> items;
        
        // 2) 遍历 merged_R 中的每个原始规则索引
        for (size_t orig_idx : merged_rule.merged_R) {
            // 检查索引是否有效
            if (orig_idx >= port_table.size()) {
                std::cerr << "[WARN] Invalid index " << orig_idx 
                          << " in merged_R (port_table size: " << port_table.size() << ")" << std::endl;
                continue;
            }
            
            // 3) 从 port_table 中获取对应的端口规则
            const auto& port_rule = port_table[orig_idx];
            
            // 4) 创建 MergedItem 并填充数据
            MergedItem item;
            item.LRMID = lrmid;  // 赋予 LRMID
            item.Src_Port_lo = port_rule.src_port_lo;
            item.Src_Port_hi = port_rule.src_port_hi;
            item.Dst_Port_lo = port_rule.dst_port_lo;
            item.Dst_Port_hi = port_rule.dst_port_hi;
            item.action = port_rule.action;
            
            items.push_back(item);
        }
        
        // 将这个 LRMID 对应的所有端口项添加到 metainfo
        metainfo[lrmid] = items;
    }

    std::cout << "[Create_metainfo] Created metainfo for " << metainfo.size() 
              << " LRMIDs (total port entries: ";
    size_t total_entries = 0;
    for (const auto& pair : metainfo) {
        total_entries += pair.second.size();
    }
    std::cout << total_entries << ")" << std::endl;
}


void output_metainfo(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo,
    const std::string& output_file
) {
    std::ofstream ofs(output_file);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Failed to open output file: " << output_file << std::endl;
        return;
    }

    // 写入表头
    ofs << "LRM-ID\tSrc_lo\tSrc_hi\tDst_lo\tDst_hi\tAction\n";

    // 遍历每个 LRMID
    for (const auto& entry : metainfo) {
        uint32_t lrmid = entry.first;
        const auto& items = entry.second;

        // 写入该 LRMID 下的所有端口项
        for (const auto& item : items) {
            ofs << lrmid << "\t"
                << item.Src_Port_lo << "\t"
                << item.Src_Port_hi << "\t"
                << item.Dst_Port_lo << "\t"
                << item.Dst_Port_hi << "\t"
                << item.action << "\n";
        }
    }

    ofs.close();
    
    // 统计信息
    size_t total_entries = 0;
    for (const auto& entry : metainfo) {
        total_entries += entry.second.size();
    }
    std::cout << "[output_metainfo] Wrote metainfo to: " << output_file 
              << " (" << total_entries << " entries)" << std::endl;
}

void load_and_create_IP_table(
    std::vector<IPRule>& ip_table,
    std::vector<PortRule>& port_table, 
    std::vector<MergrdR>& merged_ip_table,
    std::map<uint32_t, std::vector<MergedItem>>& metainfo
) {
    // 1) merge identical IP entries
    merge_same_ip_entry(ip_table, merged_ip_table);

    // 2) create metainfo for port rules
    Create_metainfo(merged_ip_table, port_table, metainfo);

    // 3) output metainfo to file
    output_metainfo(metainfo, "output/metainfo.txt");
}


std::map<uint32_t, std::vector<PortBlock>> Optimal_for_Port_Table(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo
) {
    std::map<uint32_t, std::vector<PortBlock>> optimal_metainfo;
    optimal_metainfo.clear();
    
    // 遍历所有 LRMID 及其对应的 MergedItem 列表
    for (const auto& entry : metainfo) {
        uint32_t lrmid = entry.first;
        const auto& items = entry.second;
        
        std::vector<PortBlock> port_blocks;
        
        // 处理每个 MergedItem
        for (const auto& item : items) {
            PortBlock block;
            block.LRMID = lrmid;
            block.action = item.action;
            block.REV_Flag = false;  // 默认为 false
            
            // 处理源端口范围
            if (item.Src_Port_lo == 0 && item.Src_Port_hi == 65535) {
                // 规则1: 0-65535 变为 0
                block.Src_Port_lo = 0;
                block.Src_Port_hi = 0;
            } else if (item.Src_Port_lo == 1024 && item.Src_Port_hi == 65535) {
                // 规则2: 1024-65535 变为 0-1023，并设置 REV_Flag
                block.Src_Port_lo = 0;
                block.Src_Port_hi = 1023;
                block.REV_Flag = true;
            } else {
                // 保持原端口范围
                block.Src_Port_lo = item.Src_Port_lo;
                block.Src_Port_hi = item.Src_Port_hi;
            }
            
            // 处理目标端口范围
            if (item.Dst_Port_lo == 0 && item.Dst_Port_hi == 65535) {
                // 规则1: 0-65535 变为 0
                block.Dst_Port_lo = 0;
                block.Dst_Port_hi = 0;
            } else if (item.Dst_Port_lo == 1024 && item.Dst_Port_hi == 65535) {
                // 规则2: 1024-65535 变为 0-1023，并设置 REV_Flag
                block.Dst_Port_lo = 0;
                block.Dst_Port_hi = 1023;
                block.REV_Flag = true;
            } else {
                // 保持原端口范围
                block.Dst_Port_lo = item.Dst_Port_lo;
                block.Dst_Port_hi = item.Dst_Port_hi;
            }
            
            port_blocks.push_back(block);
        }
        
        optimal_metainfo[lrmid] = port_blocks;
    }
    
    return optimal_metainfo;
}

void Create_Port_Block_Subset(
    const std::map<uint32_t, std::vector<PortBlock>>& optimal_metainfo,
    std::vector<PortBlock>& PortBlock_Subset
) {
    PortBlock_Subset.clear();

    // 遍历 optimal_metainfo 中的所有 LRMID 和 PortBlock
    for (const auto& entry : optimal_metainfo) {
        const auto& port_blocks = entry.second;
        
        for (const auto& block : port_blocks) {
            // 处理特殊情况：端口为 0 表示全端口（0-65535）
            bool src_is_any = (block.Src_Port_lo == 0 && block.Src_Port_hi == 0);
            bool dst_is_any = (block.Dst_Port_lo == 0 && block.Dst_Port_hi == 0);
            
            // 如果源端口和目标端口都是全端口，保存原规则
            if (src_is_any && dst_is_any) {
                PortBlock_Subset.push_back(block);
                continue;
            }
            
            // 计算源端口和目标端口的分块范围
            std::vector<std::pair<uint16_t, uint16_t>> src_blocks;
            std::vector<std::pair<uint16_t, uint16_t>> dst_blocks;
            
            // 分块源端口范围
            if (src_is_any) {
                // 全端口不分块，直接使用 0
                src_blocks.push_back({0, 0});
            } else {
                uint16_t src_start = block.Src_Port_lo;
                uint16_t src_end = block.Src_Port_hi;
                
                while (src_start <= src_end) {
                    uint16_t block_start = src_start;
                    uint16_t block_end;
                    
                    // 计算当前 32 的倍数区间
                    uint16_t sp = src_start / 32;
                    uint16_t next_boundary = (sp + 1) * 32;
                    
                    if (next_boundary > src_end + 1) {
                        // 当前区间包含结束端口
                        block_end = src_end;
                    } else {
                        // 延伸到下一个 32 的边界
                        block_end = next_boundary - 1;
                    }
                    
                    src_blocks.push_back({block_start, block_end});
                    
                    // 移动到下一个区间
                    if (block_end == src_end) break;
                    src_start = block_end + 1;
                }
            }
            
            // 分块目标端口范围
            if (dst_is_any) {
                // 全端口不分块，直接使用 0
                dst_blocks.push_back({0, 0});
            } else {
                uint16_t dst_start = block.Dst_Port_lo;
                uint16_t dst_end = block.Dst_Port_hi;
                
                while (dst_start <= dst_end) {
                    uint16_t block_start = dst_start;
                    uint16_t block_end;
                    
                    // 计算当前 32 的倍数区间
                    uint16_t sp = dst_start / 32;
                    uint16_t next_boundary = (sp + 1) * 32;
                    
                    if (next_boundary > dst_end + 1) {
                        // 当前区间包含结束端口
                        block_end = dst_end;
                    } else {
                        // 延伸到下一个 32 的边界
                        block_end = next_boundary - 1;
                    }
                    
                    dst_blocks.push_back({block_start, block_end});
                    
                    // 移动到下一个区间
                    if (block_end == dst_end) break;
                    dst_start = block_end + 1;
                }
            }
            
            // 生成所有源端口和目标端口的组合
            for (const auto& src_range : src_blocks) {
                for (const auto& dst_range : dst_blocks) {
                    PortBlock new_block;
                    new_block.LRMID = block.LRMID;
                    new_block.Src_Port_lo = src_range.first;
                    new_block.Src_Port_hi = src_range.second;
                    new_block.Dst_Port_lo = dst_range.first;
                    new_block.Dst_Port_hi = dst_range.second;
                    new_block.REV_Flag = block.REV_Flag;
                    new_block.action = block.action;
                    
                    PortBlock_Subset.push_back(new_block);
                }
            }
        }
    }
    
    std::cout << "[Create_Port_Block_Subset] Created " << PortBlock_Subset.size() 
              << " port block subsets (split by 32-port intervals)" << std::endl;
}


std::vector<LRME_Entry> Caculate_LRME_Enries(
    const std::vector<PortBlock>& PortBlock_Subset
) {
    std::vector<LRME_Entry> LRME_Entries;
    LRME_Entries.clear();

    // 遍历每个 PortBlock，生成对应的 LRME_Entry
    for (const auto& block : PortBlock_Subset) {
        LRME_Entry entry;
        entry.LRMID = block.LRMID;

        // 处理源端口
        if (block.Src_Port_lo == 0 && block.Src_Port_hi == 0) {
            // ANY port (0-65535)：使用特殊标记
            entry.SrcPAI = 0xFFFF;  // 特殊值表示 ANY
            entry.Src_32bitmap = 0;  // 用 0 表示 null/ANY，不设置具体位
        } else {
            // 计算 PAI：端口所在的 32 区间编号
            // 因为已经按 32 分块，lo 和 hi 在同一个区间
            entry.SrcPAI = static_cast<uint16_t>(block.Src_Port_lo / 32);
            
            // 计算 32-bit bitmap
            // block_base 是当前 32 区间的起始端口
            uint32_t block_base = entry.SrcPAI * 32;
            entry.Src_32bitmap = 0;
            
            // 计算需要设置的位范围（端口 % 32）
            uint32_t start_bit = block.Src_Port_lo - block_base;  // lo % 32
            uint32_t end_bit = block.Src_Port_hi - block_base;    // hi % 32
            
            // 设置 bitmap 的对应位
            for (uint32_t bit = start_bit; bit <= end_bit; ++bit) {
                entry.Src_32bitmap |= (1U << bit);
            }
        }

        // 处理目标端口（逻辑同源端口）
        if (block.Dst_Port_lo == 0 && block.Dst_Port_hi == 0) {
            // ANY port (0-65535)：使用特殊标记
            entry.DstPAI = 0xFFFF;  // 特殊值表示 ANY
            entry.Dst_32bitmap = 0;  // 用 0 表示 null/ANY
        } else {
            // 计算 PAI：端口所在的 32 区间编号
            entry.DstPAI = static_cast<uint16_t>(block.Dst_Port_lo / 32);
            
            // 计算 32-bit bitmap
            uint32_t block_base = entry.DstPAI * 32;
            entry.Dst_32bitmap = 0;
            
            // 计算需要设置的位范围（端口 % 32）
            uint32_t start_bit = block.Dst_Port_lo - block_base;  // lo % 32
            uint32_t end_bit = block.Dst_Port_hi - block_base;    // hi % 32
            
            // 设置 bitmap 的对应位
            for (uint32_t bit = start_bit; bit <= end_bit; ++bit) {
                entry.Dst_32bitmap |= (1U << bit);
            }
        }

        LRME_Entries.push_back(entry);
    }

    std::cout << "[Caculate_LRME_Enries] Created " << LRME_Entries.size() 
              << " LRME entries from PortBlock subset" << std::endl;

    return LRME_Entries;
}


void Caculate_LRME_for_Port_Table(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo) 
{
    // 1) Two optimal propose in paper; For ANY port and ports greater than 1024
    auto optimal_metainfo = Optimal_for_Port_Table(metainfo);

    // 2) Create PortBlock subset
    std::vector<PortBlock> PortBlock;
    Create_Port_Block_Subset(optimal_metainfo, PortBlock);

    // 3) Create LRME entries for PortBlock subset
    auto PortBlock_LRME = Caculate_LRME_Enries(PortBlock);
}



#ifdef DEMO_LOADER_MAIN
int main(int argc, char **argv) {
    return 0;
}
#endif /* COMPILE_AS_LIB */