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

    // 写入表头（对齐格式）
    ofs << std::left 
        << std::setw(10) << "LRM-ID"
        << std::setw(10) << "Src_lo"
        << std::setw(10) << "Src_hi"
        << std::setw(10) << "Dst_lo"
        << std::setw(10) << "Dst_hi"
        << std::setw(10) << "Action"
        << "\n";

    // 遍历每个 LRMID
    for (const auto& entry : metainfo) {
        uint32_t lrmid = entry.first;
        const auto& items = entry.second;

        // 写入该 LRMID 下的所有端口项
        for (const auto& item : items) {
            ofs << std::left
                << std::setw(10) << lrmid
                << std::setw(10) << item.Src_Port_lo
                << std::setw(10) << item.Src_Port_hi
                << std::setw(10) << item.Dst_Port_lo
                << std::setw(10) << item.Dst_Port_hi
                << std::setw(10) << item.action
                << "\n";
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
            block.ANY_Flag = 0;      // 默认为 0（不包含 ANY）
            
            bool src_is_any = false;
            bool dst_is_any = false;
            
            // 处理源端口范围
            if (item.Src_Port_lo == 0 && item.Src_Port_hi == 65535) {
                // 规则1: 0-65535 变为 0
                block.Src_Port_lo = 0;
                block.Src_Port_hi = 0;
                src_is_any = true;
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
                dst_is_any = true;
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
            
            // 设置 ANY_Flag
            // 0: 不包含 ANY
            // 1: 仅源端口是 ANY
            // 2: 仅目标端口是 ANY
            // 3: 源端口和目标端口都是 ANY
            if (src_is_any && dst_is_any) {
                block.ANY_Flag = 3;
            } else if (src_is_any) {
                block.ANY_Flag = 1;
            } else if (dst_is_any) {
                block.ANY_Flag = 2;
            } else {
                block.ANY_Flag = 0;
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
                    new_block.ANY_Flag = block.ANY_Flag;  // 继承原 block 的 ANY_Flag
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
        entry.ANY_Flag = block.ANY_Flag;  // 继承 PortBlock 的 ANY_Flag

        // 处理源端口
        if (block.Src_Port_lo == 0 && block.Src_Port_hi == 0) {
            // ANY port (0-65535)：使用特殊标记
            entry.SrcPAI = 0xFFFF;  // 特殊值表示 ANY
            entry.Src_32bitmap.reset();  // 全部置为 0，表示 null/ANY
        } else {
            // 计算 PAI：端口所在的 32 区间编号
            entry.SrcPAI = static_cast<uint16_t>(block.Src_Port_lo / 32);
            
            // 计算 32-bit bitmap
            uint32_t block_base = entry.SrcPAI * 32;
            entry.Src_32bitmap.reset();  // 先清空所有位
            
            // 计算需要设置的位范围（端口 % 32）
            uint32_t start_bit = block.Src_Port_lo - block_base;  // lo % 32
            uint32_t end_bit = block.Src_Port_hi - block_base;    // hi % 32
            
            // 设置 bitmap 的对应位
            for (uint32_t bit = start_bit; bit <= end_bit; ++bit) {
                entry.Src_32bitmap.set(bit);
            }
        }

        // 处理目标端口（逻辑同源端口）
        if (block.Dst_Port_lo == 0 && block.Dst_Port_hi == 0) {
            // ANY port (0-65535)：使用特殊标记
            entry.DstPAI = 0xFFFF;  // 特殊值表示 ANY
            entry.Dst_32bitmap.reset();  // 全部置为 0，表示 null/ANY
        } else {
            // 计算 PAI：端口所在的 32 区间编号
            entry.DstPAI = static_cast<uint16_t>(block.Dst_Port_lo / 32);
            
            // 计算 32-bit bitmap
            uint32_t block_base = entry.DstPAI * 32;
            entry.Dst_32bitmap.reset();  // 先清空所有位
            
            // 计算需要设置的位范围（端口 % 32）
            uint32_t start_bit = block.Dst_Port_lo - block_base;  // lo % 32
            uint32_t end_bit = block.Dst_Port_hi - block_base;    // hi % 32
            
            // 设置 bitmap 的对应位
            for (uint32_t bit = start_bit; bit <= end_bit; ++bit) {
                entry.Dst_32bitmap.set(bit);
            }
        }

        LRME_Entries.push_back(entry);
    }

    std::cout << "[Caculate_LRME_Enries] Created " << LRME_Entries.size() 
              << " LRME entries from PortBlock subset (before deduplication)" << std::endl;

    // 去重：合并完全相同的表项
    // 使用 map 来按 LRMID 分组，然后在每个组内去重
    std::map<uint32_t, std::vector<LRME_Entry>> grouped_by_lrmid;
    
    for (const auto& entry : LRME_Entries) {
        grouped_by_lrmid[entry.LRMID].push_back(entry);
    }
    
    // 清空原始列表，准备填入去重后的结果
    LRME_Entries.clear();
    
    size_t duplicates_removed = 0;
    
    // 对每个 LRMID 组内的表项进行去重
    for (auto& group_pair : grouped_by_lrmid) {
        auto& entries = group_pair.second;
        std::vector<LRME_Entry> unique_entries;
        
        for (const auto& entry : entries) {
            // 检查是否已存在相同的表项
            bool is_duplicate = false;
            
            for (const auto& existing : unique_entries) {
                // 比较所有关键字段
                if (existing.LRMID == entry.LRMID &&
                    existing.ANY_Flag == entry.ANY_Flag &&
                    existing.SrcPAI == entry.SrcPAI &&
                    existing.DstPAI == entry.DstPAI &&
                    existing.Src_32bitmap == entry.Src_32bitmap &&
                    existing.Dst_32bitmap == entry.Dst_32bitmap) {
                    is_duplicate = true;
                    duplicates_removed++;
                    break;
                }
            }
            
            // 如果不是重复的，添加到唯一列表
            if (!is_duplicate) {
                unique_entries.push_back(entry);
            }
        }
        
        // 将去重后的表项添加回结果列表
        for (const auto& entry : unique_entries) {
            LRME_Entries.push_back(entry);
        }
    }

    std::cout << "[Caculate_LRME_Enries] After deduplication: " << LRME_Entries.size() 
              << " unique entries (removed " << duplicates_removed << " duplicates)" << std::endl;

    return LRME_Entries;
}

void output_LRME_entries(
    const std::vector<LRME_Entry>& LRME_Entries,
    const std::string& output_file
) {
    std::ofstream ofs(output_file);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Failed to open output file: " << output_file << std::endl;
        return;
    }

    // 写入表头（对齐格式）
    ofs << std::left 
        << std::setw(10) << "LRMID"
        << std::setw(10) << "SrcPAI"
        << std::setw(10) << "DstPAI"
        << std::setw(35) << "Src_Bitmap"
        << std::setw(35) << "Dst_Bitmap"
        << "\n";

    // 遍历每个 LRME_Entry
    for (const auto& entry : LRME_Entries) {
        // 将 bitset 转换为字符串
        // to_string() 默认从高位到低位输出，正好是我们需要的（bit 31在左，bit 0在右）
        std::string src_bitmap = entry.Src_32bitmap.to_string();
        std::string dst_bitmap = entry.Dst_32bitmap.to_string();

        // 输出 LRMID（对齐）
        ofs << std::left << std::setw(10) << entry.LRMID;
        
        // 处理 ANY 端口（SrcPAI == 0xFFFF）
        if (entry.SrcPAI == 0xFFFF) {
            ofs << std::setw(10) << "ANY";
        } else {
            ofs << std::setw(10) << entry.SrcPAI;
        }
        
        if (entry.DstPAI == 0xFFFF) {
            ofs << std::setw(10) << "ANY";
        } else {
            ofs << std::setw(10) << entry.DstPAI;
        }
        
        ofs << std::setw(35) << src_bitmap 
            << std::setw(35) << dst_bitmap 
            << "\n";
    }

    ofs.close();
    std::cout << "[output_LRME_entries] Wrote " << LRME_Entries.size() 
              << " LRME entries to: " << output_file << std::endl;
}


std::map<uint32_t, std::vector<PortBlock>> Caculate_LRME_for_Port_Table(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo) 
{
    // 1) Two optimal propose in paper; For ANY port and ports greater than 1024
    auto optimal_metainfo = Optimal_for_Port_Table(metainfo);

    // 2) Create PortBlock subset
    std::vector<PortBlock> PortBlock;
    Create_Port_Block_Subset(optimal_metainfo, PortBlock);

    // 3) Create LRME entries for PortBlock subset
    auto PortBlock_LRME = Caculate_LRME_Enries(PortBlock);

    // 4) Output Port LRME entries to file
    output_LRME_entries(PortBlock_LRME, "output/Port_table.txt");

    // 5) Return optimal_metainfo
    return optimal_metainfo;
}

// 辅助函数：将 uint32_t IP 地址转换为点分十进制字符串
std::string ip_to_string(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}

// 辅助函数：根据 IP 范围计算 CIDR 表示
std::string ip_range_to_cidr(uint32_t ip_lo, uint32_t ip_hi) {
    // 如果 lo == hi，表示单个 IP
    if (ip_lo == ip_hi) {
        return ip_to_string(ip_lo) + "/32";
    }
    
    // 计算掩码长度
    uint32_t diff = ip_hi - ip_lo + 1;
    int prefix_len = 32;
    
    // 检查是否是标准的 CIDR 块
    if ((diff & (diff - 1)) == 0) {  // 是 2 的幂
        prefix_len = 32 - __builtin_ctz(diff);  // 计算前导零的数量
        
        // 检查 ip_lo 是否对齐
        if ((ip_lo & (diff - 1)) == 0) {
            return ip_to_string(ip_lo) + "/" + std::to_string(prefix_len);
        }
    }
    
    // 非标准 CIDR，返回范围表示
    return ip_to_string(ip_lo) + "-" + ip_to_string(ip_hi);
}

void create_final_IP_table(
    const std::vector<MergrdR>& merged_ip_table,
    const std::map<uint32_t, std::vector<PortBlock>>& optimal_metainfo,
    std::vector<IP_Table_Entry>& final_ip_table
) {
    final_ip_table.clear();
    
    // 遍历 merged_ip_table 中的每个 IP 规则
    for (const auto& ip_rule : merged_ip_table) {
        IP_Table_Entry entry;
        
        // 1) 复制 IP 和 Protocol 信息（与 merged_ip_table 一一对应）
        entry.Src_IP_lo = ip_rule.Src_IP_lo;
        entry.Src_IP_hi = ip_rule.Src_IP_hi;
        entry.Dst_IP_lo = ip_rule.Dst_IP_lo;
        entry.Dst_IP_hi = ip_rule.Dst_IP_hi;
        entry.Proto = ip_rule.Proto;
        
        // 2) 初始化 LRMID 和 REV_Flag（默认值）
        entry.Src_ANY_LRMID = 0xFFFF;  // 使用特殊值表示未设置
        entry.Dst_ANY_LRMID = 0xFFFF;
        entry.No_ANY_LRMID = 0xFFFF;
        entry.Src_ANY_REV_Flag = false;
        entry.Dst_ANY_REV_Flag = false;
        entry.No_ANY_REV_Flag = false;
        entry.drop_flag = false;
        
        // 3) 从 optimal_metainfo 中查找对应的 LRMID
        uint32_t lrmid = ip_rule.LRMID;
        auto it = optimal_metainfo.find(lrmid);
        
        if (it != optimal_metainfo.end()) {
            const auto& port_blocks = it->second;
            
            // 遍历该 LRMID 下的所有 PortBlock
            for (const auto& block : port_blocks) {
                // 根据 ANY_Flag 分类处理
                // ANY_Flag: 0=无ANY, 1=仅Src_ANY, 2=仅Dst_ANY, 3=双ANY
                
                if (block.ANY_Flag == 3) {
                    // 双 ANY：设置 drop_flag 为 true
                    entry.drop_flag = true;
                    // 双ANY情况下，可以选择跳过其他处理或记录特殊信息
                    
                } else if (block.ANY_Flag == 1) {
                    // 仅源端口是 ANY
                    entry.Src_ANY_LRMID = static_cast<uint16_t>(lrmid);
                    entry.Src_ANY_REV_Flag = block.REV_Flag;
                    
                } else if (block.ANY_Flag == 2) {
                    // 仅目标端口是 ANY
                    entry.Dst_ANY_LRMID = static_cast<uint16_t>(lrmid);
                    entry.Dst_ANY_REV_Flag = block.REV_Flag;
                    
                } else if (block.ANY_Flag == 0) {
                    // 无 ANY 端口
                    entry.No_ANY_LRMID = static_cast<uint16_t>(lrmid);
                    entry.No_ANY_REV_Flag = block.REV_Flag;
                }
            }
        }
        
        final_ip_table.push_back(entry);
    }

    std::cout << "[create_final_IP_table] Created final IP table with " 
              << final_ip_table.size() << " entries." << std::endl;
}

void output_final_IP_table(
    const std::vector<IP_Table_Entry>& final_ip_table,
    const std::string& output_file
) {
    std::ofstream ofs(output_file);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Failed to open output file: " << output_file << std::endl;
        return;
    }

    // 写入表头
    ofs << std::left
        << std::setw(20) << "SrcIP"
        << std::setw(20) << "DstIP"
        << std::setw(12) << "Protocol"
        << std::setw(10) << "Src ANY"
        << std::setw(8) << ""
        << std::setw(10) << "Dst ANY"
        << std::setw(8) << ""
        << std::setw(10) << "No ANY"
        << std::setw(8) << ""
        << "\n";
    
    ofs << std::left
        << std::setw(20) << ""
        << std::setw(20) << ""
        << std::setw(12) << ""
        << std::setw(10) << "LRM-ID"
        << std::setw(8) << "REV"
        << std::setw(10) << "LRM-ID"
        << std::setw(8) << "REV"
        << std::setw(10) << "LRM-ID"
        << std::setw(8) << "REV"
        << "\n";
    
    ofs << std::string(106, '-') << "\n";

    // 遍历每个 IP 表项
    for (const auto& entry : final_ip_table) {
        // 转换 IP 地址为 CIDR 格式
        std::string src_ip = ip_range_to_cidr(entry.Src_IP_lo, entry.Src_IP_hi);
        std::string dst_ip = ip_range_to_cidr(entry.Dst_IP_lo, entry.Dst_IP_hi);
        
        // 协议转换为十六进制字符串
        std::ostringstream proto_oss;
        proto_oss << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(entry.Proto);
        
        ofs << std::left
            << std::setw(20) << src_ip
            << std::setw(20) << dst_ip
            << std::setw(12) << proto_oss.str();
        
        // Src ANY
        if (entry.Src_ANY_LRMID != 0xFFFF) {
            ofs << std::setw(10) << entry.Src_ANY_LRMID
                << std::setw(8) << (entry.Src_ANY_REV_Flag ? "True" : "False");
        } else {
            ofs << std::setw(10) << "-"
                << std::setw(8) << "-";
        }
        
        // Dst ANY
        if (entry.Dst_ANY_LRMID != 0xFFFF) {
            ofs << std::setw(10) << entry.Dst_ANY_LRMID
                << std::setw(8) << (entry.Dst_ANY_REV_Flag ? "True" : "False");
        } else {
            ofs << std::setw(10) << "-"
                << std::setw(8) << "-";
        }
        
        // No ANY
        if (entry.No_ANY_LRMID != 0xFFFF) {
            ofs << std::setw(10) << entry.No_ANY_LRMID
                << std::setw(8) << (entry.No_ANY_REV_Flag ? "True" : "False");
        } else {
            ofs << std::setw(10) << "-"
                << std::setw(8) << "-";
        }
        
        // Drop flag
        if (entry.drop_flag) {
            ofs << " [DROP]";
        }
        
        ofs << "\n";
    }

    ofs.close();
    std::cout << "[output_final_IP_table] Wrote final IP table to: " << output_file 
              << " (" << final_ip_table.size() << " entries)" << std::endl;
}

// ===============================================================================
// TCAM-based Port Expansion Algorithm Implementation
// ===============================================================================

// 将端口范围转换为最小前缀覆盖集合（Range to Prefix）
// 返回 <prefix_value, mask> 对的列表
std::vector<std::pair<uint16_t, uint16_t>> port_range_to_prefixes(uint16_t lo, uint16_t hi) {
    std::vector<std::pair<uint16_t, uint16_t>> prefixes;
    
    // 如果是全端口范围，返回 0/0（匹配所有）
    if (lo == 0 && hi == 65535) {
        prefixes.push_back({0, 0});  // mask=0 表示通配所有位
        return prefixes;
    }
    
    uint16_t start = lo;
    
    while (start <= hi) {
        // 找到最大的前缀长度（最小的掩码块）
        int max_prefix_len = 0;
        
        // 从最大可能的块开始尝试（16位，即块大小65536）
        for (int len = 16; len >= 0; len--) {
            uint16_t block_size = (1 << len);
            uint16_t mask = ~(block_size - 1);  // 生成掩码
            uint16_t prefix = start & mask;      // 对齐到块边界
            uint16_t block_end = prefix + block_size - 1;
            
            // 检查这个块是否完全在范围内，且起始点对齐
            if (prefix == start && block_end <= hi) {
                max_prefix_len = len;
                break;
            }
        }
        
        // 生成该前缀块
        uint16_t block_size = (1 << max_prefix_len);
        uint16_t mask = ~(block_size - 1);
        uint16_t prefix = start & mask;
        
        prefixes.push_back({prefix, mask});
        
        // 移动到下一个块
        start = prefix + block_size;
        
        // 防止溢出
        if (start == 0) break;
    }
    
    return prefixes;
}

// TCAM端口展开算法主函数
void TCAM_Port_Expansion(
    const std::vector<Rule5D>& rules,
    std::vector<TCAM_Entry>& tcam_entries
) {
    tcam_entries.clear();
    
    std::cout << "[TCAM_Port_Expansion] Starting port range expansion...\n";
    
    size_t total_entries = 0;
    
    for (size_t rule_idx = 0; rule_idx < rules.size(); rule_idx++) {
        const auto& rule = rules[rule_idx];
        
        // 提取端口范围
        uint16_t src_port_lo = rule.range[2][0];
        uint16_t src_port_hi = rule.range[2][1];
        uint16_t dst_port_lo = rule.range[3][0];
        uint16_t dst_port_hi = rule.range[3][1];
        
        // 将源端口和目标端口范围转换为前缀集合
        auto src_prefixes = port_range_to_prefixes(src_port_lo, src_port_hi);
        auto dst_prefixes = port_range_to_prefixes(dst_port_lo, dst_port_hi);
        
        // 生成所有源端口前缀 × 目标端口前缀的组合
        for (const auto& src_prefix : src_prefixes) {
            for (const auto& dst_prefix : dst_prefixes) {
                TCAM_Entry entry;
                
                // 复制IP信息（IP部分不变，保持掩码形式）
                entry.Src_IP_lo = rule.range[0][0];
                entry.Src_IP_hi = rule.range[0][1];
                entry.Dst_IP_lo = rule.range[1][0];
                entry.Dst_IP_hi = rule.range[1][1];
                
                // 端口前缀和掩码
                entry.Src_Port_prefix = src_prefix.first;
                entry.Src_Port_mask = src_prefix.second;
                entry.Dst_Port_prefix = dst_prefix.first;
                entry.Dst_Port_mask = dst_prefix.second;
                
                // 协议和动作
                entry.Proto = rule.range[4][0];
                entry.action = rule.range[5][0];
                entry.rule_id = rule_idx;
                
                tcam_entries.push_back(entry);
                total_entries++;
            }
        }
    }
    
    std::cout << "[TCAM_Port_Expansion] Expansion completed: " 
              << rules.size() << " rules -> " 
              << tcam_entries.size() << " TCAM entries\n";
    std::cout << "[TCAM_Port_Expansion] Average expansion ratio: " 
              << std::fixed << std::setprecision(2)
              << (double)tcam_entries.size() / rules.size() << "x\n";
}

// 输出TCAM表到文件
void output_TCAM_table(
    const std::vector<TCAM_Entry>& tcam_entries,
    const std::string& output_file
) {
    std::ofstream ofs(output_file);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Failed to open output file: " << output_file << std::endl;
        return;
    }

    // 写入表头
    ofs << std::left
        << std::setw(20) << "SrcIP"
        << std::setw(20) << "DstIP"
        << std::setw(18) << "SrcPort(Prefix/Mask)"
        << std::setw(18) << "DstPort(Prefix/Mask)"
        << std::setw(10) << "Protocol"
        << std::setw(10) << "Action"
        << std::setw(10) << "RuleID"
        << "\n";
    
    ofs << std::string(106, '-') << "\n";

    // 遍历每个 TCAM 表项
    for (const auto& entry : tcam_entries) {
        // 转换 IP 地址为 CIDR 格式
        std::string src_ip = ip_range_to_cidr(entry.Src_IP_lo, entry.Src_IP_hi);
        std::string dst_ip = ip_range_to_cidr(entry.Dst_IP_lo, entry.Dst_IP_hi);
        
        // 端口前缀/掩码格式
        std::ostringstream src_port_oss, dst_port_oss;
        if (entry.Src_Port_mask == 0) {
            src_port_oss << "*";  // 通配所有端口
        } else {
            src_port_oss << entry.Src_Port_prefix << "/0x" 
                        << std::hex << std::setw(4) << std::setfill('0') 
                        << entry.Src_Port_mask;
        }
        
        if (entry.Dst_Port_mask == 0) {
            dst_port_oss << "*";
        } else {
            dst_port_oss << entry.Dst_Port_prefix << "/0x" 
                        << std::hex << std::setw(4) << std::setfill('0') 
                        << entry.Dst_Port_mask;
        }
        
        // 协议转换为十六进制字符串
        std::ostringstream proto_oss;
        proto_oss << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(entry.Proto);
        
        ofs << std::left
            << std::setw(20) << src_ip
            << std::setw(20) << dst_ip
            << std::setw(18) << src_port_oss.str()
            << std::setw(18) << dst_port_oss.str()
            << std::setw(10) << proto_oss.str()
            << std::setw(10) << std::dec << entry.action
            << std::setw(10) << entry.rule_id
            << "\n";
    }

    ofs.close();
    std::cout << "[output_TCAM_table] Wrote TCAM table to: " << output_file 
              << " (" << tcam_entries.size() << " entries)" << std::endl;
}

#ifdef DEMO_LOADER_MAIN
int main(int argc, char **argv) {
    return 0;
}
#endif /* COMPILE_AS_LIB */
