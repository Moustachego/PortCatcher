#pragma once

#include <vector>
#include <map>
#include <tuple>
#include <bitset>
#include <string>

// ---------------Struct Declarations---------------------
struct MergedItem {
    uint32_t LRMID;
    uint32_t Src_Port_lo;
    uint32_t Src_Port_hi;
    uint32_t Dst_Port_lo;
    uint32_t Dst_Port_hi;
    uint16_t action;
};

struct MergrdR{
    uint32_t Src_IP_lo, Src_IP_hi;
    uint32_t Dst_IP_lo, Dst_IP_hi;
    uint8_t  Proto;
    uint32_t LRMID;
    std::vector<size_t> merged_R;  // original rule indices
};

struct PortBlock{
    uint32_t LRMID;
    uint16_t Src_Port_lo, Src_Port_hi;
    uint16_t Dst_Port_lo, Dst_Port_hi;
    bool REV_Flag;
    uint8_t ANY_Flag;
    uint16_t action;
};

struct LRME_Entry{
    uint32_t LRMID;
    uint8_t ANY_Flag;
    uint16_t SrcPAI, DstPAI;  // Port Address Interval
    std::bitset<32> Src_32bitmap, Dst_32bitmap;  // 32位二进制位图
};

struct IP_Table_Entry{
    uint32_t Src_IP_lo, Src_IP_hi;
    uint32_t Dst_IP_lo, Dst_IP_hi;
    uint8_t  Proto;
    uint16_t Src_ANY_LRMID, Dst_ANY_LRMID, No_ANY_LRMID;
    bool Src_ANY_REV_Flag, Dst_ANY_REV_Flag, No_ANY_REV_Flag;
    bool drop_flag;  // true if double ANY (src and dst both ANY)
};


//---------------Function Declarations---------------------
void merge_same_ip_entry(
    const std::vector<IPRule>& ip_table,
    std::vector<MergrdR>& merged_ip_table
);

void Create_metainfo(
    const std::vector<MergrdR>& merged_ip_table,
    const std::vector<PortRule>& port_table,
    std::map<uint32_t, std::vector<MergedItem>>& metainfo
);

void output_metainfo(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo,
    const std::string& output_file
);

void load_and_create_IP_table(
    std::vector<IPRule>& ip_table,
    std::vector<PortRule>& port_table, 
    std::vector<MergrdR>& merged_ip_table,
    std::map<uint32_t, std::vector<MergedItem>>& metainfo
);

std::map<uint32_t, std::vector<PortBlock>> Optimal_for_Port_Table(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo
);

void Create_Port_Block_Subset(
    const std::map<uint32_t, std::vector<PortBlock>>& optimal_metainfo,
    std::vector<PortBlock>& PortBlock_Subset
);

std::vector<LRME_Entry> Caculate_LRME_Enries(
    const std::vector<PortBlock>& PortBlock_Subset
);

void output_LRME_entries(
    const std::vector<LRME_Entry>& LRME_Entries,
    const std::string& output_file
);

std::map<uint32_t, std::vector<PortBlock>> Caculate_LRME_for_Port_Table(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo
);

void create_final_IP_table(
    const std::vector<MergrdR>& merged_ip_table,
    const std::map<uint32_t, std::vector<PortBlock>>& optimal_metainfo,
    std::vector<IP_Table_Entry>& final_ip_table
);

void output_final_IP_table(
    const std::vector<IP_Table_Entry>& final_ip_table,
    const std::string& output_file
);

// ---------------TCAM-based Port Expansion Algorithm---------------------
struct TCAM_Entry {
    uint32_t Src_IP_lo, Src_IP_hi;
    uint32_t Dst_IP_lo, Dst_IP_hi;
    uint16_t Src_Port_prefix;      // 端口前缀值
    uint16_t Src_Port_mask;        // 端口掩码
    uint16_t Dst_Port_prefix;      // 端口前缀值
    uint16_t Dst_Port_mask;        // 端口掩码
    uint8_t  Proto;
    uint16_t action;
    uint32_t rule_id;              // 原始规则ID
};

// 将端口范围转换为最小前缀覆盖集合
std::vector<std::pair<uint16_t, uint16_t>> port_range_to_prefixes(uint16_t lo, uint16_t hi);

// TCAM端口展开算法主函数
void TCAM_Port_Expansion(
    const std::vector<Rule5D>& rules,
    std::vector<TCAM_Entry>& tcam_entries
);

// 输出TCAM表到文件
void output_TCAM_table(
    const std::vector<TCAM_Entry>& tcam_entries,
    const std::string& output_file
);
