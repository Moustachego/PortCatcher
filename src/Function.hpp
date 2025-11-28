#pragma once

#include <vector>
#include <map>
#include <tuple>

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
    uint16_t action;
};

struct LRME_Entry{
    uint32_t LRMID;
    uint16_t SrcPAI, DstPAI;  // Port Address Interval
    uint32_t Src_32bitmap, Dst_32bitmap;
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

void Caculate_LRME_for_Port_Table(
    const std::map<uint32_t, std::vector<MergedItem>>& metainfo
);