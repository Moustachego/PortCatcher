#pragma once



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


//---------------Function Declarations---------------------
void merge_same_ip_entry(
    const std::vector<IPRule>& ip_table,
    std::vector<MergrdR>& merged_ip_table
);

void laod_and_create_IP_table(
    std::vector<IPRule>& ip_table,
    std::vector<PortRule>& port_table, 
    std::vector<MergrdR>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem>& mateifno
);