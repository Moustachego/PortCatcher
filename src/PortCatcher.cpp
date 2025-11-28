/** *************************************************************/
// @Name: PortCatcher.cpp
// @Function: Load 5D rules from file, split into IP and Port tables
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-11-26
/************************************************************* */

#include <bits/stdc++.h>
#include <iostream>

#include "Loader.hpp"
#include "Function.hpp"

using namespace std;

int main(int argc, char **argv)
{
    // Parse command-line arguments
    string rules_path = "src/ACL_rules/test.rules";
    if (argc >= 2) {
        rules_path = string(argv[1]);
    }

    cout << "============================================================================\n";
    cout << "----------------------------------PortCatcher-------------------------------\n";
    cout << "============================================================================\n\n";

    // Step 1: Load rules from file
    cout << "[STEP 1] Loading rules from: " << rules_path << endl;
    vector<Rule5D> rules;
    try {
        load_rules_from_file(rules_path, rules);
    } catch (const std::exception &e) {
        cerr << "[ERROR] Failed to load rules: " << e.what() << endl;
        return 1;
    }

    cout << "[SUCCESS] Loaded " << rules.size() << " rules\n\n";

    // Step 2: Split rules into IP and Port tables
    cout << "[STEP 2] Splitting rules into IP and Port tables...\n";
    vector<IPRule> ip_table;
    vector<PortRule> port_table;
    split_rules(rules, ip_table, port_table);
    cout << "[SUCCESS] IP table: " << ip_table.size() << " entries, "
         << "Port table: " << port_table.size() << " entries\n\n";

    // Step 3: Create metadata and Merged Same IP tables
    // (load_and_create_IP_table internally handles IP merge, intersection detection, and metainfo generation)
    cout << "[STEP 3] Creating IP Table and port metadata...\n";
    vector<MergrdR> merged_ip_table;
    std::map<uint32_t, std::vector<MergedItem>> metainfo;  // key: LRMID, value: port items
    load_and_create_IP_table(ip_table, port_table, merged_ip_table, metainfo);
    cout << "[SUCCESS] IP Table and metadata processing completed (Merged to " << merged_ip_table.size() << " unique IP entries)\n\n";

    // Step 4: Create LRME for Port Table
    cout << "[STEP 4] Creating Port Table...\n";
    Caculate_LRME_for_Port_Table(metainfo);
    

}