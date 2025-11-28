# PortCatcher AI Coding Instructions

## Project Overview
PortCatcher is a network ACL (Access Control List) rule processing system that parses 5-tuple firewall rules and splits them into separate IP and Port lookup tables for optimized matching. The project appears designed for P4 programmable switch integration (note the `P4/` directory).

## Architecture

### Core Components
- **`src/Loader.{hpp,cpp}`**: Rule parsing and table generation engine
  - Parses 5-tuple ACL rules from text files
  - Splits rules into `IPRule` (src/dst IP, protocol) and `PortRule` (src/dst ports, action) tables
  - Provides CIDR conversion utilities for IP ranges
- **`src/PortCatcher.cpp`**: Main application entry point (currently skeleton)
- **`src/ACL_rules/`**: Input directory for ACL rule files (empty in current state)
- **`P4/`** and **`output/`**: Directories for P4 switch programs and generated table outputs

### Data Model: The 5D Rule Structure
Rules use a **5-dimensional tuple** representation stored in `Rule5D`:
- **Dimensions 0-1**: Source and destination IP ranges (stored as 32-bit lo/hi pairs)
- **Dimensions 2-3**: Source and destination port ranges (0-65535)
- **Dimension 4**: Protocol field (typically TCP/UDP with 0xFF mask)
- Each dimension stored as `range[d][0]` (low) and `range[d][1]` (high)

**Split Table Design**: Rules decompose into:
- `IPRule`: Contains IP+protocol matching fields (dimensions 0, 1, 4)
- `PortRule`: Contains port ranges + action + rule ID reference (dimensions 2, 3)

This split enables parallel lookup architectures where IP filtering occurs separately from port-based classification.

## Input Format

ACL rules follow this specific format (space or tab-separated):
```
@<src_ip>/<mask> <dst_ip>/<mask> <src_port_lo> : <src_port_hi> <dst_port_lo> : <dst_port_hi> <proto>/<proto_mask> <action>/<action_mask>
```

**Example**:
```
@192.168.1.0/24 10.0.0.0/8 1024 : 65535 80 : 80 0x06/0xFF 0x0000/0xFFFF
```

**Validation rules** (enforced in `load_rules_from_file`):
- IP octets must be 0-255
- Ports must be 0-65535
- Port ranges: `lo` ≤ `hi`
- Invalid lines generate warnings and are skipped

## Code Conventions

### Style Patterns
- **Headers**: Use decorative comment blocks with `@Name`, `@Function`, `@Author`, `@Created` metadata
- **Type aliases**: `using u32 = uint32_t;` preferred over raw types
- **Includes**: `#include <bits/stdc++.h>` used (non-standard but common in competitive programming style)
- **Struct layout**: Separate declarations (in `.hpp`) from implementation (in `.cpp`)

### Critical Implementation Details

**IP Range Calculation** (`ip_range_from_parts`):
- Converts CIDR notation to 32-bit integer ranges
- Handles edge cases: /0 (full range), /32 (single IP), overflow prevention with 64-bit arithmetic
- Always returns `{low, high}` pair where `low` ≤ `high`

**CIDR Decomposition** (`range_to_cidr`):
- Reverse conversion: IP range → minimal set of CIDR blocks
- Uses bit manipulation to find largest valid CIDR block at each step
- **Overflow protection**: Uses 64-bit arithmetic to prevent wraparound at 0xFFFFFFFF

**Priority Assignment**: 
- Assigned sequentially during parsing (`priority = ++rule_count`)
- Higher priority number = later in rule list (typical ACL semantics: first-match)

### File Organization
- Place ACL rule files in `src/ACL_rules/`
- Generated outputs go to `output/`
- P4 switch programs belong in `P4/`

## Build Instructions

No build system detected yet. When creating one:
- Compile with C++11 or later (uses `std::array`, range-based for)
- Link `Loader.cpp` + main source file
- Use `-DDEMO_LOADER_MAIN` to enable standalone Loader testing
- Example: `g++ -std=c++11 -o portcatcher src/PortCatcher.cpp src/Loader.cpp`

## Common Tasks

**Adding new rule validation**: Modify the validation section in `load_rules_from_file` (lines 95-113 of `Loader.cpp`)

**Changing table split logic**: Edit `split_rules` function - maintains 1:1 correspondence between IP and Port tables via shared priority field

**Debugging rule parsing**: Check stderr output - invalid lines emit `[WARN]` messages with line numbers

**Extending to new protocols**: Modify protocol handling in dimension 4 parsing (lines 142-152 of `Loader.cpp`) - currently supports exact match (0xFF mask) and wildcard (0x00 mask)
