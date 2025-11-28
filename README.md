# PortCatcher

一个高效的网络 ACL（访问控制列表）规则处理系统，用于解析 5 元组防火墙规则并将其分割成独立的 IP 和端口查找表，以优化匹配性能。该项目专为 P4 可编程交换机集成设计。

## 项目简介

PortCatcher 将传统的 5 元组 ACL 规则（源/目的 IP、源/目的端口、协议）分解为两个独立的查找表：
- **IP 规则表**：包含 IP 地址范围和协议匹配字段
- **端口规则表**：包含端口范围、动作和规则 ID

这种分离式设计支持并行查找架构，使得 IP 过滤和基于端口的分类可以独立进行，提高了数据平面的处理效率。

## 项目结构

```
PortCatcher/
├── src/
│   ├── PortCatcher.cpp      # 主程序入口
│   ├── Loader.cpp            # 规则加载和处理引擎
│   ├── Loader.hpp            # 数据结构和函数声明
│   ├── Function.hpp          # 功能扩展头文件
│   └── ACL_rules/            # ACL 规则文件目录
│       └── test.rules        # 测试规则文件
├── P4/                       # P4 交换机程序目录
├── output/                   # 生成的表输出目录
├── run.sh                    # 一键编译运行脚本
└── .github/
    └── copilot-instructions.md  # AI 编程助手指南
```

## 快速开始

### 环境要求

- **编译器**：支持 C++11 或更高版本的 g++
- **操作系统**：Linux / macOS / WSL

### 编译和运行

**方法 1：使用运行脚本（推荐）**

```bash
# 使用默认规则文件
./run.sh

# 使用自定义规则文件
./run.sh path/to/your/rules.txt
```

**方法 2：手动编译**

```bash
# 编译
g++ -std=c++11 -o portcatcher src/PortCatcher.cpp src/Loader.cpp

# 运行
./portcatcher                           # 使用默认规则文件
./portcatcher src/ACL_rules/test.rules  # 指定规则文件
```

## ACL 规则格式

规则文件采用以下格式（支持空格或制表符分隔）：

```
@<源IP>/<掩码> <目的IP>/<掩码> <源端口低> : <源端口高> <目的端口低> : <目的端口高> <协议>/<协议掩码> <动作>/<动作掩码>
```

### 示例规则

```
@192.168.1.0/24 10.0.0.0/8 1024 : 65535 80 : 80 0x06/0xFF 0x0000/0xFFFF
@0.0.0.0/0 172.16.0.0/12 0 : 65535 443 : 443 0x06/0xFF 0x0001/0xFFFF
@10.0.0.0/8 0.0.0.0/0 53 : 53 0 : 65535 0x11/0xFF 0x0000/0xFFFF
```

### 字段说明

- **IP 地址**：CIDR 格式（例如 192.168.1.0/24）
- **端口范围**：0-65535，使用 `:` 分隔低端口和高端口
- **协议**：
  - `0x06/0xFF`：TCP（精确匹配）
  - `0x11/0xFF`：UDP（精确匹配）
  - `0x00/0x00`：任意协议（通配符）
- **动作**：自定义动作标志（例如 0x0000 表示丢弃，0x0001 表示允许）

### 验证规则

- IP 地址的每个八位组必须在 0-255 之间
- 端口必须在 0-65535 之间
- 端口范围的低端口必须 ≤ 高端口
- 无效的行会生成警告并被跳过

## 核心数据结构

### Rule5D - 5 维规则

```cpp
struct Rule5D {
    std::array<std::array<uint32_t,2>, 5> range;  // [维度][低/高]
    // 维度 0-1: 源/目的 IP 范围
    // 维度 2-3: 源/目的端口范围
    // 维度 4: 协议
    std::array<int,5> prefix_length;
    uint32_t priority;
    uint16_t action;
};
```

### IPRule - IP 规则表

```cpp
struct IPRule {
    uint32_t src_ip_lo, src_ip_hi;
    uint32_t dst_ip_lo, dst_ip_hi;
    uint8_t  proto;
    uint32_t priority;
    int src_prefix_len, dst_prefix_len;
};
```

### PortRule - 端口规则表

```cpp
struct PortRule {
    uint32_t rid;                          // 规则 ID
    uint16_t src_port_lo, src_port_hi;
    uint16_t dst_port_lo, dst_port_hi;
    uint32_t priority;
    uint16_t action;
};
```

## 核心功能

### 1. 规则加载 (`load_rules_from_file`)

- 从文本文件解析 ACL 规则
- 自动验证 IP、端口和协议字段
- 支持空格和制表符分隔的格式
- CIDR 到 IP 范围的转换（支持 /0 到 /32）

### 2. 规则分割 (`split_rules`)

- 将 5 元组规则分解为 IP 表和端口表
- 通过共享的优先级字段维护 1:1 对应关系
- 支持并行查找架构

### 3. CIDR 转换 (`range_to_cidr`)

- 将 IP 范围转换回最小 CIDR 块集合
- 使用 64 位算术防止溢出
- 高效的位操作实现

## 运行示例

```bash
$ ./run.sh
=== PortCatcher 构建与运行脚本 ===

[1] 编译项目...
[成功] 编译完成

[2] 运行程序...

============================================================================
----------------------------------PortCatcher-------------------------------
============================================================================

[STEP 1] Loading rules from: src/ACL_rules/test.rules
[SUCCESS] Loaded 27 rules

[STEP 2] Splitting rules into IP and Port tables...
[split_rules] IP table size = 27, Port table size = 27
[SUCCESS] IP table: 27 entries, Port table: 27 entries

[成功] 程序运行完成
```

## 开发指南

### 添加新的规则验证

在 `Loader.cpp` 的 `load_rules_from_file` 函数中修改验证部分（第 95-113 行）。

### 修改表分割逻辑

编辑 `split_rules` 函数，注意维护 IP 表和端口表之间的对应关系。

### 调试规则解析

检查 stderr 输出，无效的行会生成带行号的 `[WARN]` 消息。

### 扩展协议支持

修改 `Loader.cpp` 中维度 4 的协议处理逻辑（第 142-152 行）。

## 性能特点

- **分离式查找**：IP 和端口匹配可以并行执行
- **紧凑存储**：使用 32 位整数存储 IP 范围
- **高效解析**：单次扫描解析规则文件
- **溢出安全**：关键算法使用 64 位算术防止溢出

## P4 集成

该项目生成的 IP 和端口表可以直接导入 P4 可编程交换机，实现硬件加速的包过滤和分类。

## 作者

- **weijzh** (weijzh@pcl.ac.cn)
- 创建日期：2025-10-30

## 许可证

请参考项目根目录的 LICENSE 文件。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

- **2025-11-27**: 添加主程序和运行脚本
- **2025-11-26**: 创建 PortCatcher 主程序框架
- **2025-10-30**: 初始版本，实现规则加载和分割功能
