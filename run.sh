#!/bin/bash
# PortCatcher 运行脚本
# 用法: ./run.sh [规则文件路径]

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== PortCatcher 构建与运行脚本 ===${NC}\n"

# 编译项目
echo -e "${YELLOW}[1] 编译项目...${NC}"
g++ -std=c++11 -o portcatcher src/PortCatcher.cpp src/Loader.cpp src/Function.cpp

if [ $? -ne 0 ]; then
    echo -e "${RED}[错误] 编译失败！${NC}"
    exit 1
fi

echo -e "${GREEN}[成功] 编译完成${NC}\n"

# 运行程序
echo -e "${YELLOW}[2] 运行程序...${NC}\n"
if [ $# -eq 0 ]; then
    # 没有参数，使用默认规则文件
    ./portcatcher
else
    # 使用指定的规则文件
    ./portcatcher "$1"
fi

exit_code=$?
echo ""
if [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}[成功] 程序运行完成${NC}"
else
    echo -e "${RED}[错误] 程序运行失败 (退出码: $exit_code)${NC}"
fi

exit $exit_code
