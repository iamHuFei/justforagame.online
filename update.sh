#!/bin/bash

# 设置工作目录
cd "$(dirname "$0")"

# 输出日志
echo "开始更新工具数据 - $(date '+%Y-%m-%d %H:%M:%S')" >> update.log

# 运行Python脚本
python3 update_tools.py >> update.log 2>&1

# 输出完成时间
echo "更新完成 - $(date '+%Y-%m-%d %H:%M:%S')" >> update.log
echo "----------------------------------------" >> update.log 