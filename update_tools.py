import requests
import re
import json
from datetime import datetime
import os

def fetch_github_md():
    """从GitHub获取README.md内容"""
    url = "https://raw.githubusercontent.com/guchangan1/All-Defense-Tool/main/README.md"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"获取README.md失败: {e}")
        return None

def parse_tools(md_content):
    """解析Markdown内容，提取工具信息"""
    tools = []
    current_category = None
    
    # 按行分割内容
    lines = md_content.split('\n')
    
    for line in lines:
        # 检查是否是标题（以#开头）
        if line.startswith('#'):
            # 提取分类名称（去掉#号和空格）
            current_category = line.lstrip('#').strip()
            continue
            
        # 使用正则表达式匹配表格行
        table_pattern = r'\|(.*?)\|(.*?)\|(.*?)\|'
        table_match = re.match(table_pattern, line)
        
        if table_match:
            # 跳过表头
            if "项目简介" in table_match.group(1):
                continue
                
            description = table_match.group(1).strip()
            github = table_match.group(2).strip()
            name = table_match.group(3).strip()
            
            # 检查是否包含有效的GitHub链接
            if "github.com" in github:
                tool = {
                    "name": name,
                    "description": description,
                    "github": github,
                    "category": current_category,
                    "rating": 4.5,  # 默认评分
                    "ratingCount": 0
                }
                tools.append(tool)
    
    return tools

def update_tools_js(tools):
    """更新tools.js文件"""
    js_content = f"const tools = {json.dumps(tools, ensure_ascii=False, indent=4)};"
    
    try:
        with open("tools.js", "w", encoding="utf-8") as f:
            f.write(js_content)
        print("tools.js 更新成功")
    except Exception as e:
        print(f"更新tools.js失败: {e}")

def main():
    print(f"开始更新工具数据 - {datetime.now()}")
    
    # 获取README.md内容
    md_content = fetch_github_md()
    if not md_content:
        return
    
    # 解析工具信息
    tools = parse_tools(md_content)
    
    # 更新tools.js
    update_tools_js(tools)
    
    print(f"更新完成 - {datetime.now()}")
    print(f"共更新 {len(tools)} 个工具")
    
    # 打印分类统计
    categories = {}
    for tool in tools:
        if tool['category']:
            categories[tool['category']] = categories.get(tool['category'], 0) + 1
    
    print("\n分类统计:")
    for category, count in categories.items():
        print(f"{category}: {count}个工具")

if __name__ == "__main__":
    main()