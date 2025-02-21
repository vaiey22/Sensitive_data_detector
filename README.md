# Sensitive Data Detector

## 项目简介
敏感数据识别模块，适用于文件泄漏防范和数据安全检测。模块可以识别文件中的敏感信息并生成结果报告

## 功能
- 快速通道：通过魔数和文件扩展名快速识别文件类型
- 深度分析：分析文件内容，结合结构特征、内容特征、统计特征进行识别
- 动态阈值：根据熵值和文件内容自动调整阈值
- 渐进式学习：通过误判样本持续优化识别模型
- 结果输出：检测结果以CSV格式输出

## 使用方法

1. 克隆仓库：
   ```bash
   git clone https://github.com/yourusername/sensitive-data-detector.git
