![image](https://github.com/user-attachments/assets/9813204b-50eb-4667-a370-5858186a4049)![image](https://github.com/user-attachments/assets/7737bbd9-0d23-48ae-bba9-9ba6ac6d1d9a)# Sensitive Data Detector
![image](https://github.com/user-attachments/assets/de65f157-d1a8-49c2-83ba-2567caecb04b)

## 项目简介
Sensitive Data Detector 是一款用于文件泄漏防范和数据安全检测的敏感数据识别模块。该模块能够分析各种文件，识别其中的敏感信息（如身份证号、银行卡号、电话号码、医疗记录等），并生成详细的结果报告。项目支持多种文件格式，能够根据不同文件的内容和特征进行深度分析。

## 功能
- **快速通道**：通过魔数和文件扩展名快速识别文件类型，无需完全解析文件内容
- **深度分析**：结合文件的结构特征、内容特征和统计特征（如熵值分析）进行多层次敏感数据识别
- **动态阈值**：根据文件的熵值和分析内容，自动调整敏感数据识别的阈值，确保高准确率
- **渐进式学习**：通过误判样本持续优化识别模型，支持定期更新学习规则
- **结果输出**：检测结果以 CSV 格式输出，方便用户查看和分析

## 安装和使用

### 克隆仓库
首先，克隆此仓库到本地：
```bash
git clone https://github.com/yourusername/sensitive-data-detector.git

进入项目目录并安装所需的依赖：
看requirements.txt --- 一般来说下载python都是会自带这些库的
如果没有的话麻烦 --- pip install <库>

使用方法
项目支持两种工作模式：学习模式 (learn) 和 检测模式 (detect)。

学习模式 (learn)：此模式用于学习并优化敏感数据识别规则。通过分析敏感文件目录中的文件，模块会提取特征并生成规则，供后续检测使用

bash
python sensitive_data_detector.py learn <敏感文件目录>
检测模式 (detect)：此模式用于检测文件夹中的文件是否包含敏感数据。检测过程中会根据已学习的规则进行分析，并生成检测报告

bash
python sensitive_data_detector.py detect <文件目录>

参数说明
<模式>：指定工作模式，learn 用于学习模式，detect 用于检测模式
<目录>：指定要处理的文件目录路径。学习模式下建议使用包含敏感数据的文件夹，检测模式下可以是任意文件夹

输出结果
检测结果会保存在同目录下的 文件目录_results.csv 文件中，包含每个文件的名称和其识别类型（敏感或常规）
学习模式下，规则会保存在 learned_rules.json 文件中，包含学习到的特征和阈值

配置与优化
文件缓存：为了提高效率，模块会缓存文件检测结果。你可以修改缓存策略来优化性能
多线程：项目默认使用多线程来处理文件，用户可以通过 max_workers 参数调整线程池的大小

常见问题
Q: 如何调整敏感数据的识别阈值？
A: 阈值可以通过 current_threshold 参数进行调整。学习模式会动态更新此阈值。你也可以手动修改 learned_rules.json 文件中的 threshold 值

Q: 文件类型无法识别怎么办？
A: 如果文件类型无法识别，可以检查文件的扩展名和魔数是否正常，或者尝试通过扩展名和魔数进行自定义识别

Q: 如何提高模型的准确率？
A: 推荐通过持续优化学习样本（特别是误判样本）来提高模型的准确性。可以通过学习模式不断优化模型规则

！！！！如何在离线环境中运行：
安装Python：确保目标环境中已经安装了Python（推荐3.6及以上版本）。如果没有安装，可以下载Python安装包并在离线环境中安装。
执行代码：因为没有额外的依赖，可以直接运行脚本：

bash
python sensitive_data_detector.py <mode> <directory>

其中，<mode>是learn或detect，<directory>是文件目录路径。
只需要确保Python已正确安装并配置即可，其他标准库的模块无需额外安装。

1、先执行学习敏感规则：
python sensitive_data_detector.py learn 敏感文件

2、再验证敏感文件：
python sensitive_data_detector.py detect 敏感文件

3、最后验证常规文件：
python sensitive_data_detector.py detect 常规文件

.log --- 日志文件
-----------------------------------------------------------------------

贡献
欢迎提交问题报告或贡献代码。您可以通过提交 pull request 或创建 issues 来参与贡献

License
该项目使用 MIT 许可证，详情请参阅 LICENSE 文件
