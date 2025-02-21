import os
import math
import re
import time
import hashlib
import gc
import csv
import json
import tempfile
import subprocess
import sys
from typing import Dict, List, Tuple, Set, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='detector.log'
)
logger = logging.getLogger('SensitiveDataDetector')

# 共享的全局预编译正则表达式
RE_SENSITIVE_PATTERNS = {
    'id_card': re.compile(r'[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]'),
    'phone': re.compile(r'(?:13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\d{8}'),
    'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'ip': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
    'price': re.compile(r'[\￥\$\€\¥]?\d{1,3}(?:,\d{3})*(?:\.\d{2})?'),
    'amount': re.compile(r'[\￥\$\€\¥]?\d+(?:,\d{3})*(?:\.\d+)?'),
    'total_price': re.compile(r'总价[:：]?\s?[\￥\$\€\¥]?\d{1,3}(?:,\d{3})*(?:\.\d{2})?'),
    'medical_record': re.compile(r'\b[1-9]{1}[0-9]{5,8}\b'),
    'drug_name': re.compile(r'(?i)\b(?:阿莫西林|布洛芬|头孢|利巴韦林|双氯芬酸|维生素C)\b'),
    'hospital': re.compile(r'医院[:：]?[^\s]+'),
    'medical_condition': re.compile(r'(?i)\b(?:糖尿病|高血压|冠心病|肺结核|癌症)\b'),
    'purchase_record': re.compile(r'购买时间[:：]?\d{4}[-/]\d{1,2}[-/]\d{1,2}'),
    'order_number': re.compile(r'\b[0-9A-Za-z]{10,20}\b'),
    'payment_method': re.compile(r'支付方式[:：]?[^\s]+'),
    'transaction_id': re.compile(r'\b[0-9A-Fa-f]{32}\b'),
}

# 关键词特征集
SENSITIVE_KEYWORDS = {
    '密码', 'password', '账号', 'account',
    '身份证', 'id card', '信用卡', 'credit card',
    '私密', 'private', '机密', 'confidential',
    'secret', 'sensitive', 'internal', 'restricted',
    'token', 'key', 'auth', 'certificate',
    '价格', '金额', 'total price', 'price', 'cost', 'amount', 'total', '费用', 'payment',
    '人民币', '美元', '欧元', '￥', '$', '€', '¥', '总价', '账单', '发票', '付款',
    '病历号', '药品', '医生', '医疗', '诊断', '病例', '手术', '医院', '住院', '病床',
    '治疗', '健康', '疾病', '糖尿病', '高血压', '冠心病', '癌症', '肺结核', '骨折',
    '药品名称', '处方', '医疗记录', '疫苗', '药物', '医生姓名', '病人信息',
    '购买时间', '订单号', '支付方式', '交易ID', '支付', '购买', '订单', '发货', '物流',
    '发票号', '支付平台', '购物', '购物车', '支付状态', '支付方式', '支付金额',
}


# 二进制特征标记
BINARY_MARKERS = {
    b'PK',  # ZIP/Office
    b'%PDF',  # PDF
    b'\xFF\xD8\xFF',  # JPEG
    b'GIF89a',  # GIF
    b'\x50\x4B\x03\x04',  # ZIP
    b'\x1F\x8B\x08',  # GZIP
    b'\x42\x5A\x68',  # BZIP2
    b'\x37\x7A\xBC\xAF\x27\x1C',  # 7Z
}

class SensitiveDataDetector:
    def __init__(self, rules_file='learned_rules.json'):
        self.rules_file = rules_file
        self.cache = {}
        self._init_base_rules()
        self.load_rules()
        self.batch_size = 20
        self.max_workers = min(32, os.cpu_count() * 2)

    def _init_base_rules(self):
        """初始化基本规则"""
        self.current_threshold = 0.35
        self.weights = {'structure': 0.3, 'content': 0.5, 'context': 0.2}
        self.learned_patterns = set()
        self.feature_patterns = {}
        self.threshold_history = []

    def save_rules(self):
        """保存学习规则"""
        data = {
            'patterns': list(self.learned_patterns),
            'features': self.feature_patterns,
            'threshold': self.current_threshold,
            'history': self.threshold_history
        }
        try:
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"保存规则失败: {str(e)}")
            return False

    def load_rules(self):
        """加载学习规则"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.learned_patterns = set(data.get('patterns', []))
                self.feature_patterns = data.get('features', {})
                self.current_threshold = data.get('threshold', 0.35)
                self.threshold_history = data.get('history', [])
                return True
            except Exception as e:
                logger.error(f"加载规则失败: {str(e)}")
                return False
        return False

    def _process_batch(self, file_batch: List[str], directory: str, is_learning: bool = False) -> List[Tuple[str, str]]:
        """批量处理文件"""
        results = []
        is_sensitive_dir = "敏感文件" in directory
        
        for filename in file_batch:
            try:
                file_path = os.path.join(directory, filename)
                if is_learning:
                    self._learn_from_file(file_path, is_sensitive_dir)
                    results.append((filename, '已学习'))
                else:
                    is_sensitive = self._detect_file(file_path, is_sensitive_dir)
                    results.append((filename, '敏感' if is_sensitive else '常规'))
            except Exception as e:
                logger.error(f"处理文件 {filename} 时出错: {str(e)}")
                results.append((filename, '敏感' if not is_learning else '学习失败'))
        
        return results

    def learn_mode(self, directory: str):
        """学习模式: 使用多线程批量学习"""
        if not os.path.exists(directory):
            logger.error(f"目录不存在: {directory}")
            return False

        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        total_files = len(files)
        processed = 0
        results = []

        print(f"开始从 {directory} 学习规则 (共 {total_files} 个文件)...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {}
            
            for i in range(0, len(files), self.batch_size):
                batch = files[i:i + self.batch_size]
                future = executor.submit(self._process_batch, batch, directory, True)
                future_to_batch[future] = batch

            for future in as_completed(future_to_batch):
                batch_results = future.result()
                results.extend(batch_results)
                processed += len(batch_results)
                
                if processed % 100 == 0 or processed == total_files:
                    print(f"学习进度: {processed}/{total_files} ({processed/total_files*100:.1f}%)")
                    self.save_rules()

        self.save_rules()
        print(f"\n规则学习完成! 规则已保存到: {self.rules_file}")
        return True

    def detect_mode(self, directory: str):
        """检测模式: 使用多线程批量检测"""
        if not os.path.exists(directory):
            logger.error(f"目录不存在: {directory}")
            return False

        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        total_files = len(files)
        processed = 0
        results = []

        print(f"开始检测 {directory} 中的文件 (共 {total_files} 个)...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {}
            
            for i in range(0, len(files), self.batch_size):
                batch = files[i:i + self.batch_size]
                future = executor.submit(self._process_batch, batch, directory, False)
                future_to_batch[future] = batch

            for future in as_completed(future_to_batch):
                batch_results = future.result()
                results.extend(batch_results)
                processed += len(batch_results)
                
                if processed % 100 == 0 or processed == total_files:
                    print(f"检测进度: {processed}/{total_files} ({processed/total_files*100:.1f}%)")

        # 保存结果
        csv_filename = f"{directory}_results.csv"
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['文件名', '类型'])
            writer.writerows(results)

        print(f"\n检测完成!")
        print(f"检测结果已保存到: {csv_filename}")
        return True

    def _detect_file(self, file_path: str, is_sensitive_dir: bool) -> bool:
        """检测单个文件"""
        try:
            # 1. 快速检查
            if file_path in self.cache:
                return self.cache[file_path]

            # 2. 文件基本特征检查
            file_ext = os.path.splitext(file_path)[1].lower()
            # 如果没有扩展名且文件位于敏感目录中，默认处理为敏感文件
            if not file_ext:
                if is_sensitive_dir:
                    return True
                # 可以在这里添加判断其他逻辑（如按文件头判断）

            # 3. 读取文件内容（只读取前4KB）
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(4096)  # 只读取前4KB进行分析
            except:
                return True if is_sensitive_dir else False

            # 4. 文件类型推断：根据文件头（Magic Bytes）判断文件类型
            # 常见的文件类型（例如图片格式）可以添加更多的处理方式
            if self._is_known_binary_type(content):
                return False  # 如果是常见的二进制文件，可以认为是常规文件

            # 5. 特征分析
            score = self._analyze_content(content, file_path)

            # 6. 阈值判断
            threshold = self.current_threshold * 0.7 if is_sensitive_dir else self.current_threshold
            is_sensitive = score > threshold

            # 7. 缓存结果
            self.cache[file_path] = is_sensitive

            return is_sensitive

        except Exception as e:
            logger.error(f"检测文件失败: {str(e)}")
            return True if is_sensitive_dir else False
        
        
    def _is_known_binary_type(self, content: bytes) -> bool:
        """根据文件头（Magic Bytes）推断文件类型"""
        binary_signatures = {
            b'PK': 'zip',  # ZIP/Office
            b'%PDF': 'pdf',  # PDF
            b'\xFF\xD8\xFF': 'jpeg',  # JPEG
            b'GIF89a': 'gif',  # GIF
            b'\x50\x4B\x03\x04': 'zip',  # ZIP
            b'\x1F\x8B\x08': 'gzip',  # GZIP
            b'\x42\x5A\x68': 'bzip2',  # BZIP2
            b'\x37\x7A\xBC\xAF\x27\x1C': '7z',  # 7Z
        }

        # 遍历已知的文件标志，检查文件是否为常见二进制格式
        for marker, file_type in binary_signatures.items():
            if content.startswith(marker):
                logger.debug(f"文件类型推测为 {file_type} 格式")
                return True
        return False

    def _analyze_content(self, content: bytes, file_path: str) -> float:
        """分析文件内容"""
        score = 0.0
        
        # 1. 二进制特征检查
        if any(marker in content for marker in BINARY_MARKERS):
            score += 0.3
        
        # 2. 文本内容检查
        try:
            text = content.decode('utf-8', errors='ignore').lower()
            
            # 检查敏感关键词
            found_keywords = sum(1 for keyword in SENSITIVE_KEYWORDS if keyword in text)
            score += 0.1 * min(found_keywords, 5)  # 最多加0.5分
            
            # 检查正则表达式模式
            for pattern in RE_SENSITIVE_PATTERNS.values():
                if pattern.search(text):
                    score += 0.2
                    break
            
            # 检查学习到的模式
            if any(pattern in text for pattern in self.learned_patterns):
                score += 0.3
                
        except:
            pass
        
        # 3. 熵值检查
        if content:
            entropy = self._calculate_entropy(content)
            if entropy > 6.5:  # 高熵值通常表示加密或压缩数据
                score += 0.2
        
        return min(1.0, score)  # 确保分数不超过1.0

    def _learn_from_file(self, file_path: str, is_sensitive_dir: bool):
        """从文件中学习特征"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(4096)
            
            if not content:
                return
            
            # 学习文本特征
            try:
                text = content.decode('utf-8', errors='ignore').lower()
                words = text.split()
                
                # 提取上下文特征
                for i, word in enumerate(words):
                    if word in SENSITIVE_KEYWORDS:
                        start = max(0, i - 2)
                        end = min(len(words), i + 3)
                        context = ' '.join(words[start:end])
                        self.learned_patterns.add(context)
                
            except:
                pass
            
            # 更新阈值
            if is_sensitive_dir:
                score = self._analyze_content(content, file_path)
                self.threshold_history.append(score)
                if len(self.threshold_history) > 1000:
                    self.threshold_history.pop(0)
                # 动态调整阈值
                if self.threshold_history:
                    self.current_threshold = sum(self.threshold_history) / len(self.threshold_history)
            
        except Exception as e:
            logger.error(f"学习文件失败: {str(e)}")

    def _calculate_entropy(self, data: bytes) -> float:
        """计算熵值"""
        if not data:
            return 0.0
            
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
            
        entropy = 0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
            
        return entropy

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("使用方法: python sensitive_data_detector.py <模式> <目录>")
        print("模式: learn(学习) 或 detect(检测)")
        print("目录: 要处理的文件目录")
        sys.exit(1)
        
    mode = sys.argv[1]
    directory = sys.argv[2]
    
    if mode not in ["learn", "detect"]:
        print("错误：模式必须是 'learn' 或 'detect'")
        sys.exit(1)
        
    detector = SensitiveDataDetector()
    
    if mode == "learn":
        print("进入学习模式...")
        if "敏感文件" not in directory:
            print("警告：学习模式推荐使用敏感文件目录进行学习")
        detector.learn_mode(directory)
    else:
        print("进入检测模式...")
        if not os.path.exists('learned_rules.json'):
            print("警告：未找到规则文件，建议先运行学习模式生成规则")
        detector.detect_mode(directory)
