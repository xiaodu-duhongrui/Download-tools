import sys
import os
import time
import math
import json
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QProgressBar, QSlider, QGroupBox, QSpinBox,
                            QFileDialog, QTextEdit, QComboBox, QMessageBox, QListWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtGui import QColor, QFont

# 配置日志系统
class MultiLanguageFormatter(logging.Formatter):
    def __init__(self, translations):
        super().__init__()
        self.translations = translations
    
    def format(self, record):
        msg = record.getMessage()
        # 检查消息是否在翻译中
        if msg in self.translations:
            return f"{record.asctime} - {record.levelname} - {self.translations[msg]}"
        return f"{record.asctime} - {record.levelname} - {msg}"

# 多语言翻译数据（直接嵌入代码）
LANGUAGES = {
    "zh_CN": {
        "app_title": "多线程下载器",
        "url_placeholder": "输入下载链接",
        "browse": "浏览",
        "download": "开始下载",
        "options": "下载选项",
        "threads": "线程数:",
        "speed_limit": "速度限制(KB/s):",
        "conn_limit": "并发连接数:",
        "glass_effect": "毛玻璃效果设置",
        "blur": "模糊度:",
        "opacity": "透明度:",
        "log": "下载日志",
        "tasks": "下载任务",
        "status_ready": "就绪",
        "browse_save_path": "保存文件",
        "warning": "警告",
        "input_url": "请输入下载链接",
        "downloading": "下载中",
        "paused": "已暂停",
        "completed": "已完成",
        "progress_format": "[{status}] {filename} - 进度: {progress}% - 速度: {speed} KB/s",
        "status_downloading": "下载中: {filename}, 进度: {progress}%",
        "log_start_download": "开始下载: {url}",
        "log_save_to": "保存到: {path}",
        "log_threads": "线程数: {threads}, 并发连接数: {conn}",
        "log_block_resume": "块 {part_file} 从 {start} 开始续传",
        "log_block_complete": "块 {part_file} 下载完成",
        "log_block_failed": "块 {part_file} 下载失败，达到最大重试次数",
        "log_merge_complete": "文件合并完成: {path}",
        "log_pause": "下载已暂停",
        "log_resume": "下载已恢复",
        "log_stop": "下载已停止",
        "log_task_complete": "任务完成: {path}"
    },
    "en_US": {
        "app_title": "Multi-Thread Downloader",
        "url_placeholder": "Enter download URL",
        "browse": "Browse",
        "download": "Start Download",
        "options": "Download Options",
        "threads": "Threads:",
        "speed_limit": "Speed Limit (KB/s):",
        "conn_limit": "Concurrent Connections:",
        "glass_effect": "Glass Effect Settings",
        "blur": "Blur:",
        "opacity": "Opacity:",
        "log": "Download Log",
        "tasks": "Download Tasks",
        "status_ready": "Ready",
        "browse_save_path": "Save File",
        "warning": "Warning",
        "input_url": "Please enter a download URL",
        "downloading": "Downloading",
        "paused": "Paused",
        "completed": "Completed",
        "progress_format": "[{status}] {filename} - Progress: {progress}% - Speed: {speed} KB/s",
        "status_downloading": "Downloading: {filename}, Progress: {progress}%",
        "log_start_download": "Start download: {url}",
        "log_save_to": "Save to: {path}",
        "log_threads": "Threads: {threads}, Connections: {conn}",
        "log_block_resume": "Block {part_file} resume from {start}",
        "log_block_complete": "Block {part_file} download complete",
        "log_block_failed": "Block {part_file} download failed, max retries reached",
        "log_merge_complete": "File merge complete: {path}",
        "log_pause": "Download paused",
        "log_resume": "Download resumed",
        "log_stop": "Download stopped",
        "log_task_complete": "Task complete: {path}"
    },
    "ja_JP": {
        "app_title": "マルチスレッドダウンローダー",
        "url_placeholder": "ダウンロードURLを入力",
        "browse": "参照",
        "download": "ダウンロード開始",
        "options": "ダウンロードオプション",
        "threads": "スレッド数:",
        "speed_limit": "速度制限(KB/s):",
        "conn_limit": "同時接続数:",
        "glass_effect": "ガラス効果設定",
        "blur": "ぼかし:",
        "opacity": "透明度:",
        "log": "ダウンロードログ",
        "tasks": "ダウンロードタスク",
        "status_ready": "準備完了",
        "browse_save_path": "ファイルを保存",
        "warning": "警告",
        "input_url": "ダウンロードURLを入力してください",
        "downloading": "ダウンロード中",
        "paused": "一時停止",
        "completed": "完了",
        "progress_format": "[{status}] {filename} - 進捗: {progress}% - 速度: {speed} KB/s",
        "status_downloading": "ダウンロード中: {filename}, 進捗: {progress}%",
        "log_start_download": "ダウンロード開始: {url}",
        "log_save_to": "保存先: {path}",
        "log_threads": "スレッド数: {threads}, 同時接続数: {conn}",
        "log_block_resume": "ブロック {part_file} から {start} 続行",
        "log_block_complete": "ブロック {part_file} ダウンロード完了",
        "log_block_failed": "ブロック {part_file} ダウンロード失敗、最大リトライ回数達成",
        "log_merge_complete": "ファイル統合完了: {path}",
        "log_pause": "ダウンロード一時停止",
        "log_resume": "ダウンロード再開",
        "log_stop": "ダウンロード停止",
        "log_task_complete": "タスク完了: {path}"
    }
}

class DownloadBlock:
    """表示文件的一个下载块"""
    def __init__(self, start, end, part_file):
        self.start = start
        self.end = end
        self.part_file = part_file
        self.downloaded = 0
        self.total = end - start + 1
        self.status = "等待"  # 等待, 下载中, 完成, 失败
        self.retries = 0
        self.max_retries = 3

class DownloaderCore:
    """下载核心逻辑"""
    def __init__(self, lang_translations):
        self.url = ""
        self.filename = ""
        self.save_path = ""
        self.thread_num = 8
        self.blocks = []
        self.downloaded_size = 0
        self.file_size = 0
        self.threads = []
        self.lock = threading.Lock()
        self.is_downloading = False
        self.speed_limit = 0  # 速度限制，单位: bytes/s
        self.conn_limit = 10  # 并发连接数限制
        self.semaphore = threading.Semaphore(10)  # 连接信号量
        self.pause_event = threading.Event()
        self.lang = lang_translations
        
    def set_url(self, url):
        self.url = url
        self.filename = url.split('/')[-1]
        
    def set_save_path(self, path):
        self.save_path = path
        
    def set_thread_num(self, num):
        self.thread_num = num
        if self.thread_num < 1:
            self.thread_num = 1
        elif self.thread_num > 32:
            self.thread_num = 32
            
    def set_speed_limit(self, limit):
        self.speed_limit = limit  # 单位: KB/s 转换为 B/s
        self.speed_limit *= 1024
        
    def set_conn_limit(self, limit):
        self.conn_limit = limit
        self.semaphore = threading.Semaphore(limit)
        
    def get_file_size(self):
        """获取文件总大小，支持断点续传"""
        try:
            # 先尝试获取已下载的块信息
            meta_file = os.path.join(os.path.dirname(self.save_path), f".{self.filename}.meta")
            if os.path.exists(meta_file):
                with open(meta_file, 'r') as f:
                    meta = json.load(f)
                self.file_size = meta.get('file_size', 0)
                self.downloaded_size = meta.get('downloaded_size', 0)
                
                # 恢复块信息
                self.blocks = []
                for block_info in meta.get('blocks', []):
                    block = DownloadBlock(
                        block_info['start'], 
                        block_info['end'], 
                        block_info['part_file']
                    )
                    block.downloaded = block_info.get('downloaded', 0)
                    block.status = block_info.get('status', '等待')
                    self.blocks.append(block)
                logger.info(self.lang["log_start_download"].format(url=self.url))
                logger.info(self.lang["log_save_to"].format(path=self.save_path))
                logger.info(self.lang["log_threads"].format(threads=self.thread_num, conn=self.conn_limit))
                return True
                
            # 首次下载，获取文件大小
            response = requests.head(self.url, timeout=10)
            if response.status_code == 200:
                content_length = response.headers.get('Content-Length')
                if content_length:
                    self.file_size = int(content_length)
                    logger.info(self.lang["log_start_download"].format(url=self.url))
                    logger.info(self.lang["log_save_to"].format(path=self.save_path))
                    logger.info(self.lang["log_threads"].format(threads=self.thread_num, conn=self.conn_limit))
                    return True
            return False
        except Exception as e:
            logger.error(f"获取文件大小失败: {str(e)}")
            return False
            
    def split_blocks(self):
        """分割文件块，支持断点续传"""
        if self.file_size == 0:
            if not self.get_file_size():
                logger.error("无法获取文件大小，无法分块")
                return False
                
        # 如果已有块信息，直接使用
        if self.blocks:
            return True
            
        block_size = math.ceil(self.file_size / self.thread_num)
        self.blocks = []
        
        for i in range(self.thread_num):
            start = i * block_size
            end = min(start + block_size - 1, self.file_size - 1)
            part_file = f"{self.save_path}.part{i}"
            self.blocks.append(DownloadBlock(start, end, part_file))
            
        # 保存元数据用于断点续传
        self.save_meta_data()
        return True
        
    def save_meta_data(self):
        """保存下载元数据，用于断点续传"""
        if not self.blocks:
            return
            
        meta = {
            'file_size': self.file_size,
            'downloaded_size': self.downloaded_size,
            'blocks': []
        }
        
        for block in self.blocks:
            block_data = {
                'start': block.start,
                'end': block.end,
                'part_file': block.part_file,
                'downloaded': block.downloaded,
                'status': block.status
            }
            meta['blocks'].append(block_data)
            
        meta_file = os.path.join(os.path.dirname(self.save_path), f".{self.filename}.meta")
        try:
            with open(meta_file, 'w') as f:
                json.dump(meta, f)
        except Exception as e:
            logger.error(f"保存元数据失败: {str(e)}")
            
    def download_block(self, block):
        """下载单个块，包含超时处理和重试机制"""
        with self.semaphore:  # 限制并发连接数
            headers = {}
            if block.downloaded > 0:
                # 断点续传
                start = block.start + block.downloaded
                end = block.end
                headers = {'Range': f'bytes={start}-{end}'}
                logger.info(self.lang["log_block_resume"].format(part_file=block.part_file, start=start))
            else:
                start = block.start
                end = block.end
                headers = {'Range': f'bytes={start}-{end}'}
            
            block.status = "下载中"
            self.save_meta_data()
            
            retry_count = 0
            while retry_count < block.max_retries:
                try:
                    # 速度限制实现
                    start_time = time.time()
                    response = requests.get(self.url, headers=headers, stream=True, timeout=15)
                    
                    if response.status_code not in [200, 206]:
                        logger.warning(f"块下载失败，状态码: {response.status_code}")
                        block.status = "失败"
                        self.save_meta_data()
                        return
                        
                    with open(block.part_file, 'ab' if block.downloaded > 0 else 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if not self.is_downloading:
                                block.status = "暂停"
                                self.save_meta_data()
                                self.pause_event.wait()
                                continue
                                
                            if chunk:
                                f.write(chunk)
                                with self.lock:
                                    block.downloaded += len(chunk)
                                    self.downloaded_size += len(chunk)
                                    
                                # 速度限制
                                if self.speed_limit > 0:
                                    elapsed = time.time() - start_time
                                    if elapsed > 0:
                                        expected_bytes = self.speed_limit * elapsed
                                        if self.downloaded_size > expected_bytes:
                                            sleep_time = (self.downloaded_size - expected_bytes) / self.speed_limit
                                            if sleep_time > 0:
                                                time.sleep(sleep_time)
                                                start_time = time.time()
                        
                    block.status = "完成"
                    logger.info(self.lang["log_block_complete"].format(part_file=block.part_file))
                    self.save_meta_data()
                    return
                    
                except requests.exceptions.Timeout:
                    retry_count += 1
                    block.retries = retry_count
                    logger.warning(f"块下载超时，正在重试 ({retry_count}/{block.max_retries})")
                    time.sleep(2)  # 重试前等待
                except Exception as e:
                    retry_count += 1
                    block.retries = retry_count
                    logger.error(f"块下载出错: {str(e)}，正在重试 ({retry_count}/{block.max_retries})")
                    time.sleep(2)  # 重试前等待
            
            block.status = "失败"
            logger.error(self.lang["log_block_failed"].format(part_file=block.part_file))
            self.save_meta_data()
            
    def merge_blocks(self):
        """合并所有块为完整文件"""
        try:
            with open(self.save_path, 'wb') as f:
                for block in self.blocks:
                    if block.status == "完成" and os.path.exists(block.part_file):
                        with open(block.part_file, 'rb') as part:
                            f.write(part.read())
                        os.remove(block.part_file)  # 合并后删除临时文件
            
            # 删除元数据
            meta_file = os.path.join(os.path.dirname(self.save_path), f".{self.filename}.meta")
            if os.path.exists(meta_file):
                os.remove(meta_file)
                
            logger.info(self.lang["log_merge_complete"].format(path=self.save_path))
            return True
        except Exception as e:
            logger.error(f"合并文件时出错: {str(e)}")
            return False
            
    def start_download(self):
        """开始下载"""
        if self.is_downloading:
            return False
            
        if not self.url:
            logger.error(self.lang["input_url"])
            return False
            
        if not self.save_path:
            self.save_path = self.filename
            logger.warning("未设置保存路径，使用默认文件名")
            
        if not self.split_blocks():
            return False
            
        self.is_downloading = True
        self.downloaded_size = 0
        self.threads = []
        
        # 重置所有块的状态
        for block in self.blocks:
            block.status = "等待"
            block.downloaded = 0
            
        self.save_meta_data()
        
        logger.info(self.lang["log_start_download"].format(url=self.url))
        logger.info(self.lang["log_save_to"].format(path=self.save_path))
        logger.info(self.lang["log_threads"].format(threads=self.thread_num, conn=self.conn_limit))
        
        # 创建下载线程
        for block in self.blocks:
            thread = threading.Thread(target=self.download_block, args=(block,))
            self.threads.append(thread)
            thread.daemon = True
            thread.start()
            
        return True
        
    def pause_download(self):
        """暂停下载"""
        if not self.is_downloading:
            return False
            
        self.is_downloading = False
        self.pause_event.clear()
        logger.info(self.lang["log_pause"])
        return True
        
    def resume_download(self):
        """恢复下载"""
        if not self.is_downloading:
            self.is_downloading = True
            self.pause_event.set()
            logger.info(self.lang["log_resume"])
            return True
            
        return False
        
    def stop_download(self):
        """停止下载"""
        self.is_downloading = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(1.0)
                
        logger.info(self.lang["log_stop"])
        return True
        
    def is_finished(self):
        """检查是否下载完成"""
        if not self.blocks:
            return True
            
        for block in self.blocks:
            if block.status != "完成":
                return False
                
        return self.downloaded_size >= self.file_size

class DownloadThread(QThread):
    """下载线程，用于更新UI"""
    progress_updated = pyqtSignal(int, str, float, str, dict)  # 进度, 状态, 速度, 文件名, 语言
    
    def __init__(self, download_task, lang):
        super().__init__()
        self.task = download_task
        self.lang = lang
        
    def run(self):
        self.task.downloader.start_download()
        self.task.start_time = time.time()
        
        while not self.task.downloader.is_finished() and self.task.downloader.is_downloading:
            progress = int((self.task.downloader.downloaded_size / self.task.downloader.file_size) * 100) if self.task.downloader.file_size > 0 else 0
            status = self.lang["downloading"]
            
            self.task.update_speed()
            speed = self.task.download_speed / 1024  # KB/s
            
            self.progress_updated.emit(progress, status, speed, os.path.basename(self.task.save_path), self.lang)
            time.sleep(0.5)
            
        if self.task.downloader.is_finished():
            self.progress_updated.emit(100, self.lang["completed"], 0, os.path.basename(self.task.save_path), self.lang)
            if self.task.downloader.merge_blocks():
                logger.info(self.lang["log_task_complete"].format(path=self.task.save_path))
        elif not self.task.downloader.is_downloading:
            self.progress_updated.emit(progress, self.lang["paused"], self.task.download_speed / 1024, os.path.basename(self.task.save_path), self.lang)

class DownloadTask:
    """下载任务类"""
    def __init__(self, url, save_path, thread_num, lang):
        self.url = url
        self.save_path = save_path
        self.thread_num = thread_num
        self.downloader = DownloaderCore(lang)
        self.downloader.set_url(url)
        self.downloader.set_save_path(save_path)
        self.downloader.set_thread_num(thread_num)
        self.start_time = 0
        self.last_speed_update = 0
        self.bytes_downloaded_since_speed = 0
        self.download_speed = 0
        self.lang = lang
        
    def update_speed(self):
        """更新下载速度"""
        now = time.time()
        elapsed = now - self.last_speed_update
        
        if elapsed > 1:
            if elapsed > 0:
                self.download_speed = self.bytes_downloaded_since_speed / elapsed
            self.bytes_downloaded_since_speed = 0
            self.last_speed_update = now

class LogHandler(logging.Handler):
    """日志处理器，用于将日志输出到UI"""
    def __init__(self, text_edit, lang):
        super().__init__()
        self.text_edit = text_edit
        self.lang = lang
        
    def emit(self, record):
        msg = self.format(record)
        self.text_edit.append(msg)
        # 滚动到底部
        self.text_edit.ensureCursorVisible()

class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        self.current_lang = "zh_CN"
        self.init_ui()
        self.download_tasks = {}
        self.download_threads = {}
        
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle(LANGUAGES[self.current_lang]["app_title"])
        self.setMinimumSize(800, 600)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint)
        
        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 语言切换栏
        lang_bar = QHBoxLayout()
        lang_label = QLabel("语言:")
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["简体中文", "English", "日本語"])
        self.lang_combo.setCurrentIndex(0)
        self.lang_combo.currentIndexChanged.connect(self.change_language)
        lang_bar.addWidget(lang_label)
        lang_bar.addWidget(self.lang_combo)
        main_layout.addLayout(lang_bar)
        
        # 顶部控制栏
        control_bar = QHBoxLayout()
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText(LANGUAGES[self.current_lang]["url_placeholder"])
        control_bar.addWidget(self.url_input, 7)
        
        self.browse_btn = QPushButton(LANGUAGES[self.current_lang]["browse"])
        self.browse_btn.clicked.connect(self.browse_save_path)
        control_bar.addWidget(self.browse_btn, 1)
        
        self.download_btn = QPushButton(LANGUAGES[self.current_lang]["download"])
        self.download_btn.clicked.connect(self.start_download)
        control_bar.addWidget(self.download_btn, 2)
        
        main_layout.addLayout(control_bar)
        
        # 下载选项组
        options_group = QGroupBox(LANGUAGES[self.current_lang]["options"])
        options_layout = QHBoxLayout()
        
        threads_label = QLabel(LANGUAGES[self.current_lang]["threads"])
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 32)
        self.threads_spinbox.setValue(8)
        options_layout.addWidget(threads_label)
        options_layout.addWidget(self.threads_spinbox)
        
        speed_label = QLabel(LANGUAGES[self.current_lang]["speed_limit"])
        self.speed_spinbox = QSpinBox()
        self.speed_spinbox.setRange(0, 10000)
        self.speed_spinbox.setValue(0)  # 0表示无限制
        options_layout.addWidget(speed_label)
        options_layout.addWidget(self.speed_spinbox)
        
        conn_label = QLabel(LANGUAGES[self.current_lang]["conn_limit"])
        self.conn_spinbox = QSpinBox()
        self.conn_spinbox.setRange(1, 50)
        self.conn_spinbox.setValue(10)
        options_layout.addWidget(conn_label)
        options_layout.addWidget(self.conn_spinbox)
        
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # 毛玻璃效果设置
        glass_group = QGroupBox(LANGUAGES[self.current_lang]["glass_effect"])
        glass_layout = QHBoxLayout()
        
        blur_label = QLabel(LANGUAGES[self.current_lang]["blur"])
        self.blur_slider = QSlider(Qt.Horizontal)
        self.blur_slider.setRange(0, 30)
        self.blur_slider.setValue(15)
        glass_layout.addWidget(blur_label)
        glass_layout.addWidget(self.blur_slider)
        
        opacity_label = QLabel(LANGUAGES[self.current_lang]["opacity"])
        self.opacity_slider = QSlider(Qt.Horizontal)
        self.opacity_slider.setRange(100, 255)
        self.opacity_slider.setValue(200)
        glass_layout.addWidget(opacity_label)
        glass_layout.addWidget(self.opacity_slider)
        
        glass_group.setLayout(glass_layout)
        main_layout.addWidget(glass_group)
        
        # 日志显示
        log_group = QGroupBox(LANGUAGES[self.current_lang]["log"])
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_group.setLayout(QVBoxLayout())
        log_group.layout().addWidget(self.log_text)
        main_layout.addWidget(log_group)
        
        # 下载任务列表
        task_group = QGroupBox(LANGUAGES[self.current_lang]["tasks"])
        self.task_list = QListWidget()
        task_group.setLayout(QVBoxLayout())
        task_group.layout().addWidget(self.task_list)
        main_layout.addWidget(task_group)
        
        # 底部状态栏
        self.status_bar = self.statusBar()
        self.status_bar.showMessage(LANGUAGES[self.current_lang]["status_ready"])
        
        # 设置样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: rgba(255, 255, 255, 200);
                border-radius: 10px;
            }
            QGroupBox {
                border: 1px solid #cccccc;
                border-radius: 5px;
                margin-top: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: padding;
                subcontrol-position: top left;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
        """)
        
        # 配置日志处理器
        self.setup_logger()
    
    def setup_logger(self):
        """设置日志处理器"""
        global logger
        logger.handlers = []  # 清除现有处理器
        
        # 创建多语言格式化器
        formatter = MultiLanguageFormatter(LANGUAGES[self.current_lang])
        
        # 创建文件处理器
        file_handler = logging.FileHandler("downloader.log", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # 创建UI处理器
        self.log_handler = LogHandler(self.log_text, LANGUAGES[self.current_lang])
        self.log_handler.setFormatter(formatter)
        logger.addHandler(self.log_handler)
        
        logger.setLevel(logging.INFO)
    
    def change_language(self, index):
        """切换语言"""
        lang_codes = ["zh_CN", "en_US", "ja_JP"]
        self.current_lang = lang_codes[index]
        
        # 更新窗口标题
        self.setWindowTitle(LANGUAGES[self.current_lang]["app_title"])
        
        # 更新控件文本
        self.url_input.setPlaceholderText(LANGUAGES[self.current_lang]["url_placeholder"])
        self.browse_btn.setText(LANGUAGES[self.current_lang]["browse"])
        self.download_btn.setText(LANGUAGES[self.current_lang]["download"])
        
        # 更新分组标题
        self.findChild(QGroupBox, "options").setTitle(LANGUAGES[self.current_lang]["options"])
        self.findChild(QGroupBox, "glass_effect").setTitle(LANGUAGES[self.current_lang]["glass_effect"])
        self.findChild(QGroupBox, "log").setTitle(LANGUAGES[self.current_lang]["log"])
        self.findChild(QGroupBox, "tasks").setTitle(LANGUAGES[self.current_lang]["tasks"])
        
        # 更新标签文本
        for widget in self.findChildren(QLabel):
            if widget.text() in LANGUAGES[self.current_lang]:
                widget.setText(LANGUAGES[self.current_lang][widget.text()])
        
        # 更新状态栏
        self.status_bar.showMessage(LANGUAGES[self.current_lang]["status_ready"])
        
        # 重新配置日志
        self.setup_logger()
        
        # 更新任务列表中的任务显示
        for i in range(self.task_list.count()):
            item = self.task_list.item(i)
            self.update_task_item_text(i)
    
    def update_task_item_text(self, index):
        """更新任务列表项文本"""
        item = self.task_list.item(index)
        for task_id, task in self.download_tasks.items():
            if os.path.basename(task.save_path) in item.text():
                speed_text = f"{task.download_speed:.2f} KB/s" if task.download_speed > 0 else "等待中"
                item.setText(LANGUAGES[self.current_lang]["progress_format"].format(
                    status=task.downloader.lang["downloading"],
                    filename=os.path.basename(task.save_path),
                    progress=int((task.downloader.downloaded_size / task.downloader.file_size) * 100) 
                    if task.downloader.file_size > 0 else 0,
                    speed=speed_text
                ))
                break
    
    def browse_save_path(self):
        """浏览保存路径"""
        url = self.url_input.text()
        if url:
            filename = url.split('/')[-1]
            save_path, _ = QFileDialog.getSaveFileName(self, LANGUAGES[self.current_lang]["browse_save_path"], filename)
            if save_path:
                self.url_input.setText(url)  # 保持URL不变
                self.save_path = save_path
        else:
            save_path, _ = QFileDialog.getSaveFileName(self, LANGUAGES[self.current_lang]["browse_save_path"])
            if save_path:
                self.save_path = save_path
    
    def start_download(self):
        """开始下载"""
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, LANGUAGES[self.current_lang]["warning"], LANGUAGES[self.current_lang]["input_url"])
            return
            
        thread_num = self.threads_spinbox.value()
        speed_limit = self.speed_spinbox.value()
        conn_limit = self.conn_spinbox.value()
        
        filename = url.split('/')[-1]
        save_path, _ = QFileDialog.getSaveFileName(self, LANGUAGES[self.current_lang]["browse_save_path"], filename)
        if not save_path:
            return
            
        # 创建下载任务
        task = DownloadTask(url, save_path, thread_num, LANGUAGES[self.current_lang])
        task.downloader.set_speed_limit(speed_limit)
        task.downloader.set_conn_limit(conn_limit)
        
        # 创建下载线程
        thread = DownloadThread(task, LANGUAGES[self.current_lang])
        thread.progress_updated.connect(self.update_progress)
        
        # 保存任务和线程
        task_id = id(task)
        self.download_tasks[task_id] = task
        self.download_threads[task_id] = thread
        
        # 开始线程
        thread.start()
        
        # 更新UI
        self.task_list.addItem(f"[{LANGUAGES[self.current_lang]['downloading']}] {filename}")
        self.status_bar.showMessage(LANGUAGES[self.current_lang]["status_downloading"].format(
            filename=filename, progress=0
        ))
        logger.info(LANGUAGES[self.current_lang]["log_start_download"].format(url=url))
    
    def update_progress(self, progress, status, speed, filename, lang):
        """更新下载进度"""
        for i in range(self.task_list.count()):
            item = self.task_list.item(i)
            if filename in item.text():
                speed_text = f"{speed:.2f}" if speed > 0 else "等待中"
                item.setText(lang["progress_format"].format(
                    status=status,
                    filename=filename,
                    progress=progress,
                    speed=speed_text
                ))
                break
        
        self.status_bar.showMessage(lang["status_downloading"].format(
            filename=filename, progress=progress
        ))

def main():
    """主函数"""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()