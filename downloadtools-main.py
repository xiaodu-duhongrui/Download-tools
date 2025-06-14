import sys
import os
import time
import math
import logging
import requests
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QProgressBar, QSlider, QGroupBox, QSpinBox,
                            QFileDialog, QTextEdit, QComboBox, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QByteArray
from PyQt5.QtGui import QColor, QPixmap, QPainter, QBrush, QPen, QFont
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QIcon, QGuiApplication
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QProgressBar, QFileDialog, QListWidget, QStyle, QFrame
import requests
import threading
import time
import math
import json
import atexit

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("downloader.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MultiThreadDownloader")

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
    def __init__(self):
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
        self.progress_updated = threading.Event()
        self.last_progress_time = time.time()
        self.pause_event = threading.Event()
        
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
                logger.info(f"从断点恢复，已下载: {self.downloaded_size} bytes")
                return True
                
            # 首次下载，获取文件大小
            response = requests.head(self.url, timeout=10)
            if response.status_code == 200:
                content_length = response.headers.get('Content-Length')
                if content_length:
                    self.file_size = int(content_length)
                    logger.info(f"获取文件大小: {self.file_size} bytes")
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
                logger.info(f"块 {block.part_file} 从 {start} 开始续传")
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
                    logger.info(f"块 {block.part_file} 下载完成")
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
            logger.error(f"块 {block.part_file} 下载失败，达到最大重试次数")
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
                
            logger.info(f"文件合并完成: {self.save_path}")
            return True
        except Exception as e:
            logger.error(f"合并文件时出错: {str(e)}")
            return False
            
    def start_download(self):
        """开始下载"""
        if self.is_downloading:
            return False
            
        if not self.url:
            logger.error("未设置下载URL")
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
        
        logger.info(f"开始下载: {self.url}")
        logger.info(f"保存到: {self.save_path}")
        logger.info(f"线程数: {self.thread_num}, 并发连接数: {self.conn_limit}")
        
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
        logger.info("下载已暂停")
        return True
        
    def resume_download(self):
        """恢复下载"""
        if not self.is_downloading:
            self.is_downloading = True
            self.pause_event.set()
            logger.info("下载已恢复")
            return True
            
        return False
        
    def stop_download(self):
        """停止下载"""
        self.is_downloading = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(1.0)
                
        logger.info("下载已停止")
        return True
        
    def is_finished(self):
        """检查是否下载完成"""
        if not self.blocks:
            return True
            
        for block in self.blocks:
            if block.status != "完成":
                return False
                
        return self.downloaded_size >= self.file_size

# GUI部分
class GlassEffectWidget(QWidget):
    """毛玻璃效果组件"""
    def __init__(self, parent=None, blur=15, opacity=200):
        super().__init__(parent)
        self.blur = blur
        self.opacity = opacity
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # 创建毛玻璃效果
        region = self.rect()
        pixmap = QPixmap(region.size())
        pixmap.fill(Qt.transparent)
        
        temp_painter = QPainter(&pixmap)
        temp_painter.setOpacity(0.7)  # 半透明
        temp_painter.fillRect(region, QColor(255, 255, 255, self.opacity))
        temp_painter.end()
        
        # 应用模糊效果
        effect = QGraphicsBlurEffect()
        effect.setBlurRadius(self.blur)
        pixmap = effect.renderPixmap(region.size(), pixmap.toImage())
        
        painter.drawPixmap(0, 0, pixmap)

class DownloadTask:
    """下载任务类"""
    def __init__(self, url, save_path, thread_num=8):
        self.url = url
        self.save_path = save_path
        self.thread_num = thread_num
        self.downloader = DownloaderCore()
        self.downloader.set_url(url)
        self.downloader.set_save_path(save_path)
        self.downloader.set_thread_num(thread_num)
        self.start_time = 0
        self.last_speed_update = 0
        self.bytes_downloaded_since_speed = 0
        self.download_speed = 0
        
    def update_speed(self):
        """更新下载速度"""
        now = time.time()
        elapsed = now - self.last_speed_update
        
        if elapsed > 1:
            if elapsed > 0:
                self.download_speed = self.bytes_downloaded_since_speed / elapsed
            self.bytes_downloaded_since_speed = 0
            self.last_speed_update = now

class DownloadThread(QThread):
    """下载线程，用于更新UI"""
    progress_updated = pyqtSignal(int, str, float, str)  # 进度, 状态, 速度, 文件名
    
    def __init__(self, download_task):
        super().__init__()
        self.task = download_task
        
    def run(self):
        self.task.downloader.start_download()
        self.task.start_time = time.time()
        
        while not self.task.downloader.is_finished() and self.task.downloader.is_downloading:
            progress = int((self.task.downloader.downloaded_size / self.task.downloader.file_size) * 100) if self.task.downloader.file_size > 0 else 0
            status = "下载中"
            
            self.task.update_speed()
            speed = self.task.download_speed / 1024  # KB/s
            
            self.progress_updated.emit(progress, status, speed, os.path.basename(self.task.save_path))
            time.sleep(0.5)
            
        if self.task.downloader.is_finished():
            self.progress_updated.emit(100, "已完成", 0, os.path.basename(self.task.save_path))
            if self.task.downloader.merge_blocks():
                logger.info(f"任务完成: {self.task.save_path}")
        elif not self.task.downloader.is_downloading:
            self.progress_updated.emit(progress, "已暂停", self.task.download_speed / 1024, os.path.basename(self.task.save_path))

class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.download_tasks = {}
        self.download_threads = {}
        self.glass_effect = None
        self.blur_value = 15
        self.opacity_value = 200
        self.setup_glass_effect()
        
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("多线程下载器")
        self.setMinimumSize(800, 600)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint)
        
        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 顶部控制栏
        control_bar = QHBoxLayout()
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("输入下载链接")
        control_bar.addWidget(self.url_input, 7)
        
        self.browse_btn = QPushButton("浏览")
        self.browse_btn.clicked.connect(self.browse_save_path)
        control_bar.addWidget(self.browse_btn, 1)
        
        self.download_btn = QPushButton("开始下载")
        self.download_btn.clicked.connect(self.start_download)
        control_bar.addWidget(self.download_btn, 2)
        
        main_layout.addLayout(control_bar)
        
        # 下载选项组
        options_group = QGroupBox("下载选项")
        options_layout = QHBoxLayout()
        
        threads_label = QLabel("线程数:")
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 32)
        self.threads_spinbox.setValue(8)
        options_layout.addWidget(threads_label)
        options_layout.addWidget(self.threads_spinbox)
        
        speed_label = QLabel("速度限制(KB/s):")
        self.speed_spinbox = QSpinBox()
        self.speed_spinbox.setRange(0, 10000)
        self.speed_spinbox.setValue(0)  # 0表示无限制
        options_layout.addWidget(speed_label)
        options_layout.addWidget(self.speed_spinbox)
        
        conn_label = QLabel("并发连接数:")
        self.conn_spinbox = QSpinBox()
        self.conn_spinbox.setRange(1, 50)
        self.conn_spinbox.setValue(10)
        options_layout.addWidget(conn_label)
        options_layout.addWidget(self.conn_spinbox)
        
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # 毛玻璃效果设置
        glass_group = QGroupBox("毛玻璃效果设置")
        glass_layout = QHBoxLayout()
        
        blur_label = QLabel("模糊度:")
        self.blur_slider = QSlider(Qt.Horizontal)
        self.blur_slider.setRange(0, 30)
        self.blur_slider.setValue(15)
        self.blur_slider.valueChanged.connect(self.update_glass_effect)
        glass_layout.addWidget(blur_label)
        glass_layout.addWidget(self.blur_slider)
        
        opacity_label = QLabel("透明度:")
        self.opacity_slider = QSlider(Qt.Horizontal)
        self.opacity_slider.setRange(100, 255)
        self.opacity_slider.setValue(200)
        self.opacity_slider.valueChanged.connect(self.update_glass_effect)
        glass_layout.addWidget(opacity_label)
        glass_layout.addWidget(self.opacity_slider)
        
        glass_group.setLayout(glass_layout)
        main_layout.addWidget(glass_group)
        
        # 日志显示
        log_group = QGroupBox("下载日志")
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_group.setLayout(QVBoxLayout())
        log_group.layout().addWidget(self.log_text)
        main_layout.addWidget(log_group)
        
        # 下载任务列表
        task_group = QGroupBox("下载任务")
        self.task_list = QListWidget()
        task_group.setLayout(QVBoxLayout())
        task_group.layout().addWidget(self.task_list)
        main_layout.addWidget(task_group)
        
        # 底部状态栏
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
        
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
        
        # 记录日志到UI
        self.log_handler = LogHandler(self.log_text)
        logger.addHandler(self.log_handler)
        
    def setup_glass_effect(self):
        """设置毛玻璃效果"""
        if hasattr(Qt, 'AA_UseBlurBehindWindow'):
            self.setAttribute(Qt.AA_UseBlurBehindWindow)
        else:
            # 自定义毛玻璃效果
            self.glass_effect = GlassEffectWidget(self, self.blur_value, self.opacity_value)
            self.glass_effect.resize(self.size())
            self.glass_effect.show()
    
    def update_glass_effect(self):
        """更新毛玻璃效果"""
        self.blur_value = self.blur_slider.value()
        self.opacity_value = self.opacity_slider.value()
        
        if self.glass_effect:
            self.glass_effect.blur = self.blur_value
            self.glass_effect.opacity = self.opacity_value
            self.glass_effect.update()
        else:
            self.setAttribute(Qt.AA_UseBlurBehindWindow, False)
            self.setAttribute(Qt.AA_UseBlurBehindWindow, True)
    
    def browse_save_path(self):
        """浏览保存路径"""
        url = self.url_input.text()
        if url:
            filename = url.split('/')[-1]
            save_path, _ = QFileDialog.getSaveFileName(self, "保存文件", filename)
            if save_path:
                self.url_input.setText(url)  # 保持URL不变
                self.save_path = save_path
        else:
            save_path, _ = QFileDialog.getSaveFileName(self, "保存文件")
            if save_path:
                self.save_path = save_path
    
    def start_download(self):
        """开始下载"""
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, "警告", "请输入下载链接")
            return
            
        thread_num = self.threads_spinbox.value()
        speed_limit = self.speed_spinbox.value()
        conn_limit = self.conn_spinbox.value()
        
        filename = url.split('/')[-1]
        save_path, _ = QFileDialog.getSaveFileName(self, "保存文件", filename)
        if not save_path:
            return
            
        # 创建下载任务
        task = DownloadTask(url, save_path, thread_num)
        task.downloader.set_speed_limit(speed_limit)
        task.downloader.set_conn_limit(conn_limit)
        
        # 创建下载线程
        thread = DownloadThread(task)
        thread.progress_updated.connect(self.update_progress)
        
        # 保存任务和线程
        task_id = id(task)
        self.download_tasks[task_id] = task
        self.download_threads[task_id] = thread
        
        # 开始线程
        thread.start()
        
        # 更新UI
        self.task_list.addItem(f"[下载中] {filename}")
        self.status_bar.showMessage(f"开始下载: {filename}")
        logger.info(f"新建下载任务: {url} -> {save_path}")
    
    def update_progress(self, progress, status, speed, filename):
        """更新下载进度"""
        for i in range(self.task_list.count()):
            item = self.task_list.item(i)
            if filename in item.text():
                speed_text = f"{speed:.2f} KB/s" if speed > 0 else "等待中"
                item.setText(f"[{status}] {filename} - 进度: {progress}% - 速度: {speed_text}")
                break
        
        self.status_bar.showMessage(f"下载中: {filename}, 进度: {progress}%")
    
    def closeEvent(self, event):
        """关闭窗口时停止所有下载"""
        for task_id, thread in self.download_threads.items():
            if thread.isRunning():
                self.download_tasks[task_id].downloader.stop_download()
                thread.wait(2000)  # 等待2秒
                
        event.accept()

class LogHandler(logging.Handler):
    """日志处理器，用于将日志输出到UI"""
    def __init__(self, text_edit):
        super().__init__()
        self.text_edit = text_edit
        
    def emit(self, record):
        msg = self.format(record)
        self.text_edit.append(msg)
        # 滚动到底部
        self.text_edit.ensureCursorVisible()

# 主函数
def main():
    app = QApplication(sys.argv)
    # 设置应用程序属性以启用Aero玻璃效果
    if hasattr(Qt, 'AA_UseAeroPeek'):
        QApplication.setAttribute(Qt.AA_UseAeroPeek, True)
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()