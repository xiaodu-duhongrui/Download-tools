import sys
import os
import time
import math
import json
import logging
import threading
import re
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QProgressBar, QSlider, QGroupBox, QSpinBox,
                            QFileDialog, QTextEdit, QMessageBox, 
                            QListWidget, QTabWidget, QTreeWidget, 
                            QTreeWidgetItem, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtGui import QColor, QFont

# 尝试导入BT相关库
try:
    import libtorrent as lt
except ImportError:
    lt = None

# ED2K 相关库尝试
try:
    import pyed2k
except ImportError:
    pyed2k = None

# 中文翻译数据（后续可扩展为JSON加载）
LANG = {
    "app_title": "多协议下载器",
    "url_placeholder": "输入下载链接 / 磁力链接 / ED2K链接",
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
    "input_url": "请输入下载链接、磁力链接或ED2K链接",
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
    "log_task_complete": "任务完成: {path}",
    "tab_http": "HTTP/HTTPS",
    "tab_bt": "BT/磁力",
    "tab_ed2k": "ED2K",
    "bt_select_files": "选择下载文件",
    "bt_no_libtorrent": "未安装libtorrent，无法使用BT/磁力下载",
    "magnet_link": "磁力链接",
    "torrent_file": "种子文件",
    "select_torrent": "选择种子文件",
    "bt_options": "BT选项",
    "seed_ratio": "做种比率:",
    "seed_time": "做种时间(小时):",
    "download_limit": "下载限速(KB/s):",
    "upload_limit": "上传限速(KB/s):",
    "use_dht": "使用DHT网络",
    "use_lsd": "使用LSD",
    "use_upnp": "使用UPnP",
    "use_natpmp": "使用NAT-PMP",
    "ed2k_no_pyed2k": "未安装pyed2k，无法使用ED2K下载",
    "ed2k_link": "ED2K链接",
    "ed2k_search": "搜索ED2K资源",
    "ed2k_options": "ED2K选项",
    "ed2k_server": "ED2K服务器:",
    "ed2k_timeout": "连接超时(秒):",
    "ed2k_retry": "重试次数:",
    "ed2k_file_info": "ED2K文件信息",
    "ed2k_filename": "文件名:",
    "ed2k_filesize": "文件大小:",
    "ed2k_hash": "文件哈希:",
    "ed2k_download": "开始ED2K下载",
    "http_download": "开始HTTP下载",
    "bt_download": "开始BT下载",
    "parse_failed": "链接解析失败，请检查链接格式",
    "select_directory": "选择下载目录",
    "ed2k_connecting": "连接ED2K网络...",
    "bt_loading_metadata": "加载BT元数据..."
}

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("downloader.log", encoding="utf-8"),
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
        self.status = "等待"
        self.retries = 0
        self.max_retries = 3

class HttpDownloaderCore:
    """HTTP下载核心逻辑"""
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
        self.speed_limit = 0
        self.conn_limit = 10
        self.semaphore = threading.Semaphore(10)
        self.pause_event = threading.Event()
        
    def set_url(self, url):
        self.url = url
        self.filename = url.split('/')[-1]
        if self.filename.startswith("magnet:") or self.filename.startswith("ed2k:"):
            self.filename = "download"
        
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
                with open(meta_file, 'r', encoding='utf-8') as f:
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
                logger.info(LANG["log_start_download"].format(url=self.url))
                logger.info(LANG["log_save_to"].format(path=self.save_path))
                logger.info(LANG["log_threads"].format(threads=self.thread_num, conn=self.conn_limit))
                return True
                
            # 首次下载，获取文件大小
            response = requests.head(self.url, timeout=10)
            if response.status_code == 200:
                content_length = response.headers.get('Content-Length')
                if content_length:
                    self.file_size = int(content_length)
                    logger.info(LANG["log_start_download"].format(url=self.url))
                    logger.info(LANG["log_save_to"].format(path=self.save_path))
                    logger.info(LANG["log_threads"].format(threads=self.thread_num, conn=self.conn_limit))
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
            with open(meta_file, 'w', encoding='utf-8') as f:
                json.dump(meta, f)
        except Exception as e:
            logger.error(f"保存元数据失败: {str(e)}")
            
    def download_block(self, block):
        """下载单个块，包含超时处理和重试机制"""
        import requests
        with self.semaphore:  # 限制并发连接数
            headers = {}
            if block.downloaded > 0:
                # 断点续传
                start = block.start + block.downloaded
                end = block.end
                headers = {'Range': f'bytes={start}-{end}'}
                logger.info(LANG["log_block_resume"].format(part_file=block.part_file, start=start))
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
                    logger.info(LANG["log_block_complete"].format(part_file=block.part_file))
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
            logger.error(LANG["log_block_failed"].format(part_file=block.part_file))
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
                
            logger.info(LANG["log_merge_complete"].format(path=self.save_path))
            return True
        except Exception as e:
            logger.error(f"合并文件时出错: {str(e)}")
            return False
            
    def start_download(self):
        """开始下载"""
        if self.is_downloading:
            return False
            
        if not self.url:
            logger.error(LANG["input_url"])
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
        
        logger.info(LANG["log_start_download"].format(url=self.url))
        logger.info(LANG["log_save_to"].format(path=self.save_path))
        logger.info(LANG["log_threads"].format(threads=self.thread_num, conn=self.conn_limit))
        
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
        logger.info(LANG["log_pause"])
        return True
        
    def resume_download(self):
        """恢复下载"""
        if not self.is_downloading:
            self.is_downloading = True
            self.pause_event.set()
            logger.info(LANG["log_resume"])
            return True
            
        return False
        
    def stop_download(self):
        """停止下载"""
        self.is_downloading = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(1.0)
                
        logger.info(LANG["log_stop"])
        return True
        
    def is_finished(self):
        """检查是否下载完成"""
        if not self.blocks:
            return True
            
        for block in self.blocks:
            if block.status != "完成":
                return False
                
        return self.downloaded_size >= self.file_size

class BTDownloaderCore:
    """BT下载核心逻辑"""
    def __init__(self):
        self.session = None
        self.torrent_handle = None
        self.save_path = ""
        self.is_downloading = False
        self.file_size = 0
        self.downloaded_size = 0
        self.download_speed = 0
        self.upload_speed = 0
        self.progress = 0
        self.seed_ratio = 2.0
        self.seed_time = 24
        self.download_limit = 0  # 0表示无限制
        self.upload_limit = 0
        self.use_dht = True
        self.use_lsd = True
        self.use_upnp = True
        self.use_natpmp = True
        self.selected_files = []
        
    def init_session(self):
        """初始化BT会话"""
        if not lt:
            logger.error(LANG["bt_no_libtorrent"])
            return False
            
        self.session = lt.session()
        self.session.listen_on(6881, 6891)
        self.session.set_dht_enabled(self.use_dht)
        self.session.set_lsd_enabled(self.use_lsd)
        self.session.set_upnp_enabled(self.use_upnp)
        self.session.set_natpmp_enabled(self.use_natpmp)
        if self.download_limit > 0:
            self.session.set_download_limit(self.download_limit * 1024)  # KB/s 转 B/s
        if self.upload_limit > 0:
            self.session.set_upload_limit(self.upload_limit * 1024)
        return True
        
    def load_torrent(self, torrent_path=None, magnet_link=None):
        """加载种子或磁力链接"""
        if not self.init_session():
            return False
            
        try:
            if magnet_link:
                params = {
                    'save_path': self.save_path,
                    'paused': True,
                    'duplicate_is_error': True,
                    'seed_mode': 0,
                    'storage_mode': lt.storage_mode_t(2)  # 稀疏模式
                }
                self.session.add_magnet_uri(magnet_link, params)
                logger.info(LANG["log_start_download"].format(url=magnet_link))
                
            elif torrent_path:
                with open(torrent_path, 'rb') as f:
                    torrent_data = f.read()
                torrent = lt.bdecode(torrent_data)
                info = lt.torrent_info(torrent)
                params = {
                    'ti': info,
                    'save_path': self.save_path,
                    'paused': True,
                    'duplicate_is_error': True,
                    'seed_mode': 0,
                    'storage_mode': lt.storage_mode_t(2)
                }
                self.session.add_torrent(params)
                logger.info(LANG["log_start_download"].format(url=torrent_path))
                
            # 等待 torrent 加载
            time.sleep(1)
            while not self.torrent_handle and self.session.size() > 0:
                for handle in self.session.torrents():
                    if handle.status().state == lt.torrent_state.loading_metadata:
                        time.sleep(0.5)
                    else:
                        self.torrent_handle = handle
                        break
            
            if not self.torrent_handle:
                logger.error("无法加载种子文件或磁力链接")
                return False
                
            # 设置文件选择
            if self.selected_files:
                self.set_selected_files()
                
            logger.info(LANG["log_save_to"].format(path=self.save_path))
            return True
            
        except Exception as e:
            logger.error(f"加载BT任务失败: {str(e)}")
            return False
            
    def set_selected_files(self):
        """设置选择的下载文件"""
        if not self.torrent_handle:
            return
            
        file_mask = 0
        for i in self.selected_files:
            file_mask |= (1 << i)
        self.torrent_handle.select_files(file_mask)
        
    def start_download(self):
        """开始BT下载"""
        if self.is_downloading or not self.torrent_handle:
            return False
            
        self.is_downloading = True
        self.torrent_handle.resume()
        return True
        
    def pause_download(self):
        """暂停BT下载"""
        if not self.is_downloading or not self.torrent_handle:
            return False
            
        self.is_downloading = False
        self.torrent_handle.pause()
        return True
        
    def resume_download(self):
        """恢复BT下载"""
        if not self.is_downloading and self.torrent_handle:
            self.is_downloading = True
            self.torrent_handle.resume()
            return True
            
        return False
        
    def stop_download(self):
        """停止BT下载"""
        self.is_downloading = False
        if self.torrent_handle:
            self.torrent_handle.pause()
            # 保存种子状态以便后续续传
            self.save_torrent_state()
        return True
        
    def save_torrent_state(self):
        """保存BT下载状态"""
        if not self.torrent_handle:
            return
            
        try:
            state = self.torrent_handle.save_state()
            state_file = os.path.join(os.path.dirname(self.save_path), f".{self.torrent_handle.name()}.state")
            with open(state_file, 'wb') as f:
                f.write(lt.bencode(state))
        except Exception as e:
            logger.error(f"保存BT状态失败: {str(e)}")
            
    def is_finished(self):
        """检查是否下载完成"""
        if not self.torrent_handle:
            return False
            
        status = self.torrent_handle.status()
        return status.state == lt.torrent_state.seeding
    
    def update_status(self):
        """更新BT下载状态"""
        if not self.torrent_handle:
            return
            
        status = self.torrent_handle.status()
        self.file_size = status.total_size
        self.downloaded_size = status.total_done
        self.download_speed = status.download_rate / 1024  # B/s 转 KB/s
        self.upload_speed = status.upload_rate / 1024
        self.progress = int(status.progress * 100)
        
        # 检查是否达到做种条件
        if self.progress >= 100 and status.ratio >= self.seed_ratio:
            if self.seed_time > 0:
                # 记录开始做种时间
                if not hasattr(self, 'seeding_start_time'):
                    self.seeding_start_time = time.time()
                # 检查做种时间
                if time.time() - self.seeding_start_time >= self.seed_time * 3600:
                    self.stop_download()
            else:
                self.stop_download()

class ED2KDownloaderCore:
    """ED2K下载核心逻辑"""
    def __init__(self):
        self.url = ""
        self.filename = ""
        self.save_path = ""
        self.thread_num = 8
        self.blocks = []
        self.downloaded_size = 0
        self.file_size = 0
        self.file_hash = ""
        self.is_downloading = False
        self.speed_limit = 0
        self.conn_limit = 10
        self.server = "ed2k://127.0.0.1:4242"  # 默认服务器
        self.timeout = 10
        self.retry_times = 3
        self.downloader = None
        self.transfer = None
        
    def parse_ed2k_link(self, link):
        """解析ED2K链接"""
        try:
            # ED2K链接格式: ed2k://|file|文件名|文件大小|哈希|/
            match = re.match(r'ed2k://\|file\|(.*?)\|(\d+)\|([a-fA-F0-9]+)\|/', link)
            if not match:
                logger.error(LANG["parse_failed"])
                return False
                
            self.filename = match.group(1)
            self.file_size = int(match.group(2))
            self.file_hash = match.group(3)
            logger.info(f"解析ED2K链接: {self.filename}, 大小: {self.file_size} bytes")
            return True
        except Exception as e:
            logger.error(f"解析ED2K链接失败: {str(e)}")
            return False
            
    def set_server(self, server):
        """设置ED2K服务器"""
        self.server = server
        
    def set_timeout(self, timeout):
        """设置连接超时"""
        self.timeout = timeout
        
    def set_retry(self, retry):
        """设置重试次数"""
        self.retry_times = retry
        
    def set_save_path(self, path):
        """设置保存路径"""
        self.save_path = path
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
    def start_download(self):
        """开始ED2K下载"""
        if not pyed2k:
            logger.error(LANG["ed2k_no_pyed2k"])
            return False
            
        if self.is_downloading:
            return False
            
        if not self.url or not self.file_hash:
            logger.error(LANG["input_url"])
            return False
            
        if not self.save_path:
            self.save_path = self.filename
            logger.warning("未设置保存路径，使用默认文件名")
            
        try:
            # 初始化ED2K客户端
            self.downloader = pyed2k.Downloader()
            self.downloader.connect(self.server, timeout=self.timeout)
            
            # 添加下载任务
            self.transfer = self.downloader.add_transfer(
                self.file_hash, 
                self.save_path, 
                filename=self.filename,
                overwrite=True
            )
            
            self.is_downloading = True
            logger.info(LANG["log_start_download"].format(url=self.url))
            logger.info(LANG["log_save_to"].format(path=self.save_path))
            return True
            
        except Exception as e:
            logger.error(f"启动ED2K下载失败: {str(e)}")
            return False
            
    def pause_download(self):
        """暂停ED2K下载"""
        if not self.is_downloading or not self.transfer:
            return False
            
        self.transfer.pause()
        self.is_downloading = False
        logger.info(LANG["log_pause"])
        return True
        
    def resume_download(self):
        """恢复ED2K下载"""
        if not self.is_downloading and self.transfer:
            self.transfer.resume()
            self.is_downloading = True
            logger.info(LANG["log_resume"])
            return True
            
        return False
        
    def stop_download(self):
        """停止ED2K下载"""
        self.is_downloading = False
        if self.transfer:
            self.transfer.cancel()
            self.transfer = None
        if self.downloader:
            self.downloader.disconnect()
            self.downloader = None
        logger.info(LANG["log_stop"])
        return True
        
    def is_finished(self):
        """检查是否下载完成"""
        if not self.transfer:
            return False
            
        return self.transfer.is_complete()
        
    def update_status(self):
        """更新ED2K下载状态"""
        if not self.transfer:
            return
            
        self.downloaded_size = self.transfer.downloaded
        self.download_speed = self.transfer.download_speed / 1024  # B/s 转 KB/s
        if self.file_size > 0:
            self.progress = int((self.downloaded_size / self.file_size) * 100)
        else:
            self.progress = 0

class DownloadTask:
    """下载任务类"""
    def __init__(self, task_type, url, save_path):
        self.task_type = task_type  # "http", "bt", "ed2k"
        self.url = url
        self.save_path = save_path
        
        if task_type == "http":
            self.downloader = HttpDownloaderCore()
            self.downloader.set_url(url)
            self.downloader.set_save_path(save_path)
        elif task_type == "bt":
            self.downloader = BTDownloaderCore()
            self.downloader.save_path = save_path
        elif task_type == "ed2k":
            self.downloader = ED2KDownloaderCore()
            self.downloader.url = url
            self.downloader.set_save_path(save_path)
            self.downloader.parse_ed2k_link(url)
            
        self.start_time = 0
        self.last_speed_update = 0
        self.bytes_downloaded_since_speed = 0
        self.download_speed = 0
        
    def update_speed(self):
        """更新下载速度"""
        if self.task_type == "http":
            now = time.time()
            elapsed = now - self.last_speed_update
            
            if elapsed > 1:
                if elapsed > 0:
                    self.download_speed = self.bytes_downloaded_since_speed / elapsed
                self.bytes_downloaded_since_speed = 0
                self.last_speed_update = now

class DownloadThread(QThread):
    """下载线程，用于更新UI"""
    progress_updated = pyqtSignal(int, str, float, str, dict)  # 进度, 状态, 速度, 文件名, 语言
    
    def __init__(self, download_task):
        super().__init__()
        self.task = download_task
        
    def run(self):
        if self.task.task_type == "http":
            self.run_http_download()
        elif self.task.task_type == "bt":
            self.run_bt_download()
        elif self.task.task_type == "ed2k":
            self.run_ed2k_download()
    
    def run_http_download(self):
        """运行HTTP下载"""
        self.task.downloader.start_download()
        self.task.start_time = time.time()
        
        while not self.task.downloader.is_finished() and self.task.downloader.is_downloading:
            progress = int((self.task.downloader.downloaded_size / self.task.downloader.file_size) * 100) if self.task.downloader.file_size > 0 else 0
            status = LANG["downloading"]
            
            self.task.update_speed()
            speed = self.task.download_speed / 1024  # KB/s
            
            self.progress_updated.emit(progress, status, speed, os.path.basename(self.task.save_path), LANG)
            time.sleep(0.5)
            
        if self.task.downloader.is_finished():
            self.progress_updated.emit(100, LANG["completed"], 0, os.path.basename(self.task.save_path), LANG)
            if self.task.downloader.merge_blocks():
                logger.info(LANG["log_task_complete"].format(path=self.task.save_path))
        elif not self.task.downloader.is_downloading:
            self.progress_updated.emit(progress, LANG["paused"], self.task.download_speed / 1024, os.path.basename(self.task.save_path), LANG)
    
    def run_bt_download(self):
        """运行BT下载"""
        if not self.task.downloader.load_torrent(magnet_link=self.task.url if self.task.url.startswith("magnet:") else None, 
                                                torrent_path=self.task.url if not self.task.url.startswith("magnet:") else None):
            return
            
        self.task.downloader.start_download()
        self.task.start_time = time.time()
        
        while not self.task.downloader.is_finished() and self.task.downloader.is_downloading:
            self.task.downloader.update_status()
            progress = self.task.downloader.progress
            status = LANG["downloading"]
            speed = self.task.downloader.download_speed
            
            self.progress_updated.emit(progress, status, speed, self.task.downloader.torrent_handle.name() if self.task.downloader.torrent_handle else "BT任务", LANG)
            time.sleep(1)
            
        if self.task.downloader.is_finished():
            self.progress_updated.emit(100, LANG["completed"], 0, self.task.downloader.torrent_handle.name(), LANG)
            logger.info(LANG["log_task_complete"].format(path=self.task.save_path))
        elif not self.task.downloader.is_downloading:
            self.progress_updated.emit(progress, LANG["paused"], self.task.downloader.download_speed, self.task.downloader.torrent_handle.name(), LANG)
    
    def run_ed2k_download(self):
        """运行ED2K下载"""
        if not self.task.downloader.start_download():
            return
            
        self.task.start_time = time.time()
        
        while not self.task.downloader.is_finished() and self.task.downloader.is_downloading:
            self.task.downloader.update_status()
            progress = self.task.downloader.progress
            status = LANG["downloading"]
            speed = self.task.downloader.download_speed
            
            self.progress_updated.emit(progress, status, speed, self.task.downloader.filename, LANG)
            time.sleep(1)
            
        if self.task.downloader.is_finished():
            self.progress_updated.emit(100, LANG["completed"], 0, self.task.downloader.filename, LANG)
            logger.info(LANG["log_task_complete"].format(path=self.task.save_path))
        elif not self.task.downloader.is_downloading:
            self.progress_updated.emit(progress, LANG["paused"], self.task.downloader.download_speed, self.task.downloader.filename, LANG)

class LogHandler(logging.Handler):
    """日志处理器，用于将日志输出到UI"""
    def __init__(self, text_edit):
        super().__init__()
        self.text_edit = text_edit
        
    def emit(self, record):
        msg = self.format(record)
        self.text_edit.append(msg)
        self.text_edit.ensureCursorVisible()

class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.download_tasks = {}
        self.download_threads = {}
        
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle(LANG["app_title"])
        self.setMinimumSize(900, 700)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 顶部控制栏
        control_bar = QHBoxLayout()
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText(LANG["url_placeholder"])
        control_bar.addWidget(self.url_input, 7)
        
        self.browse_btn = QPushButton(LANG["browse"])
        self.browse_btn.clicked.connect(self.browse_save_path)
        control_bar.addWidget(self.browse_btn, 1)
        
        self.download_btn = QPushButton(LANG["download"])
        self.download_btn.clicked.connect(self.start_download)
        control_bar.addWidget(self.download_btn, 2)
        
        main_layout.addLayout(control_bar)
        
        # 标签页控件
        self.tab_widget = QTabWidget()
        
        # HTTP下载标签页
        http_tab = QWidget()
        http_layout = QVBoxLayout()
        
        # HTTP下载选项
        http_options = QGroupBox(LANG["options"])
        http_options_layout = QHBoxLayout()
        
        threads_label = QLabel(LANG["threads"])
        self.http_threads_spinbox = QSpinBox()
        self.http_threads_spinbox.setRange(1, 32)
        self.http_threads_spinbox.setValue(8)
        http_options_layout.addWidget(threads_label)
        http_options_layout.addWidget(self.http_threads_spinbox)
        
        speed_label = QLabel(LANG["speed_limit"])
        self.http_speed_spinbox = QSpinBox()
        self.http_speed_spinbox.setRange(0, 10000)
        self.http_speed_spinbox.setValue(0)
        http_options_layout.addWidget(speed_label)
        http_options_layout.addWidget(self.http_speed_spinbox)
        
        conn_label = QLabel(LANG["conn_limit"])
        self.http_conn_spinbox = QSpinBox()
        self.http_conn_spinbox.setRange(1, 50)
        self.http_conn_spinbox.setValue(10)
        http_options_layout.addWidget(conn_label)
        http_options_layout.addWidget(self.http_conn_spinbox)
        
        http_options.setLayout(http_options_layout)
        http_layout.addWidget(http_options)
        
        self.tab_widget.addTab(http_tab, LANG["tab_http"])
        
        # BT下载标签页
        bt_tab = QWidget()
        bt_layout = QVBoxLayout()
        
        # BT下载状态
        self.bt_available = lt is not None
        if not self.bt_available:
            bt_warning = QLabel(LANG["bt_no_libtorrent"])
            bt_warning.setStyleSheet("color: red; font-weight: bold;")
            bt_warning.setAlignment(Qt.AlignCenter)
            bt_layout.addWidget(bt_warning)
        else:
            # BT控制栏
            bt_control_bar = QHBoxLayout()
            self.bt_input = QLineEdit()
            self.bt_input.setPlaceholderText(LANG["url_placeholder"])
            bt_control_bar.addWidget(self.bt_input, 5)
            
            self.bt_magnet_btn = QPushButton(LANG["magnet_link"])
            self.bt_magnet_btn.clicked.connect(lambda: self.bt_input.setText("magnet:?xt=urn:btih:"))
            bt_control_bar.addWidget(self.bt_magnet_btn, 1)
            
            self.bt_torrent_btn = QPushButton(LANG["torrent_file"])
            self.bt_torrent_btn.clicked.connect(self.select_torrent_file)
            bt_control_bar.addWidget(self.bt_torrent_btn, 1)
            
            self.bt_browse_btn = QPushButton(LANG["browse"])
            self.bt_browse_btn.clicked.connect(lambda: self.browse_save_path("bt"))
            bt_control_bar.addWidget(self.bt_browse_btn, 1)
            
            self.bt_download_btn = QPushButton(LANG["download"])
            self.bt_download_btn.clicked.connect(self.start_bt_download)
            bt_control_bar.addWidget(self.bt_download_btn, 2)
            
            bt_layout.addLayout(bt_control_bar)
            
            # BT文件选择
            file_select_group = QGroupBox(LANG["bt_select_files"])
            self.file_tree = QTreeWidget()
            self.file_tree.setHeaderLabels(["选择", "文件名", "大小"])
            file_select_group.setLayout(QVBoxLayout())
            file_select_group.layout().addWidget(self.file_tree)
            bt_layout.addWidget(file_select_group)
            
            # BT选项
            bt_options = QGroupBox(LANG["bt_options"])
            bt_options_layout = QGridLayout()
            
            seed_ratio_label = QLabel(LANG["seed_ratio"])
            self.seed_ratio_spinbox = QDoubleSpinBox()
            self.seed_ratio_spinbox.setRange(0.1, 10.0)
            self.seed_ratio_spinbox.setValue(2.0)
            self.seed_ratio_spinbox.setSingleStep(0.1)
            bt_options_layout.addWidget(seed_ratio_label, 0, 0)
            bt_options_layout.addWidget(self.seed_ratio_spinbox, 0, 1)
            
            seed_time_label = QLabel(LANG["seed_time"])
            self.seed_time_spinbox = QSpinBox()
            self.seed_time_spinbox.setRange(0, 168)  # 0-7天
            self.seed_time_spinbox.setValue(24)
            bt_options_layout.addWidget(seed_time_label, 0, 2)
            bt_options_layout.addWidget(self.seed_time_spinbox, 0, 3)
            
            download_limit_label = QLabel(LANG["download_limit"])
            self.download_limit_spinbox = QSpinBox()
            self.download_limit_spinbox.setRange(0, 10000)
            self.download_limit_spinbox.setValue(0)
            bt_options_layout.addWidget(download_limit_label, 1, 0)
            bt_options_layout.addWidget(self.download_limit_spinbox, 1, 1)
            
            upload_limit_label = QLabel(LANG["upload_limit"])
            self.upload_limit_spinbox = QSpinBox()
            self.upload_limit_spinbox.setRange(0, 10000)
            self.upload_limit_spinbox.setValue(0)
            bt_options_layout.addWidget(upload_limit_label, 1, 2)
            bt_options_layout.addWidget(self.upload_limit_spinbox, 1, 3)
            
            self.use_dht_checkbox = QCheckBox(LANG["use_dht"])
            self.use_dht_checkbox.setChecked(True)
            bt_options_layout.addWidget(self.use_dht_checkbox, 2, 0)
            
            self.use_lsd_checkbox = QCheckBox(LANG["use_lsd"])
            self.use_lsd_checkbox.setChecked(True)
            bt_options_layout.addWidget(self.use_lsd_checkbox, 2, 1)
            
            self.use_upnp_checkbox = QCheckBox(LANG["use_upnp"])
            self.use_upnp_checkbox.setChecked(True)
            bt_options_layout.addWidget(self.use_upnp_checkbox, 2, 2)
            
            self.use_natpmp_checkbox = QCheckBox(LANG["use_natpmp"])
            self.use_natpmp_checkbox.setChecked(True)
            bt_options_layout.addWidget(self.use_natpmp_checkbox, 2, 3)
            
            bt_options.setLayout(bt_options_layout)
            bt_layout.addWidget(bt_options)
        
        self.tab_widget.addTab(bt_tab, LANG["tab_bt"])
        
        # ED2K下载标签页
        ed2k_tab = QWidget()
        ed2k_layout = QVBoxLayout()
        
        # ED2K下载状态
        self.ed2k_available = pyed2k is not None
        if not self.ed2k_available:
            ed2k_warning = QLabel(LANG["ed2k_no_pyed2k"])
            ed2k_warning.setStyleSheet("color: red; font-weight: bold;")
            ed2k_warning.setAlignment(Qt.AlignCenter)
            ed2k_layout.addWidget(ed2k_warning)
        else:
            # ED2K控制栏
            ed2k_control_bar = QHBoxLayout()
            self.ed2k_input = QLineEdit()
            self.ed2k_input.setPlaceholderText(LANG["url_placeholder"])
            ed2k_control_bar.addWidget(self.ed2k_input, 5)
            
            self.ed2k_link_btn = QPushButton(LANG["ed2k_link"])
            self.ed2k_link_btn.clicked.connect(lambda: self.ed2k_input.setText("ed2k://|file|文件名|文件大小|哈希|/"))
            ed2k_control_bar.addWidget(self.ed2k_link_btn, 1)
            
            self.ed2k_browse_btn = QPushButton(LANG["browse"])
            self.ed2k_browse_btn.clicked.connect(lambda: self.browse_save_path("ed2k"))
            ed2k_control_bar.addWidget(self.ed2k_browse_btn, 1)
            
            self.ed2k_download_btn = QPushButton(LANG["download"])
            self.ed2k_download_btn.clicked.connect(self.start_ed2k_download)
            ed2k_control_bar.addWidget(self.ed2k_download_btn, 2)
            
            ed2k_layout.addLayout(ed2k_control_bar)
            
            # ED2K文件信息
            self.ed2k_info = QGroupBox(LANG["ed2k_file_info"])
            self.ed2k_info_layout = QGridLayout()
            
            self.filename_label = QLabel(LANG["ed2k_filename"] + " -")
            self.filesize_label = QLabel(LANG["ed2k_filesize"] + " -")
            self.filehash_label = QLabel(LANG["ed2k_hash"] + " -")
            
            self.ed2k_info_layout.addWidget(QLabel(LANG["ed2k_filename"]), 0, 0)
            self.ed2k_info_layout.addWidget(self.filename_label, 0, 1)
            self.ed2k_info_layout.addWidget(QLabel(LANG["ed2k_filesize"]), 1, 0)
            self.ed2k_info_layout.addWidget(self.filesize_label, 1, 1)
            self.ed2k_info_layout.addWidget(QLabel(LANG["ed2k_hash"]), 2, 0)
            self.ed2k_info_layout.addWidget(self.filehash_label, 2, 1)
            
            self.ed2k_info.setLayout(self.ed2k_info_layout)
            ed2k_layout.addWidget(self.ed2k_info)
            
            # ED2K选项
            ed2k_options = QGroupBox(LANG["ed2k_options"])
            ed2k_options_layout = QGridLayout()
            
            server_label = QLabel(LANG["ed2k_server"])
            self.server_input = QLineEdit("ed2k://127.0.0.1:4242")
            ed2k_options_layout.addWidget(server_label, 0, 0)
            ed2k_options_layout.addWidget(self.server_input, 0, 1)
            
            timeout_label = QLabel(LANG["ed2k_timeout"])
            self.timeout_spinbox = QSpinBox()
            self.timeout_spinbox.setRange(5, 60)
            self.timeout_spinbox.setValue(10)
            ed2k_options_layout.addWidget(timeout_label, 0, 2)
            ed2k_options_layout.addWidget(self.timeout_spinbox, 0, 3)
            
            retry_label = QLabel(LANG["ed2k_retry"])
            self.retry_spinbox = QSpinBox()
            self.retry_spinbox.setRange(1, 10)
            self.retry_spinbox.setValue(3)
            ed2k_options_layout.addWidget(retry_label, 1, 0)
            ed2k_options_layout.addWidget(self.retry_spinbox, 1, 1)
            
            ed2k_options.setLayout(ed2k_options_layout)
            ed2k_layout.addWidget(ed2k_options)
        
        self.tab_widget.addTab(ed2k_tab, LANG["tab_ed2k"])
        
        main_layout.addWidget(self.tab_widget)
        
        # 日志显示
        log_group = QGroupBox(LANG["log"])
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_group.setLayout(QVBoxLayout())
        log_group.layout().addWidget(self.log_text)
        main_layout.addWidget(log_group)
        
        # 下载任务列表
        task_group = QGroupBox(LANG["tasks"])
        self.task_list = QListWidget()
        task_group.setLayout(QVBoxLayout())
        task_group.layout().addWidget(self.task_list)
        main_layout.addWidget(task_group)
        
        # 底部状态栏
        self.status_bar = self.statusBar()
        self.status_bar.showMessage(LANG["status_ready"])
        
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
            QTabWidget::pane {
                border: none;
            }
        """)
        
        # 配置日志处理器
        self.setup_logger()
    
    def setup_logger(self):
        """设置日志处理器"""
        global logger
        logger.handlers = []
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        file_handler = logging.FileHandler("downloader.log", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        self.log_handler = LogHandler(self.log_text)
        self.log_handler.setFormatter(formatter)
        logger.addHandler(self.log_handler)
        
        logger.setLevel(logging.INFO)
    
    def browse_save_path(self, task_type=""):
        """浏览保存路径"""
        if task_type in ["bt", "ed2k"]:
            url = self.bt_input.text() if task_type == "bt" else self.ed2k_input.text()
        else:
            url = self.url_input.text()
            
        if url.startswith("magnet:") or url.startswith("ed2k:"):
            filename = "download"
        else:
            filename = url.split('/')[-1]
            if not filename or filename.startswith("?"):
                filename = "download"
                
        save_path, _ = QFileDialog.getSaveFileName(self, LANG["browse_save_path"], filename)
        if save_path:
            if task_type == "bt":
                self.bt_input.setText(url)
            elif task_type == "ed2k":
                self.ed2k_input.setText(url)
            else:
                self.url_input.setText(url)
            return save_path
        return None
    
    def select_torrent_file(self):
        """选择种子文件"""
        if not self.bt_available:
            return
            
        file_path, _ = QFileDialog.getOpenFileName(self, LANG["select_torrent"], "", "Torrent Files (*.torrent)")
        if file_path:
            self.bt_input.setText(file_path)
            
            # 加载种子文件并显示文件列表
            self.load_torrent_files(file_path)
    
    def load_torrent_files(self, torrent_path):
        """加载种子文件并显示文件列表"""
        if not self.bt_available:
            return
            
        try:
            with open(torrent_path, 'rb') as f:
                torrent_data = f.read()
            torrent = lt.bdecode(torrent_data)
            info = lt.torrent_info(torrent)
            
            self.file_tree.clear()
            total_size = 0
            self.file_tree.setUpdatesEnabled(False)
            
            # 添加文件到树状视图
            for i in range(info.num_files()):
                file_path = info.file_path(i)
                file_size = info.file_size(i)
                total_size += file_size
                
                item = QTreeWidgetItem(self.file_tree)
                item.setText(0, "✓" if i == 0 else " ")  # 默认选择第一个文件
                item.setText(1, file_path)
                item.setText(2, self.format_size(file_size))
                item.setData(0, Qt.UserRole, i)  # 存储文件索引
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(0, Qt.Checked if i == 0 else Qt.Unchecked)
            
            self.file_tree.setUpdatesEnabled(True)
            self.file_tree.expandAll()
            
        except Exception as e:
            logger.error(f"加载种子文件失败: {str(e)}")
    
    def format_size(self, bytes_size):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"
    
    def get_selected_files(self):
        """获取选中的文件索引"""
        selected = []
        for i in range(self.file_tree.topLevelItemCount()):
            item = self.file_tree.topLevelItem(i)
            if item.checkState(0) == Qt.Checked:
                selected.append(item.data(0, Qt.UserRole))
        return selected
    
    def parse_url(self, url):
        """解析URL协议类型"""
        if url.startswith("http://") or url.startswith("https://"):
            return "http"
        elif url.startswith("magnet:"):
            return "bt"
        elif url.startswith("ed2k:"):
            return "ed2k"
        else:
            return None
    
    def start_download(self):
        """开始下载"""
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, LANG["warning"], LANG["input_url"])
            return
            
        protocol = self.parse_url(url)
        if not protocol:
            QMessageBox.warning(self, LANG["warning"], LANG["parse_failed"])
            return
            
        save_path = self.browse_save_path()
        if not save_path:
            return
            
        # 设置HTTP下载选项
        thread_num = self.http_threads_spinbox.value()
        speed_limit = self.http_speed_spinbox.value()
        conn_limit = self.http_conn_spinbox.value()
        
        task = DownloadTask(protocol, url, save_path)
        
        if protocol == "http":
            task.downloader.set_thread_num(thread_num)
            task.downloader.set_speed_limit(speed_limit)
            task.downloader.set_conn_limit(conn_limit)
        
        thread = DownloadThread(task)
        thread.progress_updated.connect(self.update_progress)
        
        task_id = id(task)
        self.download_tasks[task_id] = task
        self.download_threads[task_id] = thread
        
        thread.start()
        
        filename = os.path.basename(save_path)
        self.task_list.addItem(f"[{LANG['downloading']}] {filename}")
        self.status_bar.showMessage(LANG["status_downloading"].format(filename=filename, progress=0))
        logger.info(LANG["log_start_download"].format(url=url))
    
    def start_bt_download(self):
        """开始BT下载"""
        url = self.bt_input.text()
        if not url:
            QMessageBox.warning(self, LANG["warning"], LANG["input_url"])
            return
            
        save_path = self.browse_save_path("bt")
        if not save_path:
            return
            
        task = DownloadTask("bt", url, save_path)
        
        # 设置BT下载选项
        task.downloader.seed_ratio = self.seed_ratio_spinbox.value()
        task.downloader.seed_time = self.seed_time_spinbox.value()
        task.downloader.download_limit = self.download_limit_spinbox.value()
        task.downloader.upload_limit = self.upload_limit_spinbox.value()
        task.downloader.use_dht = self.use_dht_checkbox.isChecked()
        task.downloader.use_lsd = self.use_lsd_checkbox.isChecked()
        task.downloader.use_upnp = self.use_upnp_checkbox.isChecked()
        task.downloader.use_natpmp = self.use_natpmp_checkbox.isChecked()
        
        # 设置选择的文件
        task.downloader.selected_files = self.get_selected_files()
        
        thread = DownloadThread(task)
        thread.progress_updated.connect(self.update_progress)
        
        task_id = id(task)
        self.download_tasks[task_id] = task
        self.download_threads[task_id] = thread
        
        thread.start()
        
        if url.startswith("magnet:"):
            filename = "BT下载"
        else:
            filename = os.path.basename(url)
        self.task_list.addItem(f"[{LANG['downloading']}] {filename}")
        self.status_bar.showMessage(LANG["status_downloading"].format(filename=filename, progress=0))
        logger.info(LANG["log_start_download"].format(url=url))
    
    def start_ed2k_download(self):
        """开始ED2K下载"""
        if not self.ed2k_available:
            QMessageBox.warning(self, LANG["warning"], LANG["ed2k_no_pyed2k"])
            return
            
        url = self.ed2k_input.text()
        if not url or not url.startswith("ed2k:"):
            QMessageBox.warning(self, LANG["warning"], LANG["input_url"])
            return
            
        save_path = self.browse_save_path("ed2k")
        if not save_path:
            return
            
        task = DownloadTask("ed2k", url, save_path)
        
        # 设置ED2K选项
        task.downloader.set_server(self.server_input.text())
        task.downloader.set_timeout(self.timeout_spinbox.value())
        task.downloader.set_retry(self.retry_spinbox.value())
        
        thread = DownloadThread(task)
        thread.progress_updated.connect(self.update_progress)
        
        task_id = id(task)
        self.download_tasks[task_id] = task
        self.download_threads[task_id] = thread
        
        thread.start()
        
        filename = task.downloader.filename if task.downloader.filename else "ED2K下载"
        self.task_list.addItem(f"[{LANG['downloading']}] {filename}")
        self.status_bar.showMessage(LANG["status_downloading"].format(filename=filename, progress=0))
        logger.info(LANG["log_start_download"].format(url=url))
    
    def update_progress(self, progress, status, speed, filename, lang):
        """更新下载进度"""
        for i in range(self.task_list.count()):
            item = self.task_list.item(i)
            if filename in item.text():
                speed_text = f"{speed:.2f} KB/s" if speed > 0 else "等待中"
                item.setText(lang["progress_format"].format(
                    status=status,
                    filename=filename,
                    progress=progress,
                    speed=speed_text
                ))
                break
        
        self.status_bar.showMessage(lang["status_downloading"].format(filename=filename, progress=progress))

def main():
    """主函数"""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()