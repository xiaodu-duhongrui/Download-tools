import sys
import os
import time
import math
import json
import logging
import threading
import platform
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, request, jsonify
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QProgressBar, QGroupBox, QSpinBox,
                            QFileDialog, QTextEdit, QListWidget, QTabWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import requests
import re
import atexit

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s',
                    handlers=[logging.FileHandler("downloader.log"), logging.StreamHandler()])
logger = logging.getLogger("Downloader")

# 中文翻译
L = {
    "app_title": "多协议下载器", "url_placeholder": "输入下载链接", "browse": "浏览",
    "download": "开始下载", "options": "下载选项", "threads": "线程数:",
    "speed_limit": "限速(KB/s):", "conn_limit": "并发连接:", "log": "下载日志",
    "tasks": "下载任务", "status_ready": "就绪", "browse_save_path": "保存文件",
    "warning": "警告", "input_url": "请输入下载链接", "downloading": "下载中",
    "paused": "已暂停", "completed": "已完成", "progress_format": "[{0}] {1} - 进度: {2}% - 速度: {3} KB/s",
    "status_downloading": "下载中: {0}, 进度: {1}%", "tab_http": "HTTP", "tab_bt": "BT/磁力",
    "tab_ed2k": "ED2K", "bt_no_libtorrent": "未安装libtorrent", "ed2k_no_pyed2k": "未安装pyed2k",
    "browser_monitor": "浏览器监控", "monitor_started": "监控已启动", "monitor_stopped": "监控已停止"
}

# 浏览器配置
BROWSERS = {
    "chrome": {"processes": ["chrome.exe"], "dir": os.path.join(os.path.expanduser("~"), "Downloads")},
    "edge": {"processes": ["msedge.exe"], "dir": os.path.join(os.path.expanduser("~"), "Downloads")},
    "firefox": {"processes": ["firefox.exe"], "dir": os.path.join(os.path.expanduser("~"), "Downloads")}
}

class DownloadBlock:
    __slots__ = ['s', 'e', 'f', 'd', 't', 'status']
    def __init__(self, s, e, f): 
        self.s, self.e, self.f = s, e, f
        self.d, self.t = 0, e - s + 1
        self.status = "等待"

class HttpDownloader:
    __slots__ = ['url', 'fname', 'path', 'threads', 'blocks', 'dl_size', 'file_size',
                 'running', 'speed_limit', 'conn_limit', 'sema', 'pause']
    def __init__(self):
        self.url, self.fname, self.path = "", "", ""
        self.threads, self.blocks, self.dl_size, self.file_size = 8, [], 0, 0
        self.running, self.speed_limit, self.conn_limit = False, 0, 10
        self.sema = threading.Semaphore(10)
        self.pause = threading.Event()
    
    def set_opt(self, t, sl, cl):
        self.threads, self.speed_limit, self.conn_limit = t, sl * 1024, cl
        self.sema = threading.Semaphore(cl)
    
    def get_size(self):
        if not self.url: return False
        try:
            meta = self._load_meta()
            if meta:
                self.file_size, self.dl_size, self.blocks = meta
                return True
            r = requests.head(self.url, timeout=10, headers={"Range": "bytes=0-1"})
            if r.status_code == 200:
                self.file_size = int(r.headers.get('Content-Length', 0))
                return self.file_size > 0
            if r.status_code == 206:
                self.file_size = int(r.headers.get('Content-Range', '').split('/')[-1])
                return self.file_size > 0
        except: return False
    
    def _load_meta(self):
        meta_path = os.path.join(os.path.dirname(self.path), f".{os.path.basename(self.path)}.meta")
        if not os.path.exists(meta_path): return None
        try:
            with open(meta_path, 'rb') as f:
                meta = json.load(f)
            self.blocks = [DownloadBlock(b['s'], b['e'], b['f']) for b in meta['blocks']]
            return meta['size'], meta['dl'], self.blocks
        except: return None
    
    def _save_meta(self):
        meta_path = os.path.join(os.path.dirname(self.path), f".{os.path.basename(self.path)}.meta")
        blocks = [{'s': b.s, 'e': b.e, 'f': b.f, 'd': b.d, 't': b.t} for b in self.blocks]
        with open(meta_path, 'w') as f: json.dump({'size': self.file_size, 'dl': self.dl_size, 'blocks': blocks}, f)
    
    def split_blocks(self):
        if not self.file_size: return False
        if self.blocks: return True
        bs = math.ceil(self.file_size / self.threads)
        self.blocks = []
        for i in range(self.threads):
            s, e = i * bs, min((i + 1) * bs - 1, self.file_size - 1)
            self.blocks.append(DownloadBlock(s, e, f"{self.path}.part{i}"))
        self._save_meta()
        return True
    
    def download_block(self, block):
        headers = {'Range': f'bytes={block.s+block.d}-{block.e}'} if block.d else {}
        block.status = "下载中"
        self._save_meta()
        for _ in range(3):
            try:
                start = time.time()
                r = requests.get(self.url, headers=headers, stream=True, timeout=15, 
                               preload_content=False)
                if r.status_code not in [200, 206]: break
                with open(block.f, 'ab' if block.d else 'wb') as f:
                    for chunk in r.iter_content(16384):
                        if not self.running: 
                            block.status = "暂停"; self._save_meta(); self.pause.wait()
                        if chunk:
                            f.write(chunk)
                            with threading.Lock():
                                block.d += len(chunk)
                                self.dl_size += len(chunk)
                            if self.speed_limit > 0:
                                elapsed = time.time() - start
                                if self.dl_size > self.speed_limit * elapsed:
                                    time.sleep((self.dl_size - self.speed_limit * elapsed) / self.speed_limit)
                block.status = "完成"; self._save_meta(); return
            except: pass
        block.status = "失败"; self._save_meta()
    
    def merge(self):
        try:
            with open(self.path, 'wb') as f:
                for b in self.blocks:
                    if b.status == "完成" and os.path.exists(b.f):
                        with open(b.f, 'rb') as part:
                            f.write(part.read(131072))  # 128KB块读取
            for b in self.blocks:
                if os.path.exists(b.f):
                    os.remove(b.f)
            os.remove(os.path.join(os.path.dirname(self.path), f".{os.path.basename(self.path)}.meta"))
            return True
        except: return False
    
    def start(self):
        if self.running or not self.url or not self.path: return False
        if not self.get_size(): return False
        if not self.split_blocks(): return False
        self.running = True; self.dl_size = 0
        for b in self.blocks: b.d, b.status = 0, "等待"
        self._save_meta()
        threads = []
        for b in self.blocks:
            t = threading.Thread(target=self.download_block, args=(b,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads: t.join(0.1)  # 优化线程启动
        return True
    
    def pause(self):
        if not self.running: return False
        self.running = False; self.pause.clear()
        return True
    
    def resume(self):
        if self.running: return False
        self.running = True; self.pause.set()
        return True
    
    def stop(self):
        self.running = False
        for b in self.blocks: b.status = "暂停"
        self._save_meta()
    
    def is_finished(self):
        if not self.blocks: return True
        return all(b.status == "完成" for b in self.blocks) and self.dl_size >= self.file_size

class BTDownloader:
    __slots__ = ['session', 'handle', 'path', 'running', 'dl_size', 'file_size',
                 'speed', 'seed_ratio', 'seed_time']
    def __init__(self):
        self.session, self.handle, self.path = None, None, ""
        self.running, self.dl_size, self.file_size = False, 0, 0
        self.speed, self.seed_ratio, self.seed_time = 0, 2.0, 24
    
    def init_session(self):
        if not lt: return False
        self.session = lt.session()
        self.session.listen_on(6881, 6891)
        self.session.set_dht_enabled(True)
        self.session.set_alert_mask(lt.alert.category_t.all_categories)
        return True
    
    def load_torrent(self, url):
        if not self.init_session(): return False
        try:
            params = {'save_path': self.path, 'paused': True, 'storage_mode': lt.storage_mode_t(2)}
            if url.startswith("magnet:"):
                self.session.add_magnet_uri(url, params)
            else:
                with open(url, 'rb') as f: torrent = lt.bdecode(f.read())
                self.session.add_torrent({'ti': lt.torrent_info(torrent), **params})
            
            timeout = 10
            while not self.handle and self.session.size() > 0 and timeout > 0:
                for h in self.session.torrents():
                    if h.status().state != lt.torrent_state.loading_metadata:
                        self.handle = h; break
                time.sleep(0.5)
                timeout -= 0.5
            return self.handle is not None
        except: return False
    
    def start(self):
        if self.running or not self.handle: return False
        self.running = True
        self.handle.resume()
        return True
    
    def pause(self):
        if not self.running or not self.handle: return False
        self.running = False
        self.handle.pause()
        return True
    
    def stop(self):
        self.running = False
        if self.handle:
            self.handle.pause()
            state = self.handle.save_state()
            state_file = os.path.join(os.path.dirname(self.path), f".{self.handle.name()}.state")
            with open(state_file, 'wb') as f: f.write(lt.bencode(state))
    
    def is_finished(self):
        if not self.handle: return False
        return self.handle.status().state == lt.torrent_state.seeding
    
    def update(self):
        if not self.handle: return
        s = self.handle.status()
        self.dl_size, self.file_size = s.total_done, s.total_size
        self.speed = s.download_rate / 1024
        self.running = s.state != lt.torrent_state.paused

class ED2KDownloader:
    __slots__ = ['url', 'path', 'dl_size', 'file_size', 'running', 'speed',
                 'downloader', 'transfer', 'server', 'timeout', 'retry', 'fname', 'hash']
    def __init__(self):
        self.url, self.path, self.dl_size, self.file_size = "", "", 0, 0
        self.running, self.speed, self.downloader, self.transfer = False, 0, None, None
        self.server, self.timeout, self.retry = "ed2k://127.0.0.1:4242", 10, 3
        self.fname, self.hash = "", ""
    
    def parse_url(self, url):
        m = re.match(r'ed2k://\|file\|(.*?)\|(\d+)\|([a-fA-F0-9]+)\|/', url)
        if not m: return False
        self.fname, self.file_size, self.hash = m.group(1), int(m.group(2)), m.group(3)
        return True
    
    def start(self):
        if self.running or not pyed2k or not self.url: return False
        if not self.parse_url(self.url): return False
        try:
            self.downloader = pyed2k.Downloader()
            self.downloader.connect(self.server, timeout=self.timeout)
            self.transfer = self.downloader.add_transfer(self.hash, self.path, filename=self.fname)
            self.running = True
            return True
        except: return False
    
    def pause(self):
        if not self.running or not self.transfer: return False
        self.transfer.pause()
        self.running = False
        return True
    
    def stop(self):
        self.running = False
        if self.transfer: self.transfer.cancel()
        if self.downloader: self.downloader.disconnect()
    
    def is_finished(self):
        if not self.transfer: return False
        return self.transfer.is_complete()
    
    def update(self):
        if not self.transfer: return
        self.dl_size = self.transfer.downloaded
        self.speed = self.transfer.download_speed / 1024
        self.running = not self.transfer.is_paused()

class DownloadTask:
    __slots__ = ['typ', 'url', 'path', 'downloader']
    def __init__(self, typ, url, path):
        self.typ, self.url, self.path = typ, url, path
        if typ == "http":
            self.downloader = HttpDownloader()
        elif typ == "bt":
            self.downloader = BTDownloader()
        elif typ == "ed2k":
            self.downloader = ED2KDownloader()
        self.downloader.url, self.downloader.path = url, path
    
    def set_opt(self, t, sl, cl):
        if self.typ == "http":
            self.downloader.set_opt(t, sl, cl)
    
    def start(self):
        if self.typ == "http":
            return self.downloader.start()
        elif self.typ == "bt":
            return self.downloader.load_torrent(self.url) and self.downloader.start()
        elif self.typ == "ed2k":
            return self.downloader.start()
        return False
    
    def pause(self):
        if self.typ == "http":
            return self.downloader.pause()
        elif self.typ == "bt":
            return self.downloader.pause()
        elif self.typ == "ed2k":
            return self.downloader.pause()
        return False
    
    def resume(self):
        if self.typ == "http":
            return self.downloader.resume()
        elif self.typ == "bt":
            return self.downloader.resume()
        elif self.typ == "ed2k":
            return self.downloader.resume()
        return False
    
    def stop(self):
        if self.typ == "http":
            self.downloader.stop()
        elif self.typ == "bt":
            self.downloader.stop()
        elif self.typ == "ed2k":
            self.downloader.stop()
    
    def is_finished(self):
        if self.typ == "http":
            return self.downloader.is_finished()
        elif self.typ == "bt":
            return self.downloader.is_finished()
        elif self.typ == "ed2k":
            return self.downloader.is_finished()
        return True
    
    def update(self):
        if self.typ == "http":
            return self.downloader.dl_size, self.downloader.file_size, self.downloader.running
        elif self.typ == "bt":
            self.downloader.update()
            return self.downloader.dl_size, self.downloader.file_size, self.downloader.running
        elif self.typ == "ed2k":
            self.downloader.update()
            return self.downloader.dl_size, self.downloader.file_size, self.downloader.running
        return 0, 0, False

class DownloadThread(QThread):
    update = pyqtSignal(int, str, float, str)
    __slots__ = ['task']
    def __init__(self, task):
        super().__init__()
        self.task = task
    
    def run(self):
        if not self.task.start(): return
        while not self.task.is_finished():
            dl, fs, running = self.task.update()
            if not running: 
                time.sleep(0.2)
                continue
            progress = int(dl / fs * 100) if fs > 0 else 0
            status = L["downloading"] if running else L["paused"]
            self.update.emit(progress, status, self.task.downloader.speed, os.path.basename(self.task.path))
            time.sleep(0.3)
        self.update.emit(100, L["completed"], 0, os.path.basename(self.task.path))

class FileHandler(FileSystemEventHandler):
    __slots__ = ['main_window']
    def __init__(self, main_window):
        self.main_window = main_window
    
    def on_created(self, event):
        if not event.is_directory and os.path.getsize(event.src_path) > 1024:
            self.main_window.handle_download(event.src_path)

class MainWindow(QMainWindow):
    __slots__ = ['tasks', 'observer', 'monitor_running', 'url_input', 'browse_btn', 
                 'download_btn', 'threads', 'speed', 'conn', 'tabs', 'log', 'task_list',
                 'monitor_status', 'monitor_btn']
    def __init__(self):
        super().__init__()
        self.tasks = {}
        self.observer = None
        self.monitor_running = False
        self.init_ui()
        self.start_http_server()
        self.detect_browsers()
    
    def init_ui(self):
        self.setWindowTitle(L["app_title"])
        self.setMinimumSize(700, 600)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit(L["url_placeholder"])
        self.browse_btn = QPushButton(L["browse"])
        self.download_btn = QPushButton(L["download"])
        url_layout.addWidget(self.url_input, 7)
        url_layout.addWidget(self.browse_btn, 1)
        url_layout.addWidget(self.download_btn, 2)
        layout.addLayout(url_layout)
        
        opt_layout = QHBoxLayout()
        self.threads = QSpinBox(); self.threads.setRange(1, 32); self.threads.setValue(8)
        self.speed = QSpinBox(); self.speed.setRange(0, 10000); self.speed.setValue(0)
        self.conn = QSpinBox(); self.conn.setRange(1, 50); self.conn.setValue(10)
        opt_layout.addWidget(QLabel(L["threads"])); opt_layout.addWidget(self.threads)
        opt_layout.addWidget(QLabel(L["speed_limit"])); opt_layout.addWidget(self.speed)
        opt_layout.addWidget(QLabel(L["conn_limit"])); opt_layout.addWidget(self.conn)
        layout.addLayout(opt_layout)
        
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        self.log = QTextEdit(); self.log.setReadOnly(True)
        layout.addWidget(QLabel(L["log"]))
        layout.addWidget(self.log)
        
        self.task_list = QListWidget()
        layout.addWidget(QLabel(L["tasks"]))
        layout.addWidget(self.task_list)
        
        monitor_layout = QHBoxLayout()
        self.monitor_status = QLabel(L["monitor_stopped"])
        self.monitor_btn = QPushButton("启动浏览器监控")
        self.monitor_btn.clicked.connect(self.toggle_monitor)
        monitor_layout.addWidget(self.monitor_status)
        monitor_layout.addWidget(self.monitor_btn)
        layout.addLayout(monitor_layout)
        
        self.download_btn.clicked.connect(self.start_download)
        self.browse_btn.clicked.connect(self.browse_path)
        
        self.setStyleSheet("""
            QMainWindow {background-color: rgba(255,255,255,200); border-radius:5px;}
            QGroupBox {border:1px solid #ccc; border-radius:5px; margin-top:5px;}
            QPushButton {background-color:#4CAF50; color:white; border-radius:5px;}
            QPushButton:hover {background-color:#45a049;}
        """)
    
    def start_http_server(self):
        app = Flask(__name__)
        @app.route('/download', methods=['POST'])
        def handle():
            data = request.json
            url, fname = data.get('url'), data.get('filename')
            if not url: return jsonify({"error": "No URL"})
            path = os.path.join(BROWSERS["chrome"]["dir"], fname or "download")
            self.add_task(url, path)
            return jsonify({"status": "ok"})
        threading.Thread(target=app.run, kwargs={"host": "127.0.0.1", "port": 5000, "debug": False}, daemon=True).start()
    
    def detect_browsers(self):
        if platform.system() != "Windows": return
        for b in BROWSERS:
            try:
                if b == "chrome":
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Google\Chrome\BLBeacon")
                    BROWSERS[b]["dir"], _ = winreg.QueryValueEx(key, "DownloadDir")
                elif b == "edge":
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Edge\BLBeacon")
                    BROWSERS[b]["dir"], _ = winreg.QueryValueEx(key, "DownloadDir")
            except: pass
    
    def toggle_monitor(self):
        if self.monitor_running:
            self.stop_monitor()
        else:
            self.start_monitor()
    
    def start_monitor(self):
        self.monitor_running = True
        self.monitor_btn.setText("停止浏览器监控")
        self.monitor_status.setText(L["monitor_started"])
        self.observer = Observer()
        for b in BROWSERS:
            d = BROWSERS[b]["dir"]
            if os.path.exists(d):
                self.observer.schedule(FileHandler(self), d, False)
        self.observer.start()
        threading.Thread(target=self.monitor_processes, daemon=True).start()
    
    def stop_monitor(self):
        self.monitor_running = False
        self.monitor_btn.setText("启动浏览器监控")
        self.monitor_status.setText(L["monitor_stopped"])
        if self.observer:
            self.observer.stop()
            self.observer = None
    
    def monitor_processes(self):
        while self.monitor_running:
            for b, info in BROWSERS.items():
                for pn in info["processes"]:
                    for proc in psutil.process_iter(['pid', 'name']):
                        if proc.info['name'].lower() == pn.lower():
                            return
            time.sleep(2)
    
    def handle_download(self, path):
        try:
            with open(path, 'rb') as f: content = f.read(4096)
            url = self.extract_url(content)
            if url:
                self.add_task(url, path)
        except: pass
    
    def extract_url(self, content):
        content = content.decode('utf-8', errors='ignore')
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
        return urls[0] if urls else None
    
    def browse_path(self):
        url = self.url_input.text()
        fname = url.split('/')[-1] if url else "download"
        path, _ = QFileDialog.getSaveFileName(self, L["browse_save_path"], fname)
        if path:
            self.url_input.setText(url)
            return path
        return None
    
    def add_task(self, url, path=None):
        typ = self.parse_url(url)
        if not typ: return
        task = DownloadTask(typ, url, path or self.browse_path())
        if not task.path: return
        task.set_opt(self.threads.value(), self.speed.value(), self.conn.value())
        thread = DownloadThread(task)
        thread.update.connect(self.update_task)
        task_id = id(task)
        self.tasks[task_id] = (task, thread)
        thread.start()
        self.task_list.addItem(f"[{L['downloading']}] {os.path.basename(task.path)}")
    
    def start_download(self):
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, L["warning"], L["input_url"])
            return
        self.add_task(url)
    
    def update_task(self, progress, status, speed, fname):
        for i in range(self.task_list.count()):
            item = self.task_list.item(i)
            if fname in item.text():
                item.setText(L["progress_format"].format(status, fname, progress, f"{speed:.2f}"))
                self.statusBar().showMessage(L["status_downloading"].format(fname, progress))
                break

    def parse_url(self, url):
        if url.startswith(('http://', 'https://')): return "http"
        if url.startswith("magnet:"): return "bt"
        if url.startswith("ed2k:"): return "ed2k"
        return None

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()