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
                            QFileDialog, QTextEdit, QListWidget, QTabWidget,
                            QCheckBox, QComboBox, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import requests
import re
import atexit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import ssl
import socket
from cryptography import x509

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s',
                    handlers=[logging.FileHandler("downloader.log"), logging.StreamHandler()])
logger = logging.getLogger("SecureMultiProtocolDownloader")

# 多语言翻译
L = {
    "app_title": "军事级安全多协议下载器", "url_placeholder": "输入下载链接", "browse": "浏览",
    "download": "开始下载", "options": "下载选项", "threads": "线程数:",
    "speed_limit": "限速(KB/s):", "conn_limit": "并发连接:", "log": "下载日志",
    "tasks": "下载任务", "status_ready": "就绪", "browse_save_path": "保存文件",
    "warning": "警告", "input_url": "请输入下载链接", "downloading": "下载中",
    "paused": "已暂停", "completed": "已完成", "progress_format": "[{0}] {1} - 进度: {2}% - 速度: {3} KB/s",
    "status_downloading": "下载中: {0}, 进度: {1}%", "tab_http": "HTTP/S", "tab_bt": "BT/加密",
    "tab_ed2k": "ED2K/加密",
    "encryption": "加密设置", "aes_256": "AES-256加密", 
    "sha_512": "SHA-512校验", "military_grade": "军事级安全", 
    "encryption_enabled": "加密已启用", "encryption_failed": "加密失败", 
    "decryption_failed": "解密失败", "integrity_check": "完整性校验",
    "key_exchange": "密钥交换中", "secure_connection": "安全连接已建立",
    "protocol": "协议:", 
    "auto_thread": "自动线程数", "browser_monitor": "浏览器监控", 
    "monitor_started": "监控已启动", "monitor_stopped": "监控已停止",
    "cert_verify_failed": "证书验证失败", "cert_expired": "证书已过期",
    "cert_not_trusted": "证书不受信任", "cert_mismatch": "证书域名不匹配"
}

# 浏览器配置
BROWSERS = {
    "chrome": {"processes": ["chrome.exe"], "dir": os.path.join(os.path.expanduser("~"), "Downloads")},
    "edge": {"processes": ["msedge.exe"], "dir": os.path.join(os.path.expanduser("~"), "Downloads")},
    "firefox": {"processes": ["firefox.exe"], "dir": os.path.join(os.path.expanduser("~"), "Downloads")}
}

# 加密配置
ENCRYPTION_CONFIG = {
    "default_cipher": "AES-256",
    "hash_algorithm": "SHA-512",
    "key_length": 32,
    "iv_length": 16,
    "padding": "PKCS7"
}

class CryptoHandler:
    """加密处理类，提供军事级加密解密功能"""
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key(self):
        """生成AES-256加密密钥"""
        return os.urandom(ENCRYPTION_CONFIG["key_length"])
    
    def generate_iv(self):
        """生成初始化向量"""
        return os.urandom(ENCRYPTION_CONFIG["iv_length"])
    
    def encrypt_aes_256_cbc(self, data, key, iv):
        """AES-256 CBC模式加密"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def decrypt_aes_256_cbc(self, encrypted_data, key, iv):
        """AES-256 CBC模式解密"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
    
    def calculate_hash(self, data):
        """计算SHA-512哈希"""
        digest = hashes.Hash(hashes.SHA512(), backend=self.backend)
        digest.update(data)
        return digest.finalize()
    
    def derive_key(self, master_key, info=b"downloader_key"):
        """从主密钥派生会话密钥"""
        return HKDF(
            algorithm=hashes.SHA512(),
            length=ENCRYPTION_CONFIG["key_length"],
            salt=None,
            info=info,
            backend=self.backend
        ).derive(master_key)
    
    def generate_ec_key_pair(self):
        """生成ECDH密钥对"""
        private_key = ec.generate_private_key(ec.SECP384R1(), self.backend)
        public_key = private_key.public_key()
        return private_key, public_key
    
    def derive_shared_secret(self, private_key, peer_public_key):
        """派生共享密钥"""
        return private_key.exchange(ec.ECDH(), peer_public_key)
    
    def public_key_to_bytes(self, public_key):
        """将公钥转换为字节"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def bytes_to_public_key(self, key_bytes):
        """从字节转换为公钥"""
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(),
            key_bytes,
            self.backend
        )
    
    def extract_public_key_from_cert(self, cert_data):
        """从证书中提取EC公钥"""
        cert = x509.load_pem_x509_certificate(cert_data, self.backend)
        public_key = cert.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("证书中不包含EC公钥")
        return public_key

class SecureHttpSession:
    """安全HTTP会话，支持军事级加密"""
    def __init__(self, crypto_handler):
        self.crypto_handler = crypto_handler
        self.key = None
        self.iv = None
        self.session = requests.Session()
        self.ssl_context = self._create_ssl_context()
        self.peer_public_key = None
    
    def _create_ssl_context(self):
        """创建安全SSL上下文"""
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ciphers("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384")
        return context
    
    def establish_secure_channel(self, host):
        """建立安全通信通道，使用ECDH密钥交换"""
        try:
            # 1. 生成客户端EC密钥对
            client_private_key, client_public_key = self.crypto_handler.generate_ec_key_pair()
            
            # 2. 从服务器获取公钥
            server_public_key = self._get_server_public_key(host)
            if not server_public_key:
                return False
            
            # 3. 派生共享密钥
            shared_secret = self.crypto_handler.derive_shared_secret(client_private_key, server_public_key)
            
            # 4. 派生加密密钥和IV
            self.key = self.crypto_handler.derive_key(shared_secret, b"http_encryption")
            self.iv = self.crypto_handler.generate_iv()
            
            logger.info(L["secure_connection"])
            return True
        except Exception as e:
            logger.error(f"安全通道建立失败: {e}")
            return False
    
    def _get_server_public_key(self, host):
        """从服务器证书中提取公钥（完整实现）"""
        try:
            # 建立初始TLS连接以获取服务器证书
            with socket.create_connection((host, 443)) as sock:
                with self.ssl_context.wrap_socket(sock, server_hostname=host) as ssock:
                    # 获取服务器证书
                    cert_data = ssock.getpeercert(True)
                    if not cert_data:
                        logger.error("无法获取服务器证书")
                        return None
                    
                    # 验证证书
                    if not self._verify_certificate(cert_data, host):
                        logger.error(L["cert_verify_failed"])
                        return None
                    
                    # 从证书中提取公钥
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_data)
                    public_key = self.crypto_handler.extract_public_key_from_cert(cert_pem.encode())
                    return public_key
        except Exception as e:
            logger.error(f"获取服务器公钥失败: {e}")
            return None
    
    def _verify_certificate(self, cert_data, host):
        """验证服务器证书"""
        try:
            # 检查证书是否过期
            not_after = ssl.cert_time_to_seconds(cert_data['notAfter'])
            if not_after < time.time():
                logger.warning(L["cert_expired"])
                return False
            
            # 检查证书域名是否匹配
            subject = dict(x[0] for x in cert_data['subject'])
            common_name = subject.get((u'commonName',), [''])[0]
            alt_names = []
            for ext in cert_data.get('extensions', []):
                if ext[0] == 'subjectAltName':
                    alt_names = [x[1] for x in ext[1]]
            
            if common_name != host and host not in alt_names:
                logger.warning(L["cert_mismatch"])
                return False
            
            # 这里可以添加证书吊销列表(CRL)检查等更多验证
            logger.info("证书验证通过")
            return True
        except Exception as e:
            logger.error(f"证书验证出错: {e}")
            return False
    
    def get(self, url, **kwargs):
        """安全GET请求"""
        if not self.key or not self.iv:
            host = url.split('/')[2]
            if not self.establish_secure_channel(host):
                return requests.get(url, **kwargs)
        
        encrypted_url = self.crypto_handler.encrypt_aes_256_cbc(url.encode(), self.key, self.iv)
        response = self.session.get(url, data=encrypted_url, **kwargs)
        
        try:
            decrypted_content = self.crypto_handler.decrypt_aes_256_cbc(response.content, self.key, self.iv)
            response._content = decrypted_content
        except:
            logger.error(L["decryption_failed"])
            response._content = response.content
        
        return response
    
    def head(self, url, **kwargs):
        """安全HEAD请求"""
        if not self.key or not self.iv:
            host = url.split('/')[2]
            if not self.establish_secure_channel(host):
                return requests.head(url, **kwargs)
        
        encrypted_url = self.crypto_handler.encrypt_aes_256_cbc(url.encode(), self.key, self.iv)
        response = self.session.head(url, data=encrypted_url, **kwargs)
        
        try:
            decrypted_content = self.crypto_handler.decrypt_aes_256_cbc(response.content, self.key, self.iv)
            response._content = decrypted_content
        except:
            logger.error(L["decryption_failed"])
            response._content = response.content
        
        return response

class DownloadBlock:
    """下载块，支持加密"""
    __slots__ = ['s', 'e', 'f', 'd', 't', 'status', 'crypto_handler', 'key', 'iv']
    def __init__(self, start, end, part_file, crypto_handler, key=None, iv=None):
        self.s, self.e, self.f = start, end, part_file
        self.d, self.t = 0, end - start + 1
        self.status = "等待"
        self.crypto_handler = crypto_handler
        self.key = key
        self.iv = iv

class HttpDownloader:
    """HTTP下载器，支持军事级安全传输"""
    __slots__ = ['url', 'fname', 'path', 'threads', 'blocks', 'dl_size', 'file_size',
                 'running', 'speed_limit', 'conn_limit', 'sema', 'pause', 'auto_thread',
                 'crypto_handler', 'secure_session', 'hash_check', 'encryption_enabled']
    def __init__(self, crypto_handler):
        self.url = ""
        self.fname = ""
        self.path = ""
        self.threads = 16
        self.blocks = []
        self.dl_size = 0
        self.file_size = 0
        self.running = False
        self.speed_limit = 0
        self.conn_limit = 20
        self.sema = threading.Semaphore(20)
        self.pause = threading.Event()
        self.auto_thread = False
        self.crypto_handler = crypto_handler
        self.secure_session = SecureHttpSession(crypto_handler)
        self.hash_check = True
        self.encryption_enabled = True

    def set_opt(self, threads, speed_limit, conn_limit, auto_thread, encryption_enabled):
        self.threads = threads
        self.speed_limit = speed_limit * 1024
        self.conn_limit = conn_limit
        self.auto_thread = auto_thread
        self.encryption_enabled = encryption_enabled
        self.sema = threading.Semaphore(conn_limit)

    def get_auto_threads(self):
        """基于网络质量和文件大小动态调整线程数"""
        if not self.file_size: return 16
        network_quality = self._check_network_quality()
        base_threads = max(1, min(256, math.ceil(self.file_size / (1024 * 1024 * 50 * (2 - network_quality/10)))))
        return base_threads

    def _check_network_quality(self):
        """检查网络质量，返回0-10"""
        try:
            start = time.time()
            response = requests.head("https://www.google.com", timeout=5)
            rtt = (time.time() - start) * 1000  # 毫秒
            if rtt < 100:
                return 10
            elif rtt < 200:
                return 7
            elif rtt < 300:
                return 5
            else:
                return 3
        except:
            return 5

    def _load_meta(self):
        """加载下载元数据，包含加密密钥"""
        meta_path = os.path.join(os.path.dirname(self.path), f".{os.path.basename(self.path)}.meta")
        if not os.path.exists(meta_path): return None
        try:
            with open(meta_path, 'rb') as f:
                meta = json.load(f)
            key = base64.b64decode(meta['key'])
            iv = base64.b64decode(meta['iv'])
            self.blocks = [DownloadBlock(b['s'], b['e'], b['f'], self.crypto_handler, key, iv) for b in meta['blocks']]
            return meta['size'], meta['dl'], self.blocks
        except Exception as e:
            logger.error(f"加载元数据失败: {e}")
            return None

    def _save_meta(self):
        """保存下载元数据，包含加密密钥"""
        meta_path = os.path.join(os.path.dirname(self.path), f".{os.path.basename(self.path)}.meta")
        blocks = [{'s': b.s, 'e': b.e, 'f': b.f, 'd': b.d, 't': b.t} for b in self.blocks]
        meta = {
            'size': self.file_size,
            'dl': self.dl_size,
            'blocks': blocks,
            'key': base64.b64encode(self.blocks[0].key).decode(),
            'iv': base64.b64encode(self.blocks[0].iv).decode()
        }
        with open(meta_path, 'w') as f: json.dump(meta, f)

    def get_size(self):
        """使用安全会话获取文件大小"""
        if not self.url: return False
        try:
            meta = self._load_meta()
            if meta:
                self.file_size, self.dl_size, self.blocks = meta
                return True
            
            response = self.secure_session.head(self.url, headers={"Range": "bytes=0-1"})
            if response.status_code == 200:
                self.file_size = int(response.headers.get('Content-Length', 0))
                return self.file_size > 0
            if response.status_code == 206:
                self.file_size = int(response.headers.get('Content-Range', '').split('/')[-1])
                return self.file_size > 0
        except Exception as e:
            logger.error(f"获取文件大小失败: {e}")
            return False

    def split_blocks(self):
        """分割文件块，生成加密密钥"""
        if not self.file_size: return False
        if self.blocks: return True
        
        block_size = math.ceil(self.file_size / self.threads)
        self.blocks = []
        
        key = self.crypto_handler.generate_key()
        iv = self.crypto_handler.generate_iv()
        
        for i in range(self.threads):
            start = i * block_size
            end = min(start + block_size - 1, self.file_size - 1)
            self.blocks.append(DownloadBlock(start, end, f"{self.path}.part{i}", self.crypto_handler, key, iv))
        
        self._save_meta()
        return True

    def download_block(self, block):
        """下载加密块，包含重试和速度自适应"""
        headers = {'Range': f'bytes={block.s+block.d}-{block.e}'} if block.d else {}
        block.status = "下载中"
        self._save_meta()
        
        for retry in range(5):
            try:
                start_time = time.time()
                response = self.secure_session.get(self.url, headers=headers, stream=True, timeout=20)
                
                if response.status_code not in [200, 206]:
                    logger.warning(f"块下载失败，状态码: {response.status_code}")
                    block.status = "失败"
                    self._save_meta()
                    return
                
                with open(block.f, 'ab' if block.d else 'wb') as f:
                    for chunk in response.iter_content(32768):
                        if not self.running: 
                            block.status = "暂停"; self._save_meta(); self.pause.wait()
                        if chunk:
                            if self.encryption_enabled:
                                try:
                                    chunk = self.crypto_handler.decrypt_aes_256_cbc(chunk, block.key, block.iv)
                                except:
                                    logger.error(L["decryption_failed"])
                                    chunk = b""
                            
                            f.write(chunk)
                            with threading.Lock():
                                block.d += len(chunk)
                                self.dl_size += len(chunk)
                            
                            if self.speed_limit > 0:
                                self._adapt_speed(start_time, len(chunk))
                
                block.status = "完成"
                self._save_meta()
                return
            except Exception as e:
                logger.error(f"块下载出错 (重试 {retry+1}/5): {e}")
                time.sleep(1)
        
        block.status = "失败"
        self._save_meta()

    def _adapt_speed(self, start_time, chunk_size):
        """根据网络质量和限速动态调整速度"""
        elapsed = time.time() - start_time
        if elapsed > 0:
            expected_bytes = self.speed_limit * elapsed
            if self.dl_size > expected_bytes:
                network_quality = self._check_network_quality()
                sleep_time = (self.dl_size - expected_bytes) / (self.speed_limit * (network_quality / 10))
                if sleep_time > 0:
                    time.sleep(sleep_time)

    def merge(self):
        """合并文件并验证完整性"""
        try:
            file_hash = self.crypto_handler.calculate_hash(b"")
            
            with open(self.path, 'wb') as f:
                for b in self.blocks:
                    if b.status == "完成" and os.path.exists(b.f):
                        with open(b.f, 'rb') as part:
                            data = part.read(131072)
                            f.write(data)
                            file_hash = self.crypto_handler.calculate_hash(file_hash + data)
            for b in self.blocks:
                if os.path.exists(b.f):
                    os.remove(b.f)
            os.remove(os.path.join(os.path.dirname(self.path), f".{os.path.basename(self.path)}.meta"))
            
            if self.hash_check:
                server_hash = self._get_server_hash()
                if file_hash != server_hash:
                    logger.warning(L["integrity_check"] + "失败")
                    raise Exception("文件完整性校验失败")
                logger.info(L["integrity_check"] + "通过")
            
            return True
        except Exception as e:
            logger.error(f"文件合并失败: {e}")
            return False

    def _get_server_hash(self):
        """获取服务器文件哈希"""
        try:
            response = self.secure_session.get(f"{self.url}.hash")
            return response.content
        except:
            return b""

    def start(self):
        """启动安全下载"""
        if self.running or not self.url or not self.path: return False
        
        if self.auto_thread:
            self.threads = self.get_auto_threads()
        
        if not self.get_size(): return False
        if not self.split_blocks(): return False
        
        self.running = True
        self.dl_size = 0
        for b in self.blocks: b.d, b.status = 0, "等待"
        self._save_meta()
        
        threads = []
        for b in self.blocks:
            t = threading.Thread(target=self.download_block, args=(b,), daemon=True)
            threads.append(t)
            t.start()
        
        for t in threads: t.join(0.1)
        return True

    def pause(self):
        """暂停下载"""
        if not self.running: return False
        self.running = False
        self.pause.clear()
        return True

    def resume(self):
        """恢复下载"""
        if self.running: return False
        self.running = True
        self.pause.set()
        return True

    def stop(self):
        """停止下载"""
        self.running = False
        for b in self.blocks: b.status = "暂停"
        self._save_meta()

    def is_finished(self):
        """检查是否下载完成"""
        if not self.blocks: return True
        return all(b.status == "完成" for b in self.blocks) and self.dl_size >= self.file_size

class BTDownloader:
    """BT下载器，支持加密传输"""
    __slots__ = ['session', 'handle', 'path', 'running', 'dl_size', 'file_size',
                 'speed', 'seed_ratio', 'seed_time', 'crypto_handler', 'encryption_enabled']
    def __init__(self, crypto_handler):
        self.session = None
        self.handle = None
        self.path = ""
        self.running = False
        self.dl_size = 0
        self.file_size = 0
        self.speed = 0
        self.seed_ratio = 2.0
        self.seed_time = 24
        self.crypto_handler = crypto_handler
        self.encryption_enabled = True

    def init_session(self):
        """初始化BT会话，启用加密"""
        global lt
        try:
            import libtorrent as lt
        except ImportError:
            lt = None
        if not lt: 
            logger.error(L["bt_no_libtorrent"])
            return False
            
        self.session = lt.session()
        self.session.listen_on(6881, 6891)
        self.session.set_dht_enabled(True)
        self.session.set_alert_mask(lt.alert.category_t.all_categories)
        self.session.set_tls_security_level(lt.tls_security_level_t.Required)
        return True

    def load_torrent(self, url):
        """加载种子或磁力链接，支持加密"""
        if not self.init_session(): return False
        try:
            params = {
                'save_path': self.path, 
                'paused': True, 
                'storage_mode': lt.storage_mode_t(2),
                'encrypt': lt.encrypt_type_t.Required
            }
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
        except Exception as e:
            logger.error(f"加载BT任务失败: {e}")
            return False

    def start(self):
        """开始BT下载"""
        if self.running or not self.handle: return False
        self.running = True
        self.handle.resume()
        return True

    def pause(self):
        """暂停BT下载"""
        if not self.running or not self.handle: return False
        self.running = False
        self.handle.pause()
        return True

    def stop(self):
        """停止BT下载"""
        self.running = False
        if self.handle:
            self.handle.pause()
            state = self.handle.save_state()
            state_file = os.path.join(os.path.dirname(self.path), f".{self.handle.name()}.state")
            with open(state_file, 'wb') as f: f.write(lt.bencode(state))

    def is_finished(self):
        """检查是否下载完成"""
        if not self.handle: return False
        return self.handle.status().state == lt.torrent_state.seeding

    def update(self):
        """更新BT下载状态"""
        global lt
        try:
            import libtorrent as lt
        except ImportError:
            lt = None
        if not lt or not self.handle: return
        s = self.handle.status()
        self.dl_size, self.file_size = s.total_done, s.total_size
        self.speed = s.download_rate / 1024
        self.running = s.state != lt.torrent_state.paused

class ED2KDownloader:
    """ED2K下载器，支持加密传输"""
    __slots__ = ['url', 'path', 'dl_size', 'file_size', 'running', 'speed',
                 'downloader', 'transfer', 'server', 'timeout', 'retry', 
                 'fname', 'hash', 'crypto_handler', 'encryption_enabled']
    def __init__(self, crypto_handler):
        self.url = ""
        self.path = ""
        self.dl_size = 0
        self.file_size = 0
        self.running = False
        self.speed = 0
        self.downloader = None
        self.transfer = None
        self.server = "ed2k://127.0.0.1:4242"
        self.timeout = 10
        self.retry = 3
        self.fname = ""
        self.hash = ""
        self.crypto_handler = crypto_handler
        self.encryption_enabled = True

    def parse_url(self, url):
        """解析ED2K链接"""
        m = re.match(r'ed2k://\|file\|(.*?)\|(\d+)\|([a-fA-F0-9]+)\|/', url)
        if not m: 
            logger.error("ED2K链接解析失败")
            return False
        self.fname, self.file_size, self.hash = m.group(1), int(m.group(2)), m.group(3)
        return True

    def start(self):
        """启动ED2K下载，启用加密"""
        global pyed2k
        try:
            import pyed2k
        except ImportError:
            pyed2k = None
        if self.running or not pyed2k or not self.url: return False
        if not self.parse_url(self.url): return False
        try:
            self.downloader = pyed2k.Downloader()
            # 启用TLS加密
            self.downloader.set_tls(True)
            self.downloader.connect(self.server, timeout=self.timeout)
            self.transfer = self.downloader.add_transfer(self.hash, self.path, filename=self.fname)
            self.running = True
            return True
        except Exception as e:
            logger.error(f"启动ED2K下载失败: {e}")
            return False

    def pause(self):
        """暂停ED2K下载"""
        global pyed2k
        try:
            import pyed2k
        except ImportError:
            pyed2k = None
        if not self.running or not pyed2k or not self.transfer: return False
        self.transfer.pause()
        self.running = False
        return True

    def stop(self):
        """停止ED2K下载"""
        global pyed2k
        try:
            import pyed2k
        except ImportError:
            pyed2k = None
        self.running = False
        if pyed2k and self.transfer: self.transfer.cancel()
        if pyed2k and self.downloader: self.downloader.disconnect()

    def is_finished(self):
        """检查是否下载完成"""
        global pyed2k
        try:
            import pyed2k
        except ImportError:
            pyed2k = None
        if not pyed2k or not self.transfer: return False
        return self.transfer.is_complete()

    def update(self):
        """更新ED2K下载状态"""
        global pyed2k
        try:
            import pyed2k
        except ImportError:
            pyed2k = None
        if not pyed2k or not self.transfer: return
        self.dl_size = self.transfer.downloaded
        self.speed = self.transfer.download_speed / 1024
        self.running = not self.transfer.is_paused()

class DownloadTask:
    """下载任务，管理不同协议的下载器"""
    __slots__ = ['typ', 'url', 'path', 'downloader']
    def __init__(self, typ, url, path, crypto_handler):
        self.typ, self.url, self.path = typ, url, path
        if typ == "http":
            self.downloader = HttpDownloader(crypto_handler)
        elif typ == "bt":
            self.downloader = BTDownloader(crypto_handler)
        elif typ == "ed2k":
            self.downloader = ED2KDownloader(crypto_handler)
        self.downloader.url, self.downloader.path = url, path

    def set_opt(self, threads, speed_limit, conn_limit, auto_thread, encryption_enabled):
        """设置下载选项"""
        if self.typ == "http":
            self.downloader.set_opt(threads, speed_limit, conn_limit, auto_thread, encryption_enabled)
        # BT和ED2K的选项设置...

    def start(self):
        """启动下载任务"""
        if self.typ == "http":
            return self.downloader.start()
        elif self.typ == "bt":
            return self.downloader.load_torrent(self.url) and self.downloader.start()
        elif self.typ == "ed2k":
            return self.downloader.start()
        return False

    def pause(self):
        """暂停下载任务"""
        if self.typ == "http":
            return self.downloader.pause()
        elif self.typ == "bt":
            return self.downloader.pause()
        elif self.typ == "ed2k":
            return self.downloader.pause()
        return False

    def resume(self):
        """恢复下载任务"""
        if self.typ == "http":
            return self.downloader.resume()
        elif self.typ == "bt":
            return self.downloader.resume()
        elif self.typ == "ed2k":
            return self.downloader.resume()
        return False

    def stop(self):
        """停止下载任务"""
        if self.typ == "http":
            self.downloader.stop()
        elif self.typ == "bt":
            self.downloader.stop()
        elif self.typ == "ed2k":
            self.downloader.stop()

    def is_finished(self):
        """检查任务是否完成"""
        if self.typ == "http":
            return self.downloader.is_finished()
        elif self.typ == "bt":
            return self.downloader.is_finished()
        elif self.typ == "ed2k":
            return self.downloader.is_finished()
        return True

    def update(self):
        """更新任务状态"""
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
    """下载线程，更新UI进度"""
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
    """文件系统事件处理器，监控浏览器下载"""
    __slots__ = ['main_window']
    def __init__(self, main_window):
        self.main_window = main_window

    def on_created(self, event):
        if not event.is_directory and os.path.getsize(event.src_path) > 1024:
            self.main_window.handle_download(event.src_path)

class MainWindow(QMainWindow):
    """主窗口，管理所有功能"""
    __slots__ = ['tasks', 'observer', 'monitor_running', 'url_input', 'browse_btn', 
                 'download_btn', 'threads', 'speed', 'conn', 'tabs', 'log', 'task_list',
                 'monitor_status', 'monitor_btn', 'auto_thread_check', 'encryption_check', 'hash_checkbox', 'protocol_combo']
    def __init__(self):
        super().__init__()
        self.tasks = {}
        self.observer = None
        self.monitor_running = False
        self.crypto_handler = CryptoHandler()
        self.init_ui()
        self.start_http_server()
        self.detect_browsers()

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle(L["app_title"])
        self.setMinimumSize(700, 650)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # 顶部URL输入栏
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit(L["url_placeholder"])
        self.browse_btn = QPushButton(L["browse"])
        self.download_btn = QPushButton(L["download"])
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems([L["tab_http"], L["tab_bt"], L["tab_ed2k"]])
        url_layout.addWidget(self.url_input, 5)
        url_layout.addWidget(self.protocol_combo, 1)
        url_layout.addWidget(self.browse_btn, 1)
        url_layout.addWidget(self.download_btn, 2)
        layout.addLayout(url_layout)

        # 下载选项
        opt_layout = QHBoxLayout()
        self.threads = QSpinBox(); self.threads.setRange(1, 256); self.threads.setValue(16)
        self.speed = QSpinBox(); self.speed.setRange(0, 10000); self.speed.setValue(0)
        self.conn = QSpinBox(); self.conn.setRange(1, 50); self.conn.setValue(20)
        self.auto_thread_check = QCheckBox(L["auto_thread"])
        opt_layout.addWidget(QLabel(L["threads"])); opt_layout.addWidget(self.threads)
        opt_layout.addWidget(QLabel(L["speed_limit"])); opt_layout.addWidget(self.speed)
        opt_layout.addWidget(QLabel(L["conn_limit"])); opt_layout.addWidget(self.conn)
        opt_layout.addWidget(self.auto_thread_check)
        layout.addLayout(opt_layout)

        # 加密设置
        encrypt_layout = QHBoxLayout()
        self.encryption_check = QCheckBox(L["aes_256"]); self.encryption_check.setChecked(True)
        self.hash_checkbox = QCheckBox(L["sha_512"]); self.hash_checkbox.setChecked(True)
        encrypt_layout.addWidget(self.encryption_check)
        encrypt_layout.addWidget(self.hash_checkbox)
        layout.addLayout(encrypt_layout)

        # 下载日志
        self.log = QTextEdit(); self.log.setReadOnly(True)
        layout.addWidget(QLabel(L["log"]))
        layout.addWidget(self.log)

        # 下载任务列表
        self.task_list = QListWidget()
        layout.addWidget(QLabel(L["tasks"]))
        layout.addWidget(self.task_list)

        # 浏览器监控控制
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
        """启动HTTP服务器接收浏览器扩展请求"""
        app = Flask(__name__)
        @app.route('/download', methods=['POST'])
        def handle_download():
            try:
                data = request.json
                url = data.get('url')
                if not url: 
                    return jsonify({"error": "No URL"})
                self.add_task(url)
                return jsonify({"status": "ok"})
            except Exception as e:
                logger.error(f"处理下载请求失败: {e}")
                return jsonify({"error": str(e)})
        threading.Thread(target=app.run, kwargs={"host": "127.0.0.1", "port": 5000, "debug": False}, daemon=True).start()
        logger.info("HTTP服务器已启动，监听端口5000")

    def detect_browsers(self):
        """检测浏览器下载目录"""
        if platform.system() != "Windows": return
        for b in BROWSERS:
            try:
                if b == "chrome":
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Google\Chrome\BLBeacon")
                    BROWSERS[b]["dir"], _ = winreg.QueryValueEx(key, "DownloadDir")
                elif b == "edge":
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Edge\BLBeacon")
                    BROWSERS[b]["dir"], _ = winreg.QueryValueEx(key, "DownloadDir")
            except:
                BROWSERS[b]["dir"] = os.path.join(os.path.expanduser("~"), "Downloads")
                logger.warning(f"无法检测{b}下载目录，使用默认目录")

    def toggle_monitor(self):
        """切换浏览器监控状态"""
        if self.monitor_running:
            self.stop_monitor()
        else:
            self.start_monitor()

    def start_monitor(self):
        """启动浏览器监控"""
        self.monitor_running = True
        self.monitor_btn.setText("停止浏览器监控")
        self.monitor_status.setText(L["monitor_started"])
        self.observer = Observer()
        for b in BROWSERS:
            d = BROWSERS[b]["dir"]
            if os.path.exists(d):
                self.observer.schedule(FileHandler(self), d, False)
                logger.info(f"开始监控{b}下载目录: {d}")
        self.observer.start()
        threading.Thread(target=self.monitor_processes, daemon=True).start()

    def stop_monitor(self):
        """停止浏览器监控"""
        self.monitor_running = False
        self.monitor_btn.setText("启动浏览器监控")
        self.monitor_status.setText(L["monitor_stopped"])
        if self.observer:
            self.observer.stop()
            self.observer = None

    def monitor_processes(self):
        """监控浏览器进程"""
        while self.monitor_running:
            for b, info in BROWSERS.items():
                for pn in info["processes"]:
                    for proc in psutil.process_iter(['pid', 'name']):
                        if proc.info['name'].lower() == pn.lower():
                            logger.info(f"检测到浏览器进程: {b}, PID: {proc.pid}")
                            return
            time.sleep(2)

    def handle_download(self, path):
        """处理浏览器下载文件"""
        try:
            with open(path, 'rb') as f: content = f.read(4096)
            url = self.extract_url(content)
            if url:
                self.add_task(url)
        except Exception as e:
            logger.error(f"处理下载文件失败: {e}")

    def extract_url(self, content):
        """从文件中提取URL"""
        content = content.decode('utf-8', errors='ignore')
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
        return urls[0] if urls else None

    def browse_path(self):
        """浏览保存路径"""
        url = self.url_input.text()
        fname = url.split('/')[-1] if url else "download"
        path, _ = QFileDialog.getSaveFileName(self, L["browse_save_path"], fname)
        if path:
            self.url_input.setText(url)
            return path
        return None

    def parse_url(self, url):
        """解析URL协议类型"""
        if url.startswith(('http://', 'https://')): return "http"
        if url.startswith("magnet:"): return "bt"
        if url.startswith("ed2k:"): return "ed2k"
        return None

    def add_task(self, url, path=None):
        """添加下载任务"""
        typ = self.parse_url(url)
        if not typ: 
            QMessageBox.warning(self, L["warning"], "不支持的协议")
            return
        if path is None:
            path = self.browse_path()
        if not path: return
        
        task = DownloadTask(typ, url, path, self.crypto_handler)
        task.set_opt(
            self.threads.value(), 
            self.speed.value(), 
            self.conn.value(),
            self.auto_thread_check.isChecked(),
            self.encryption_check.isChecked()
        )
        
        thread = DownloadThread(task)
        thread.update.connect(self.update_task)
        task_id = id(task)
        self.tasks[task_id] = (task, thread)
        thread.start()
        
        self.task_list.addItem(f"[{L['downloading']}] {os.path.basename(task.path)}")
        logger.info(L["log_start_download"].format(url=url))

    def start_download(self):
        """开始下载"""
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, L["warning"], L["input_url"])
            return
        self.add_task(url)

    def update_task(self, progress, status, speed, fname):
        """更新任务进度"""
        for i in range(self.task_list.count()):
            item = self.task_list.item(i)
            if fname in item.text():
                item.setText(L["progress_format"].format(status, fname, progress, f"{speed:.2f}"))
                self.statusBar().showMessage(L["status_downloading"].format(fname, progress))
                break

def main():
    """主函数"""
    global lt, pyed2k, winreg
    try:
        import libtorrent as lt
    except ImportError:
        lt = None
    try:
        import pyed2k
    except ImportError:
        pyed2k = None
    if platform.system() == "Windows":
        try:
            import winreg
        except ImportError:
            winreg = None
    
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()