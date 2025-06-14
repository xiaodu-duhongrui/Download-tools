import requests
import threading
import os
import time
from tqdm import tqdm
import math

class MultiThreadDownloader:
    def __init__(self, url, save_path=None, thread_num=8):
        """
        初始化多线程下载器
        url: 下载链接
        save_path: 保存路径，默认为当前目录下的文件名
        thread_num: 线程数量，默认为8
        """
        self.url = url
        self.thread_num = thread_num
        
        # 解析文件名
        self.filename = url.split('/')[-1]
        if save_path:
            self.save_path = os.path.join(save_path, self.filename)
        else:
            self.save_path = self.filename
            
        self.file_size = 0
        self.threads = []
        self.blocks = []
        self.downloaded_size = 0
        self.lock = threading.Lock()  # 用于线程同步的锁
        
    def get_file_size(self):
        """获取文件总大小"""
        try:
            response = requests.head(self.url)
            if response.status_code == 200:
                content_length = response.headers.get('Content-Length')
                if content_length:
                    self.file_size = int(content_length)
                    return True
            return False
        except Exception as e:
            print(f"获取文件大小失败: {e}")
            return False
    
    def split_blocks(self):
        """将文件分成多个块"""
        if self.file_size == 0:
            if not self.get_file_size():
                print("无法获取文件大小，无法分块")
                return False
                
        block_size = math.ceil(self.file_size / self.thread_num)
        
        # 分块计算
        self.blocks = []
        for i in range(self.thread_num):
            start = i * block_size
            end = min(start + block_size - 1, self.file_size - 1)
            self.blocks.append((start, end, f"{self.save_path}.part{i}"))
            
        return True
    
    def download_block(self, start, end, part_file):
        """下载单个块"""
        headers = {'Range': f'bytes={start}-{end}'}
        
        try:
            with requests.get(self.url, headers=headers, stream=True) as response:
                if response.status_code == 206 or response.status_code == 200:
                    with open(part_file, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                with self.lock:
                                    self.downloaded_size += len(chunk)
                else:
                    print(f"下载块失败，状态码: {response.status_code}")
        except Exception as e:
            print(f"下载块时出错: {e}")
    
    def merge_blocks(self):
        """合并所有块为完整文件"""
        try:
            with open(self.save_path, 'wb') as f:
                for i in range(self.thread_num):
                    part_file = f"{self.save_path}.part{i}"
                    if os.path.exists(part_file):
                        with open(part_file, 'rb') as part:
                            f.write(part.read())
                        os.remove(part_file)  # 合并后删除临时文件
            print(f"文件合并完成: {self.save_path}")
        except Exception as e:
            print(f"合并文件时出错: {e}")
    
    def show_progress(self):
        """显示下载进度"""
        progress_bar = tqdm(total=self.file_size, unit='B', unit_scale=True)
        
        while self.downloaded_size < self.file_size:
            progress_bar.update(self.downloaded_size - progress_bar.n)
            time.sleep(0.5)
        
        progress_bar.close()
    
    def download(self):
        """开始下载"""
        print(f"开始下载: {self.url}")
        print(f"保存到: {self.save_path}")
        
        if not self.split_blocks():
            return False
            
        # 创建进度显示线程
        progress_thread = threading.Thread(target=self.show_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        # 创建下载线程
        for start, end, part_file in self.blocks:
            thread = threading.Thread(target=self.download_block, args=(start, end, part_file))
            self.threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in self.threads:
            thread.join()
        
        # 合并文件
        self.merge_blocks()
        print(f"下载完成! 总大小: {self.file_size / (1024 * 1024):.2f} MB")
        return True

# 使用示例
if __name__ == "__main__":
    # 替换为你要下载的文件链接
    download_url = "https://example.com/large_file.zip"
    
    # 创建下载器实例，设置线程数为5
    downloader = MultiThreadDownloader(download_url, thread_num=5)
    
    # 开始下载
    downloader.download()
