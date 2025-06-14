# Download-tools
多线程下载器 🚀
🌟 核心亮点特性

• ✅ 毛玻璃美学界面：现代Aero Glass设计，支持实时调节模糊度与透明度

• ⏸️ 断点续传：智能保存下载进度，中断后可从上次位置继续

• ⚙️ 精细控制：自定义线程数、下载速度限制、并发连接数

• 📊 实时监控：进度条可视化、日志系统、下载状态实时显示

• 🛡️ 稳定机制：超时自动重试、多线程安全控制、错误捕获处理

📦 版本更新日志

🆕 版本 2.0.0 (2025-06-14) - 重大升级

🌈 视觉体验重构

• 🌟 全新QT图形界面，采用毛玻璃设计风格，支持动态调整模糊度（0-30）和透明度（100-255）

• 🎨 界面元素圆角+半透明设计，适配现代UI审美，支持响应式缩放

⚙️ 功能增强

• 📌 新增完整断点续传功能：自动保存下载元数据，中断后可恢复下载

• 🔧 下载控制升级：

◦ 自定义线程数（1-32）适配不同网络环境

◦ 下载速度限制（0-10000KB/s，0为无限制）

◦ 并发连接数控制，避免服务器压力过大

• 📝 实时日志系统：界面显示+文件记录双模式，详细追踪下载状态

🧰 技术优化

• 🧵 重构多线程模型：UI与下载逻辑分离，避免界面卡顿

• 🔒 增强线程安全：信号量控制并发连接，数据同步锁机制

• 🛠️ 完善错误处理：超时重试策略、详细错误提示与恢复方案

📦 版本 1.0.0 (初始版本)

基础功能

• 🚀 多线程分块下载：默认8线程，提升大文件下载速度

• 📊 命令行进度条：实时显示下载进度与速度

• ⚙️ 基础配置：自定义线程数、保存路径

🛠️ 安装与使用

依赖环境

• 🐍 Python 3.6+

• 🧩 GUI版本：PyQt5, requests

• 🖥️ 命令行版本：requests, tqdm

安装命令
# 安装GUI版本依赖  
pip install PyQt5 requests  

# 安装命令行版本依赖（可选）  
pip install requests tqdm  
使用方法

GUI版本
python downloader_gui.py  
命令行版本
python downloader_cli.py https://example.com/file.zip --threads 8 --path ./downloads  
📝 项目特点

• 🌐 支持HTTP/HTTPS协议下载

• 🛠️ 高可配置性，适配不同网络场景

• 🛡️ 完善的错误处理与恢复机制

• 🎨 现代美观的界面设计（GUI版）

• ⚡ 轻量级实现，低资源占用

🤝 贡献指南

1. 🍴 Fork项目并创建功能分支：git checkout -b feature/amazing-feature

2. ✨ 提交更改：git commit -m 'Add some amazing feature'

3. 🚀 推送到分支：git push origin feature/amazing-feature

4. � pull request：提交Pull Request

📜 许可证

MIT License © 2025

💬 联系与反馈

如有问题或建议，欢迎在仓库提出Issue，或通过邮箱联系：your.email@example.com 📧