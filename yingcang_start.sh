#!/bin/bash
# 盈仓 · 进销存管理系统 - 启动脚本

APP_DIR="/usr/share/nginx/zzb"
LOG_FILE="/usr/share/nginx/zzb/flask_app.log"

echo "正在停止旧服务..."
pkill -f "python3 yingcang_app.py" 2>/dev/null
sleep 1

echo "正在启动盈仓后端服务..."
cd "$APP_DIR"
nohup python3 yingcang_app.py > "$LOG_FILE" 2>&1 &

sleep 1
if pgrep -f "python3 yingcang_app.py" > /dev/null; then
    echo "✅ 盈仓后端服务已启动成功"
    echo "日志文件: $LOG_FILE"
else
    echo "❌ 启动失败，请查看日志: $LOG_FILE"
fi
