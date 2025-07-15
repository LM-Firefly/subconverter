# 启动本地HTTP服务器用于测试转换前
# 使用方法: 在PowerShell中运行此脚本

Write-Host "正在启动本地HTTP服务器..." -ForegroundColor Green
Write-Host "服务器地址: http://localhost:8000" -ForegroundColor Cyan
Write-Host ""
Write-Host "测试转换URL:" -ForegroundColor Yellow
Write-Host "http://127.0.0.1:25500/sub?target=clash&url=http://localhost:8000/转换前&list=true&new_name=true" -ForegroundColor White
Write-Host ""
Write-Host "按 Ctrl+C 停止服务器" -ForegroundColor Red
Write-Host ""

# 启动Python HTTP服务器
python -m http.server 8000
