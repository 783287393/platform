# 停止 8501 端口上的 Streamlit 平台进程
$conns = Get-NetTCPConnection -LocalPort 8501 -State Listen -ErrorAction SilentlyContinue
if (-not $conns) {
    Write-Host "8501 端口没有正在监听的平台进程。"
    return
}
foreach ($c in $conns) {
    Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    Write-Host "已停止进程 $($c.OwningProcess)"
}
