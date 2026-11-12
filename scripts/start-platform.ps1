# 一键启动：创建/复用 .venv -> 安装依赖 -> 初始化演示库 -> 启动 Streamlit 平台
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $venv)) {
    Write-Host "未发现虚拟环境，创建 .venv ..."
    python -m venv $venv
}

Write-Host "检查并安装依赖（requirements.txt 已固定版本）..."
& $python -m pip install -q -r (Join-Path $root "requirements.txt")

$db = Join-Path $root "data\security.db"
if (-not (Test-Path -LiteralPath $db)) {
    Write-Host "未发现数据库，写入演示样本数据（before/after + 复核记录）..."
    Push-Location $root
    & $python -m core.seed
    Pop-Location
}

Write-Host "启动漏洞管理平台：http://127.0.0.1:8501"
Push-Location $root
& $python -m streamlit run core\app.py --server.port 8501 --server.headless false --browser.gatherUsageStats false
Pop-Location
