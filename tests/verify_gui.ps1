$exePath = Resolve-Path ".\target\debug\win_cert_checker.exe"
Write-Host "正在启动桌面 GUI 应用: $exePath"

$proc = Start-Process -FilePath $exePath -PassThru
Start-Sleep -Seconds 3

$proc.Refresh()
$pId = $proc.Id
$handle = $proc.MainWindowHandle
$title = $proc.MainWindowTitle
$isRunning = -not $proc.HasExited

Write-Host "================ GUI 验收结果 ================"
Write-Host "进程 PID: $pId"
Write-Host "主窗口句柄: $handle"
Write-Host "主窗口标题: $title"
Write-Host "进程处于活跃运行中: $isRunning"
Write-Host "============================================="

if ($isRunning) {
    Write-Host "SUCCESS: 桌面应用程序已成功在 Windows 桌面环境中启动并响应！"
    $proc.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds 2
    if (-not $proc.HasExited) {
        $proc.Kill()
    }
    Write-Host "SUCCESS: 窗口关闭流程顺利完成。"
} else {
    Write-Host "ERROR: 桌面应用程序异常退出，ExitCode: $($proc.ExitCode)"
    exit 1
}
