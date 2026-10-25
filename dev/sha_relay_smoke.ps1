$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$base=Join-Path $env:TEMP ('kh-auth-sha-relay-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $base | Out-Null
$shared=[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')
$token=Join-Path $base 'internal-token'
[IO.File]::WriteAllText($token,$shared)
$cover=Join-Path $repo 'assets\kernelhermit-default.png'
$bGood=Join-Path $base 'B-good.png'
$bBad=Join-Path $base 'B-bad.png'
Copy-Item -LiteralPath $cover -Destination $bGood
Add-Type -AssemblyName System.Drawing
$bitmap=New-Object System.Drawing.Bitmap(640,360)
$gfx=[System.Drawing.Graphics]::FromImage($bitmap)
$gfx.Clear([System.Drawing.Color]::DarkSlateBlue)
$gfx.Dispose()
$bitmap.Save($bBad,[System.Drawing.Imaging.ImageFormat]::Png)
$bitmap.Dispose()
$mcp=$null;$auth=$null;$agent=$null
function Post-Mcp($command) {
    $body=@{jsonrpc='2.0';id=7;method='tools/call';params=@{name='run_remote_powershell';arguments=@{command=$command;target_user='testagent';timeout_seconds=10}}}|ConvertTo-Json -Depth 8 -Compress
    Invoke-RestMethod -Uri 'http://127.0.0.1:41470/mcp' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 20
}
function Wait-Health($url) {
    for($i=0;$i -lt 50;$i++){try {$null=Invoke-RestMethod -Uri $url -TimeoutSec 1;return}catch{Start-Sleep -Milliseconds 150}}
    throw "Health endpoint failed: $url"
}
try {
    $env:KH_DEBUG_BIND='127.0.0.1:41470'
    $env:KH_DEBUG_ALLOWED_HOSTS='localhost:41470,127.0.0.1:41470'
    $env:KH_DEBUG_MASTER_A=$cover
    $env:KH_DEBUG_AUTH_RELAY_URL='http://127.0.0.1:41471/relay/command'
    $env:KH_DEBUG_SERVICE_TOKEN_FILE=$token
    $env:KH_DEBUG_IMAGE_DIR=Join-Path $base 'screenshots'
    Remove-Item Env:\KH_DEBUG_AUTH_URL,Env:\KH_DEBUG_PAIR_B -ErrorAction SilentlyContinue
    $mcp=Start-Process (Join-Path $repo 'target\debug\kh-debug-mcp.exe') -PassThru -WindowStyle Hidden
    Wait-Health 'http://127.0.0.1:41470/health'
    $offline=Post-Mcp 'Write-Output SHOULD_NOT_RUN'
    if($offline.result.isError -ne $true -or !$offline.result.content[0].text.Contains('AuthGate unavailable')){
        throw 'FAIL: MCP was not blocked with AuthGate stopped'
    }
    Write-Output 'AUTHGATE_ABSENT_MCP_COMMAND=BLOCKED'
    try {
        $null=Invoke-WebRequest -Uri 'http://127.0.0.1:41470/agent/login' -Method Post -ContentType 'application/json' -Body '{}' -ErrorAction Stop
        throw 'MCP has direct agent endpoint'
    } catch {
        if([int]$_.Exception.Response.StatusCode -ne 404){throw}
    }
    Write-Output 'MCP_DIRECT_AGENT_ENDPOINT=ABSENT'

    $env:KH_AUTH_BIND='127.0.0.1:41471'
    $env:KH_AUTH_API_TOKEN_FILE=$token
    $env:KH_AUTH_MCP_TOKEN_FILE=$token
    $env:KH_AUTH_MCP_MASTER_URL='http://127.0.0.1:41470/internal/master-sha256'
    $env:KH_AUTH_STATE_DIR=Join-Path $base 'auth-state'
    $env:KH_AUTH_LEASE_SECONDS='30'
    Remove-Item Env:\KH_AUTH_PYTHON,Env:\KH_AUTH_BRIDGE_SCRIPT,Env:\KH_AUTH_COVER_PNG -ErrorAction SilentlyContinue
    $auth=Start-Process (Join-Path $repo 'target\debug\kh-debug-auth.exe') -PassThru -WindowStyle Hidden
    Wait-Health 'http://127.0.0.1:41471/health'
    $bad=@{user_id='testagent';b_png_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($bBad))}|ConvertTo-Json -Compress
    try {
        $null=Invoke-RestMethod 'http://127.0.0.1:41471/agent/login' -Method Post -ContentType 'application/json' -Body $bad -ErrorAction Stop
        throw 'BAD IMAGE GRANTED TUNNEL'
    } catch {
        if([int]$_.Exception.Response.StatusCode -ne 401){throw}
    }
    Write-Output 'MISMATCHED_IMAGE=BLOCKED'
    $validHeaders=@{Authorization="Bearer $shared"}
    $digest=Invoke-RestMethod 'http://127.0.0.1:41470/internal/master-sha256' -Headers $validHeaders
    if($digest.sha256 -ne ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($cover))).Replace('-','').ToLowerInvariant())){throw 'A hash incorrect'}
    Write-Output 'AUTH_GATE_FETCHES_A_CHECKSUM=PASS'
    try {
        $null=Invoke-RestMethod 'http://127.0.0.1:41471/relay/command' -Method Post -ContentType 'application/json' -Body '{"command":"Write-Output BYPASS"}' -ErrorAction Stop
        throw 'UNAUTHORIZED COMMAND WAS ACCEPTED'
    } catch {
        if([int]$_.Exception.Response.StatusCode -ne 401){throw}
    }
    Write-Output 'UNAUTHENTICATED_RELAY_REQUEST=BLOCKED'
    $env:KH_AGENT_AUTH_URL='http://127.0.0.1:41471'
    $env:KH_AGENT_USER='testagent'
    $env:KH_AGENT_B=$bGood
    $agent=Start-Process (Join-Path $repo 'target\debug\kh-debug-agent.exe') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $base 'agent.log') -RedirectStandardError (Join-Path $base 'agent.err')
    $result=$null
    for($i=0;$i -lt 25;$i++) {
        $result=Post-Mcp 'Write-Output AUTHGATE_RELAY_OK; Write-Output $env:KH_AGENT_ROLE'
        if($result.result.isError -eq $false -and $result.result.content[0].text.Contains('AUTHGATE_RELAY_OK')){break}
        Start-Sleep -Milliseconds 200
    }
    if($result.result.isError -ne $false -or !$result.result.content[0].text.Contains('USER_SIDE_AGENT')){
        throw ('FULL RELAY FAIL: '+($result | ConvertTo-Json -Compress -Depth 6))
    }
    Write-Output 'MCP_TO_AUTHGATE_TO_USER_POWERSHELL=PASS'
    Stop-Process -Id $auth.Id -Force
    $auth=$null
    Start-Sleep -Milliseconds 350
    $blocked=Post-Mcp 'Write-Output MUST_NEVER_RUN'
    if($blocked.result.isError -ne $true){throw 'AUTH STOP DID NOT BLOCK MCP'}
    Write-Output 'AUTHGATE_KILLED_MCP_COMMAND=BLOCKED'
    for($i=0;$i -lt 15;$i++){
       if($agent.HasExited){break}
       Start-Sleep -Milliseconds 250
       $agent.Refresh()
    }
    Write-Output ('AGENT_EXITED_AFTER_AUTH_DOWN='+$agent.HasExited)
    Write-Output 'THREE_ROLE_SHA_TUNNEL_SMOKE=PASS'
} finally {
    foreach($p in @($agent,$auth,$mcp)){if($null -ne $p){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}}
    Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
}
