# PowerShell Web-Based GUI Alternative
# Creates a local web server that provides the GUI interface

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Restarting as Administrator..." -ForegroundColor Yellow
    Start-Process PowerShell -Verb RunAs "-File `"$PSCommandPath`""
    exit
}

Write-Host "Starting PowerShell Web GUI Server..." -ForegroundColor Green

# Create HTTP listener
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:8080/")
$listener.Start()

Write-Host "Web GUI available at: http://localhost:8080" -ForegroundColor Cyan
Write-Host "Opening browser..." -ForegroundColor Yellow

# Open browser
Start-Process "http://localhost:8080"

# HTML content with embedded CSS and JavaScript
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows System Management Tool</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', sans-serif; 
            background: #1e1e1e; 
            color: #ffffff; 
            height: 100vh; 
            display: flex; 
        }
        .sidebar { 
            width: 250px; 
            background: #2d2d30; 
            padding: 20px; 
            border-right: 1px solid #3e3e42; 
        }
        .content { 
            flex: 1; 
            padding: 20px; 
            overflow-y: auto; 
        }
        .nav-button { 
            width: 100%; 
            padding: 12px; 
            margin: 5px 0; 
            background: #404040; 
            border: none; 
            color: white; 
            border-radius: 5px; 
            cursor: pointer; 
            transition: background 0.3s; 
        }
        .nav-button:hover { background: #505050; }
        .nav-button.active { background: #007acc; }
        .panel { display: none; }
        .panel.active { display: block; }
        .action-button { 
            padding: 10px 20px; 
            margin: 10px 5px; 
            background: #007acc; 
            border: none; 
            color: white; 
            border-radius: 5px; 
            cursor: pointer; 
        }
        .action-button:hover { background: #005a9e; }
        .status { 
            margin: 10px 0; 
            padding: 10px; 
            background: #2d2d30; 
            border-radius: 5px; 
            border-left: 4px solid #007acc; 
        }
        h1 { color: #ffffff; margin-bottom: 20px; }
        h2 { color: #ffffff; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>System Tools</h2>
        <button class="nav-button active" onclick="showPanel('optimize')">Optimize</button>
        <button class="nav-button" onclick="showPanel('backup')">Backup</button>
        <button class="nav-button" onclick="showPanel('software')">Software</button>
        <button class="nav-button" onclick="showPanel('settings')">Settings</button>
        <button class="nav-button" onclick="showPanel('info')">System Info</button>
    </div>
    
    <div class="content">
        <div id="optimize" class="panel active">
            <h1>System Optimization</h1>
            <button class="action-button" onclick="executeAction('clear-temp')">Clear Temporary Files</button>
            <button class="action-button" onclick="executeAction('disk-cleanup')">Disk Cleanup</button>
            <button class="action-button" onclick="executeAction('defrag')">Defragment Drives</button>
            <div id="optimize-status" class="status">Ready to optimize your system.</div>
        </div>
        
        <div id="backup" class="panel">
            <h1>Backup & Restore</h1>
            <button class="action-button" onclick="executeAction('create-restore-point')">Create Restore Point</button>
            <button class="action-button" onclick="executeAction('backup-registry')">Backup Registry</button>
            <div id="backup-status" class="status">Backup tools ready.</div>
        </div>
        
        <div id="software" class="panel">
            <h1>Software Management</h1>
            <button class="action-button" onclick="executeAction('install-chocolatey')">Install Chocolatey</button>
            <button class="action-button" onclick="executeAction('update-software')">Update All Software</button>
            <div id="software-status" class="status">Software management tools ready.</div>
        </div>
        
        <div id="settings" class="panel">
            <h1>System Settings</h1>
            <button class="action-button" onclick="executeAction('optimize-services')">Optimize Services</button>
            <button class="action-button" onclick="executeAction('privacy-settings')">Configure Privacy</button>
            <div id="settings-status" class="status">Settings panel ready.</div>
        </div>
        
        <div id="info" class="panel">
            <h1>System Information</h1>
            <button class="action-button" onclick="executeAction('get-system-info')">Get System Info</button>
            <div id="info-display" class="status">Click button to display system information.</div>
        </div>
    </div>

    <script>
        function showPanel(panelId) {
            // Hide all panels
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-button').forEach(b => b.classList.remove('active'));
            
            // Show selected panel
            document.getElementById(panelId).classList.add('active');
            event.target.classList.add('active');
        }

        function executeAction(action) {
            const statusDiv = document.querySelector('.panel.active .status');
            statusDiv.innerHTML = 'Executing: ' + action + '...';
            
            fetch('/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action })
            })
            .then(response => response.text())
            .then(data => {
                statusDiv.innerHTML = data;
            })
            .catch(error => {
                statusDiv.innerHTML = 'Error: ' + error;
            });
        }
    </script>
</body>
</html>
"@

# Function to handle PowerShell commands
function Execute-SystemAction {
    param($action)
    
    switch ($action) {
        'clear-temp' {
            try {
                $tempPath = $env:TEMP
                $count = (Get-ChildItem $tempPath -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
                Get-ChildItem $tempPath -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                return " Cleared $count temporary files successfully"
            } catch {
                return " Error clearing temporary files: $($_.Exception.Message)"
            }
        }
        'create-restore-point' {
            try {
                Checkpoint-Computer -Description "System Management Tool Restore Point" -RestorePointType "MODIFY_SETTINGS"
                return " System restore point created successfully"
            } catch {
                return " Error creating restore point: $($_.Exception.Message)"
            }
        }
        'get-system-info' {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
            $memory = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
            
            return @"
<strong>System Information:</strong><br>
OS: $($os.Caption) $($os.Version)<br>
CPU: $($cpu.Name)<br>
RAM: $([math]::Round($memory.Sum / 1GB, 2)) GB<br>
Last Boot: $($os.LastBootUpTime)
"@
        }
        default {
            return "Action '$action' is not implemented yet"
        }
    }
}

# Main server loop
Write-Host "Server running... Press Ctrl+C to stop" -ForegroundColor Green

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        if ($request.Url.AbsolutePath -eq "/" -and $request.HttpMethod -eq "GET") {
            # Serve main page
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($htmlContent)
            $response.ContentLength64 = $buffer.Length
            $response.ContentType = "text/html"
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($request.Url.AbsolutePath -eq "/execute" -and $request.HttpMethod -eq "POST") {
            # Handle action execution
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd()
            $data = $json | ConvertFrom-Json
            
            $result = Execute-SystemAction -action $data.action
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($result)
            $response.ContentLength64 = $buffer.Length
            $response.ContentType = "text/html"
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        $response.Close()
    }
}
finally {
    $listener.Stop()
    Write-Host "Server stopped" -ForegroundColor Yellow
}