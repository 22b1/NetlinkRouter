# NetlinkRouter

## 1. Overview

NetlinkRouter is a Windows application that diverts network traffic from a specified process through a SOCKS5 proxy. It runs as a Windows service and is configured primarily via named pipe communication, making it suitable for control by other applications, such as a C# management UI.

## 2. Features

*   Runs as a background Windows Service (`NetlinkRouterService`).
*   Traffic diversion for a specific target process.
*   SOCKS5 proxy support (including optional username/password authentication).
*   Configuration and control via Named Pipes.
*   Command-line arguments for service installation and uninstallation.

## 3. Service Installation and Uninstallation

The NetlinkRouter service can be installed or uninstalled using the executable with specific command-line arguments. These operations typically require administrator privileges.

### From Command Prompt (Admin):

*   **Install Service**:
    ```cmd
    NetlinkRouter.exe install
    ```
*   **Uninstall Service**:
    ```cmd
    NetlinkRouter.exe uninstall
    ```

### From C# (Requires Admin Privileges for the C# app or shelling out with `runas` verb):

You can start a process from C# to execute these commands:

```csharp
using System.Diagnostics;

public class ServiceManager
{
    private string executablePath = @"C:\Path\To\NetlinkRouter.exe"; // Adjust path

    public void InstallService()
    {
        ProcessStartInfo startInfo = new ProcessStartInfo(executablePath, "install")
        {
            Verb = "runas", // To request administrator privileges
            UseShellExecute = true 
        };
        try
        {
            Process.Start(startInfo)?.WaitForExit();
            // Log success or check exit code
        }
        catch (Exception ex)
        {
            // Log error (e.g., user cancelled UAC prompt)
        }
    }

    public void UninstallService()
    {
        ProcessStartInfo startInfo = new ProcessStartInfo(executablePath, "uninstall")
        {
            Verb = "runas",
            UseShellExecute = true
        };
        try
        {
            Process.Start(startInfo)?.WaitForExit();
            // Log success or check exit code
        }
        catch (Exception ex)
        {
            // Log error
        }
    }
}
```

## 4. Service Control (from C#)

Once installed, the service can be controlled using the `System.ServiceProcess.ServiceController` class in C#.

*   **Service Name**: `NetlinkRouterService`

```csharp
using System.ServiceProcess;
using System.Threading.Tasks; // For Task.Delay

public class NetlinkRouterController
{
    private const string ServiceName = "NetlinkRouterService";

    public ServiceControllerStatus GetServiceStatus()
    {
        using (ServiceController sc = new ServiceController(ServiceName))
        {
            try
            {
                return sc.Status;
            }
            catch (InvalidOperationException)
            {
                // Service not installed or other issues
                return ServiceControllerStatus.Stopped; // Or throw
            }
        }
    }

    public async Task StartServiceAsync(int timeoutMilliseconds = 30000)
    {
        using (ServiceController sc = new ServiceController(ServiceName))
        {
            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                sc.Start();
                await WaitForStatusAsync(sc, ServiceControllerStatus.Running, timeoutMilliseconds);
            }
            // Else: already running or in a pending state
        }
    }

    public async Task StopServiceAsync(int timeoutMilliseconds = 30000)
    {
        using (ServiceController sc = new ServiceController(ServiceName))
        {
            if (sc.Status == ServiceControllerStatus.Running || sc.Status == ServiceControllerStatus.Paused)
            {
                sc.Stop();
                await WaitForStatusAsync(sc, ServiceControllerStatus.Stopped, timeoutMilliseconds);
            }
            // Else: already stopped or in a pending state
        }
    }

    private async Task WaitForStatusAsync(ServiceController sc, ServiceControllerStatus desiredStatus, int timeoutMilliseconds)
    {
        var stopwatch = Stopwatch.StartNew();
        while (sc.Status != desiredStatus && stopwatch.ElapsedMilliseconds < timeoutMilliseconds)
        {
            await Task.Delay(250);
            sc.Refresh(); // Important to get the latest status
        }
        stopwatch.Stop();
        if (sc.Status != desiredStatus)
        {
            throw new TimeoutException($"Service '{ServiceName}' did not reach status '{desiredStatus}' within the timeout period.");
        }
    }
}
```

## 5. Configuration via Named Pipe (from C#)

NetlinkRouter is configured by sending commands over a named pipe.

*   **Pipe Name**: `\\.\pipe\NLRouterPipe` (Use as `NLRouterPipe` for `NamedPipeClientStream` server name parameter if connecting to local machine, or the full path for remote).
*   **Communication**: Send commands as simple UTF-8 encoded strings. The service will respond with "OK" upon successful processing of a valid command, or a string starting with "ERROR:" if an issue occurs.

### Connecting and Sending Commands:

```csharp
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;

public class NetlinkConfigurator
{
    private const string PipeName = "NLRouterPipe"; // For local machine

    public async Task<string> SendCommandAsync(string command, int timeoutMilliseconds = 5000)
    {
        using (var pipeClient = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            try
            {
                await pipeClient.ConnectAsync(timeoutMilliseconds);

                byte[] commandBytes = Encoding.UTF8.GetBytes(command);
                await pipeClient.WriteAsync(commandBytes, 0, commandBytes.Length);
                pipeClient.WaitForPipeDrain(); // Ensure all data is sent

                byte[] responseBytes = new byte[1024]; // Adjust buffer size if necessary
                int bytesRead = await pipeClient.ReadAsync(responseBytes, 0, responseBytes.Length);
                
                return Encoding.UTF8.GetString(responseBytes, 0, bytesRead);
            }
            catch (TimeoutException ex)
            {
                return $"ERROR: Timeout connecting to pipe: {ex.Message}";
            }
            catch (IOException ex)
            {
                return $"ERROR: IOException with pipe: {ex.Message}";
            }
            catch (Exception ex)
            {
                return $"ERROR: Unexpected error: {ex.Message}";
            }
        }
    }
}
```

### Supported Commands:

All commands are space-delimited. Parameters should not contain spaces unless specifically handled or quoted (the current C++ parser does not seem to handle quoted spaces, so avoid them).

1.  **`START <ProcessName> <ProxyIP> <ProxyPort> <Username> <Password>`**
    *   Starts or restarts the traffic diversion with new settings.
    *   `<ProcessName>`: Target application's executable name (e.g., `brave.exe`, `firefox.exe`).
    *   `<ProxyIP>`: IP address or hostname of the SOCKS5 proxy server.
    *   `<ProxyPort>`: Port number of the SOCKS5 proxy server (e.g., `1080`, `9050`).
    *   `<Username>`: Username for SOCKS5 proxy authentication. Use `_` or an empty string `""` if no username.
    *   `<Password>`: Password for SOCKS5 proxy authentication. Use `_` or an empty string `""` if no password.
    *   Example: `START brave.exe 127.0.0.1 1080 user123 pass456`
    *   Example (no auth): `START chrome.exe myproxy.com 8888 _ _`

2.  **`STOP`**
    *   Stops the traffic diversion. The service continues running but does not proxy any traffic.
    *   Example: `STOP`

3.  **`PAUSE`**
    *   Temporarily pauses traffic diversion. The WinDivert capture loop will stop processing packets. The service reports its state as `SERVICE_PAUSED` to the Service Control Manager.
    *   Example: `PAUSE`

4.  **`RESUME`**
    *   Resumes traffic diversion if it was paused. If the service was configured and `DivertHandler` was not running, it will attempt to start it. The service reports its state as `SERVICE_RUNNING`.
    *   Example: `RESUME`

### Example C# Usage:

```csharp
public async Task ConfigureAndStartNetlink()
{
    NetlinkConfigurator configurator = new NetlinkConfigurator();
    string processName = "brave.exe";
    string proxyIp = "127.0.0.1";
    string proxyPort = "1080";
    string username = "_"; // No username
    string password = "_"; // No password

    string command = $"START {processName} {proxyIp} {proxyPort} {username} {password}";
    string response = await configurator.SendCommandAsync(command);

    if (response.StartsWith("OK"))
    {
        // Log success: "NetlinkRouter configured and started successfully."
    }
    else
    {
        // Log error: $"Failed to configure NetlinkRouter: {response}"
    }
}
```

## 6. Command-Line Arguments (for reference)

These are primarily for manual administration or debugging:

*   `NetlinkRouter.exe install`: Installs the Windows service. Requires admin privileges.
*   `NetlinkRouter.exe uninstall`: Uninstalls the Windows service. Requires admin privileges.
*   `NetlinkRouter.exe --run-in-console`: Runs the service logic directly in the current console window instead of as a background service. Useful for debugging. Press Ctrl+C to stop. Configuration still relies on the named pipe or a pre-existing config file if auto-load is implemented.

## 7. Building from Source

NetlinkRouter is a C++ project. You will need a C++ compiler (e.g., Visual Studio with C++ workloads) and any dependencies (like WinDivert SDK) to build it.

## 8. Troubleshooting & Logging

*   **Log File**: The primary source of information is the `NetlinkRouter.log` file, which is created in the same directory as `NetlinkRouter.exe`.
*   **Event Viewer**: Check the Windows Event Viewer (System and Application logs) for any service-related errors if the SCM fails to start/stop the service.
*   **Permissions**: Ensure the user account running the C# application has permissions to control services if it's trying to start/stop `NetlinkRouterService`. Installation/uninstallation of the service itself from C# will require the C# application to run with administrator privileges.
*   **Named Pipe Connection**: Ensure the service is running before attempting to connect via named pipe. If connection fails, check the log file for errors related to `NamedPipeServer` initialization. 