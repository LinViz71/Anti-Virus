# Russian GUI for ClamAV on-demand scans. Files are deleted only after explicit confirmation.

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

function New-ExactPathMap {
    $map = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    return ,$map
}

$script:dataRoot = Join-Path $env:LOCALAPPDATA 'ProtectionScanner'
$script:databaseDirectory = Join-Path $script:dataRoot 'database'
$script:logsDirectory = Join-Path $script:dataRoot 'logs'
$script:configPath = Join-Path $script:dataRoot 'freshclam.conf'
$script:settingsPath = Join-Path $script:dataRoot 'clamscan-path.txt'
$null = New-Item -ItemType Directory -Path $script:databaseDirectory -Force
$null = New-Item -ItemType Directory -Path $script:logsDirectory -Force

$script:enginePath = $null
$script:freshclamPath = $null
$script:activeProcess = $null
$script:activeKind = $null
$script:activeReportPath = $null
$script:lastReportPath = $null
$script:activeStdOutPath = $null
$script:activeStdErrPath = $null
$script:wasCancelled = $false
$script:countJob = $null
$script:countProgressPath = $null
$script:countTargetsPath = $null
$script:pendingScanTargets = @()
$script:scanTotalFiles = 0
$script:scannedOutputCount = 0
$script:scanMonitor = $null
$script:scanReportError = $null
$script:scanResultLines = @()
$script:scanResultHashes = @()
$script:scanResultsTruncated = $false
$script:deletionBatch = $null
$script:deletionRowsByPath = New-ExactPathMap
$script:deletionAppliedCount = 0
$script:deletionProcessedPaths = New-ExactPathMap
$script:deletionSignatureByPath = New-ExactPathMap
$script:verifiedDeletionByPath = New-ExactPathMap
$script:deletionMode = $null
$script:closeAfterDeletion = $false
$script:allowFormClose = $false

if (-not ('ProtectionScanner.ScanOutputMonitor' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Threading;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading.Tasks;

namespace ProtectionScanner {
    public sealed class ScanOutputMonitor : IDisposable {
        private readonly object reportLock = new object();
        private readonly List<string> resultLines = new List<string>();
        private readonly List<string> resultHashes = new List<string>();
        private readonly List<Task> hashTasks = new List<Task>();
        private readonly object hashTasksLock = new object();
        private static readonly SemaphoreSlim hashSlots = new SemaphoreSlim(2);
        private readonly CancellationTokenSource hashCancellation = new CancellationTokenSource();
        private StreamWriter report;
        private volatile Task<int> completion;
        private readonly object completionLock = new object();
        private long filesProcessed;
        private string reportError;
        private bool resultsTruncated;
        public Process Process { get; private set; }
        public long FilesProcessed { get { return Interlocked.Read(ref filesProcessed); } }
        public string ReportError { get { lock (reportLock) { return reportError; } } }
        public bool ResultsTruncated { get { lock (reportLock) { return resultsTruncated; } } }

        public string[] GetResultLines() {
            lock (reportLock) { return resultLines.ToArray(); }
        }
        public string[] GetResultHashes() {
            lock (reportLock) { return resultHashes.ToArray(); }
        }
        public bool IsComplete {
            get { Task<int> task = completion; return task != null && task.IsCompleted; }
        }

        public ScanOutputMonitor(string executable, string arguments, string reportPath) {
            try {
                report = new StreamWriter(reportPath, false, new UTF8Encoding(true));
                report.AutoFlush = true;
                report.WriteLine("Краткий отчёт ClamAV. Чистые файлы не перечислены.");
            } catch (Exception ex) {
                reportError = ex.Message;
                report = null;
            }
            Process = new Process();
            Process.StartInfo = new ProcessStartInfo {
                FileName = executable,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = new UTF8Encoding(false),
                StandardErrorEncoding = new UTF8Encoding(false)
            };
            Process.OutputDataReceived += OnOutput;
            Process.ErrorDataReceived += OnError;
            try {
                if (!Process.Start()) throw new InvalidOperationException("Не удалось запустить ClamAV.");
                Process.BeginOutputReadLine();
                Process.BeginErrorReadLine();
            } catch {
                Dispose();
                throw;
            }
        }

        private void OnOutput(object sender, DataReceivedEventArgs e) {
            if (e.Data == null) return;
            string line = e.Data;
            if (Regex.IsMatch(line, @":\s+(?:OK|Empty file)\s*$", RegexOptions.IgnoreCase) ||
                Regex.IsMatch(line, @":\s+.*\s+(?:FOUND|ERROR)\s*$", RegexOptions.IgnoreCase)) {
                Interlocked.Increment(ref filesProcessed);
            }
            Match resultMatch = Regex.Match(line, @"^(.*):\s+(.*\s+(FOUND|ERROR))$", RegexOptions.IgnoreCase);
            if (resultMatch.Success) {
                int resultIndex = -1;
                lock (reportLock) {
                    if (resultLines.Count < 5000) {
                        resultIndex = resultLines.Count;
                        resultLines.Add(line);
                        resultHashes.Add(null);
                    }
                    else resultsTruncated = true;
                }
                if (resultIndex >= 0 && CanDeleteDetection(resultMatch.Groups[2].Value)) {
                    string filePath = resultMatch.Groups[1].Value;
                    int hashIndex = resultIndex;
                    Task hashTask = Task.Run(async () => {
                        bool slotAcquired = false;
                        try {
                            await hashSlots.WaitAsync(hashCancellation.Token);
                            slotAcquired = true;
                            string hash = await GetFileHashAsync(filePath, hashCancellation.Token);
                            lock (reportLock) { resultHashes[hashIndex] = hash; }
                        }
                        catch (OperationCanceledException) { }
                        catch { }
                        finally { if (slotAcquired) hashSlots.Release(); }
                    });
                    lock (hashTasksLock) { hashTasks.Add(hashTask); }
                }
            }
            if (ShouldKeep(line)) WriteReportLine(line);
        }

        private void OnError(object sender, DataReceivedEventArgs e) {
            if (e.Data != null && Regex.IsMatch(e.Data, @"(?i)\b(error|warning|failed|denied|limit)\b")) {
                string detail = "ClamAV: " + e.Data;
                lock (reportLock) {
                    if (resultLines.Count < 5000) {
                        resultLines.Add(detail);
                        resultHashes.Add(null);
                    } else resultsTruncated = true;
                }
                WriteReportLine(detail);
            }
        }

        private static bool ShouldKeep(string line) {
            return Regex.IsMatch(line, @":\s+.*(?:FOUND|ERROR)\s*$", RegexOptions.IgnoreCase) ||
                Regex.IsMatch(line, @"^----------- SCAN SUMMARY -----------\s*$") ||
                Regex.IsMatch(line, @"^(Known viruses|Engine version|Scanned directories|Scanned files|Infected files|Total errors|Data scanned|Data read|Time|Start Date|End Date):") ||
                Regex.IsMatch(line, @"(?i)\b(error|warning|failed|denied|encrypted|exceeds|limit|can't open)\b");
        }

        private static bool CanDeleteDetection(string resultText) {
            if (!Regex.IsMatch(resultText, @"\bFOUND$", RegexOptions.IgnoreCase)) return false;
            string signature = Regex.Replace(resultText, @"\s+FOUND$", "", RegexOptions.IgnoreCase);
            return !Regex.IsMatch(signature,
                @"(^|\.)(Heuristics|PUA|Phishing|Broken|Encrypted|Limit|Limits|Exceeded)(\.|$)",
                RegexOptions.IgnoreCase);
        }

        private static async Task<string> GetFileHashAsync(string path, CancellationToken cancellation) {
            Process hashProcess = null;
            bool processStarted = false;
            try {
                cancellation.ThrowIfCancellationRequested();
                string script = "$ErrorActionPreference='Stop'; $file=Get-Item -LiteralPath $env:PROTECTION_SCANNER_HASH_PATH; " +
                    "if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 2 }; " +
                    "(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash";
                string encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                string windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                string powershellPath = Path.Combine(windowsDirectory, "System32\\WindowsPowerShell\\v1.0\\powershell.exe");
                hashProcess = new Process();
                hashProcess.StartInfo = new ProcessStartInfo {
                    FileName = powershellPath,
                    Arguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + encodedScript,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = new UTF8Encoding(false),
                    StandardErrorEncoding = new UTF8Encoding(false)
                };
                hashProcess.StartInfo.EnvironmentVariables["PROTECTION_SCANNER_HASH_PATH"] = path;
                if (!hashProcess.Start()) return null;
                processStarted = true;
                Task<string> standardOutput = hashProcess.StandardOutput.ReadToEndAsync();
                Task<string> standardError = hashProcess.StandardError.ReadToEndAsync();
                Stopwatch timeout = Stopwatch.StartNew();
                while (!hashProcess.HasExited) {
                    cancellation.ThrowIfCancellationRequested();
                    if (timeout.ElapsedMilliseconds >= 120000) return null;
                    await Task.Delay(100);
                }
                hashProcess.WaitForExit();
                string output = await standardOutput;
                await standardError;
                string hash = output.Trim();
                return hashProcess.ExitCode == 0 && Regex.IsMatch(hash, "^[A-Fa-f0-9]{64}$") ? hash : null;
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch { return null; }
            finally {
                if (hashProcess != null) {
                    try {
                        if (processStarted && !hashProcess.HasExited) {
                            hashProcess.Kill();
                            hashProcess.WaitForExit(5000);
                        }
                    }
                    catch { }
                    finally { hashProcess.Dispose(); }
                }
            }
        }

        public void CancelHashing() { hashCancellation.Cancel(); }

        private void WriteReportLine(string line) {
            lock (reportLock) {
                if (report == null) return;
                try { report.WriteLine(line); }
                catch (Exception ex) {
                    reportError = ex.Message;
                    try { report.Dispose(); } catch { }
                    report = null;
                }
            }
        }

        public void BeginComplete() {
            lock (completionLock) {
                if (completion != null) return;
                completion = Task.Run(async () => {
                    Process.WaitForExit();
                    Process.WaitForExit();
                    Task[] pendingHashes;
                    lock (hashTasksLock) { pendingHashes = hashTasks.ToArray(); }
                    Task allHashes = Task.WhenAll(pendingHashes);
                    Task hashWaitTimeout = Task.Delay(120000);
                    Task cancellationSignal = Task.Delay(Timeout.Infinite, hashCancellation.Token);
                    Task completedTask = await Task.WhenAny(allHashes, hashWaitTimeout, cancellationSignal);
                    if (completedTask == hashWaitTimeout) {
                        hashCancellation.Cancel();
                        await Task.WhenAny(allHashes, Task.Delay(5000));
                    }
                    lock (reportLock) {
                        if (report != null) {
                            try { report.Flush(); report.Dispose(); }
                            catch (Exception ex) { reportError = ex.Message; }
                            report = null;
                        }
                    }
                    return Process.ExitCode;
                });
            }
        }

        public int Complete() {
            Task<int> task = completion;
            if (task == null) throw new InvalidOperationException("Завершение сканирования ещё не запущено.");
            return task.GetAwaiter().GetResult();
        }

        public void Dispose() {
            lock (reportLock) {
                if (report != null) {
                    try { report.Dispose(); } catch { }
                    report = null;
                }
            }
            if (Process != null) {
                Process.OutputDataReceived -= OnOutput;
                Process.ErrorDataReceived -= OnError;
                Process.Dispose();
            }
        }
    }
}

namespace ProtectionScanner {
    internal sealed class DeletionDeadline {
        private const int Waiting = 0;
        private const int Stopped = 1;
        private const int Deleting = 2;
        private readonly Stopwatch elapsed = Stopwatch.StartNew();
        private readonly object cleanupSync = new object();
        private string temporaryDirectory;
        private bool cleanupConfirmed;
        private int state;

        public bool HasExpired { get { return elapsed.ElapsedMilliseconds >= 120000; } }

        public void SetTemporaryDirectory(string path) {
            lock (cleanupSync) { temporaryDirectory = path; }
        }

        public void ConfirmCleanup() {
            lock (cleanupSync) { cleanupConfirmed = true; }
        }

        public string GetCleanupWarning() {
            lock (cleanupSync) {
                if (cleanupConfirmed) return "Очистка завершена.";
                if (String.IsNullOrWhiteSpace(temporaryDirectory))
                    return "Завершение проверки и очистка временных данных не подтверждены.";
                return "Временные данные проверки могут остаться в " + temporaryDirectory;
            }
        }

        public bool TryStop() {
            return Interlocked.CompareExchange(ref state, Stopped, Waiting) == Waiting;
        }

        public void BeginDeletion(CancellationToken cancellation) {
            cancellation.ThrowIfCancellationRequested();
            if (HasExpired)
                throw new TimeoutException("Повторная проверка файла превысила 2 минуты.");
            if (Interlocked.CompareExchange(ref state, Deleting, Waiting) != Waiting)
                throw new OperationCanceledException();
            cancellation.ThrowIfCancellationRequested();
            if (HasExpired)
                throw new TimeoutException("Повторная проверка файла превысила 2 минуты.");
        }
    }

    public static class SafeFileDeletion {
        private const uint GenericRead = 0x80000000;
        private const uint DeleteAccess = 0x00010000;
        private const uint ReadAttributes = 0x00000080;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint ShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;
        private const uint AttributeDirectory = 0x00000010;
        private const uint AttributeDevice = 0x00000040;
        private const uint AttributeReparsePoint = 0x00000400;
        private const int FileAttributeTagInfo = 9;
        private const int FileDispositionInfo = 4;
        private const uint FileBegin = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTagInfo { public uint Attributes; public uint ReparseTag; }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime { public uint Low; public uint High; }
        [StructLayout(LayoutKind.Sequential)]
        private struct HandleFileInformation {
            public uint FileAttributes;
            public FileTime CreationTime;
            public FileTime LastAccessTime;
            public FileTime LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct DispositionInfo { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
            IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateDirectoryNative(string path, IntPtr security);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass,
            out AttributeTagInfo info, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle,
            out HandleFileInformation info);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(SafeFileHandle handle, byte[] buffer, uint count,
            out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFilePointerEx(SafeFileHandle handle, long distance,
            out long newPosition, uint moveMethod);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass,
            ref DispositionInfo info, uint size);

        private static void Rewind(SafeFileHandle handle) {
            long position;
            if (!SetFilePointerEx(handle, 0, out position, FileBegin))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public static string GetFileIdentity(string path) {
            using (SafeFileHandle handle = CreateFile(path, ReadAttributes,
                ShareRead | ShareWrite | ShareDelete, IntPtr.Zero, OpenExisting,
                OpenReparsePoint, IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                HandleFileInformation info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if ((info.FileAttributes & (AttributeDirectory | AttributeDevice | AttributeReparsePoint)) != 0)
                    throw new InvalidOperationException("Объект не является обычным файлом.");
                return info.VolumeSerialNumber.ToString("X8") + ":" +
                    info.FileIndexHigh.ToString("X8") + info.FileIndexLow.ToString("X8");
            }
        }

        private static string HashHandleCore(SafeFileHandle handle, CancellationToken cancellation) {
            Rewind(handle);
            using (SHA256 sha = SHA256.Create()) {
                byte[] buffer = new byte[65536];
                uint bytesRead;
                while (true) {
                    cancellation.ThrowIfCancellationRequested();
                    if (!ReadFile(handle, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    if (bytesRead == 0) break;
                    sha.TransformBlock(buffer, 0, (int)bytesRead, buffer, 0);
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return BitConverter.ToString(sha.Hash).Replace("-", "");
            }
        }

        private static string HashHandle(SafeFileHandle handle, CancellationToken cancellation) {
            CancellationTokenSource operationCancellation =
                CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            Task<string> hashTask = Task.Run(() => HashHandleCore(handle, operationCancellation.Token));
            Stopwatch timeout = Stopwatch.StartNew();
            try {
                while (!hashTask.IsCompleted) {
                    cancellation.ThrowIfCancellationRequested();
                    if (timeout.ElapsedMilliseconds >= 120000)
                        throw new TimeoutException("Проверка SHA-256 файла превысила 2 минуты.");
                    Thread.Sleep(100);
                }
                cancellation.ThrowIfCancellationRequested();
                return hashTask.GetAwaiter().GetResult();
            }
            finally {
                if (hashTask.IsCompleted) {
                    operationCancellation.Dispose();
                }
                else {
                    operationCancellation.Cancel();
                    hashTask.ContinueWith(task => {
                        try { task.GetAwaiter().GetResult(); } catch { }
                        operationCancellation.Dispose();
                    }, TaskScheduler.Default);
                }
            }
        }

        private static string QuoteArgument(string value) {
            StringBuilder result = new StringBuilder();
            result.Append('"');
            int backslashes = 0;
            foreach (char character in value) {
                if (character == '\\') { backslashes++; continue; }
                if (character == '"') {
                    result.Append('\\', backslashes * 2 + 1);
                    result.Append('"');
                    backslashes = 0;
                    continue;
                }
                if (backslashes > 0) { result.Append('\\', backslashes); backslashes = 0; }
                result.Append(character);
            }
            if (backslashes > 0) result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }

        private static void CopyHandleToStandardInput(SafeFileHandle handle, Process process,
            CancellationToken cancellation) {
            try {
                byte[] buffer = new byte[65536];
                uint count;
                while (true) {
                    cancellation.ThrowIfCancellationRequested();
                    if (!ReadFile(handle, buffer, (uint)buffer.Length, out count, IntPtr.Zero))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    if (count == 0) break;
                    process.StandardInput.BaseStream.Write(buffer, 0, (int)count);
                }
            }
            finally {
                try { process.StandardInput.BaseStream.Dispose(); } catch { }
            }
        }

        private static bool StopProcess(Process process, int timeoutMilliseconds) {
            try {
                if (process.HasExited) return true;
                process.Kill();
                return process.WaitForExit(timeoutMilliseconds) || process.HasExited;
            }
            catch {
                try { return process.HasExited; }
                catch { return false; }
            }
        }

        internal static bool WaitForTask(Task task, int timeoutMilliseconds) {
            if (task == null) return true;
            try { return task.Wait(timeoutMilliseconds); }
            catch (AggregateException) { return true; }
        }

        private static void CompleteInputCopy(Task inputCopy, CancellationToken cancellation) {
            try { inputCopy.GetAwaiter().GetResult(); }
            catch {
                cancellation.ThrowIfCancellationRequested();
                throw;
            }
        }

        private static string GetVerificationTempPath(string tempRoot) {
            string root = Path.GetFullPath(tempRoot);
            string rootPrefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            string directory = Path.GetFullPath(Path.Combine(root, "verify-" + Guid.NewGuid().ToString("N")));
            if (!directory.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Временный каталог проверки вышел за пределы своей папки.");
            return directory;
        }

        private static string ScanOpenHandle(SafeFileHandle handle, string executable,
            string databasePath, string tempRoot, CancellationToken cancellation,
            DeletionDeadline deadline) {
            cancellation.ThrowIfCancellationRequested();
            Rewind(handle);
            cancellation.ThrowIfCancellationRequested();
            string tempDirectory = GetVerificationTempPath(tempRoot);
            deadline.SetTemporaryDirectory(tempDirectory);
            bool tempDirectoryCreated = false;
            Process process = new Process();
            process.StartInfo = new ProcessStartInfo {
                FileName = executable,
                Arguments = "--stdout --heuristic-alerts=no --database=" + QuoteArgument(databasePath) +
                    " --tempdir=" + QuoteArgument(tempDirectory) + " -",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = new UTF8Encoding(false),
                StandardErrorEncoding = new UTF8Encoding(false)
            };
            Task<string> stdout = null;
            Task<string> stderr = null;
            Task inputCopy = null;
            bool processStarted = false;
            try {
                cancellation.ThrowIfCancellationRequested();
                if (Directory.Exists(tempDirectory) || File.Exists(tempDirectory))
                    throw new IOException("Временный каталог уже существует.");
                cancellation.ThrowIfCancellationRequested();
                string parentDirectory = Path.GetDirectoryName(tempDirectory);
                if (!Directory.Exists(parentDirectory)) Directory.CreateDirectory(parentDirectory);
                if (!CreateDirectoryNative(tempDirectory, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                tempDirectoryCreated = true;
                cancellation.ThrowIfCancellationRequested();
                if (!process.Start()) throw new InvalidOperationException("Не удалось запустить ClamAV.");
                processStarted = true;
                cancellation.ThrowIfCancellationRequested();
                stdout = process.StandardOutput.ReadToEndAsync();
                stderr = process.StandardError.ReadToEndAsync();
                Stopwatch timeout = Stopwatch.StartNew();
                inputCopy = Task.Run(() => CopyHandleToStandardInput(handle, process, cancellation));
                while (!process.HasExited || !inputCopy.IsCompleted || !stdout.IsCompleted || !stderr.IsCompleted) {
                    cancellation.ThrowIfCancellationRequested();
                    if (timeout.ElapsedMilliseconds >= 120000) {
                        throw new TimeoutException("Повторная проверка ClamAV превысила 2 минуты.");
                    }
                    if (inputCopy.IsFaulted) CompleteInputCopy(inputCopy, cancellation);
                    Thread.Sleep(100);
                }
                cancellation.ThrowIfCancellationRequested();
                CompleteInputCopy(inputCopy, cancellation);
                string output = stdout.GetAwaiter().GetResult();
                string errors = stderr.GetAwaiter().GetResult();
                if (process.ExitCode != 1)
                    throw new InvalidOperationException("ClamAV не подтвердил обнаружение. " + errors.Trim());
                Match match = Regex.Match(output, @"(?m)^stdin:\s+(.*?)\s+FOUND\s*$", RegexOptions.IgnoreCase);
                if (!match.Success)
                    throw new InvalidOperationException("Повторная проверка не подтвердила вирусную сигнатуру.");
                return match.Groups[1].Value.Trim();
            }
            finally {
                bool processStopped = !processStarted || StopProcess(process, 5000);
                bool inputFinished = WaitForTask(inputCopy, 5000);
                bool outputFinished = WaitForTask(stdout, 5000) && WaitForTask(stderr, 5000);
                process.Dispose();
                if (tempDirectoryCreated) {
                    if (!processStopped || !inputFinished || !outputFinished)
                        throw new TimeoutException("Не удалось штатно остановить ClamAV и завершить очистку. Временные данные сохранены в " + tempDirectory);
                    try {
                        Directory.Delete(tempDirectory, true);
                        deadline.ConfirmCleanup();
                    }
                    catch (DirectoryNotFoundException) { deadline.ConfirmCleanup(); }
                    catch (Exception ex) {
                        throw new IOException("Не удалось очистить временные данные из " + tempDirectory + ". " + ex.Message, ex);
                    }
                }
            }
        }

        private static string VerifyFile(string path, string expectedHash, string expectedSignature,
            string executable, string databasePath, string tempRoot, CancellationToken cancellation,
            DeletionDeadline deadline, bool deleteAfterVerification) {
            cancellation.ThrowIfCancellationRequested();
            if ((deleteAfterVerification && String.IsNullOrWhiteSpace(expectedHash)) ||
                (expectedHash != null && !Regex.IsMatch(expectedHash, "^[A-Fa-f0-9]{64}$")))
                throw new InvalidOperationException("Нет корректного SHA-256 для проверки; удаление отменено.");
            if (String.IsNullOrWhiteSpace(expectedSignature))
                throw new InvalidOperationException("Не указана сигнатура для повторной проверки.");
            uint access = GenericRead | ReadAttributes | (deleteAfterVerification ? DeleteAccess : 0);
            using (SafeFileHandle handle = CreateFile(path, access,
                ShareRead, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero)) {
                cancellation.ThrowIfCancellationRequested();
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                AttributeTagInfo attributes;
                if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, out attributes,
                    (uint)Marshal.SizeOf(typeof(AttributeTagInfo))))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                cancellation.ThrowIfCancellationRequested();
                if ((attributes.Attributes & (AttributeDirectory | AttributeDevice | AttributeReparsePoint)) != 0)
                    throw new InvalidOperationException("Объект не является обычным файлом.");

                string actualHash = HashHandle(handle, cancellation);
                if (expectedHash != null && !String.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Файл изменился после проверки; удаление отменено.");

                string actualSignature = ScanOpenHandle(handle, executable, databasePath, tempRoot,
                    cancellation, deadline);
                if (!String.Equals(actualSignature, expectedSignature, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Повторная проверка не подтвердила ту же вирусную сигнатуру.");
                if (!deleteAfterVerification) return actualHash;
                DispositionInfo disposition = new DispositionInfo { DeleteFile = true };
                deadline.BeginDeletion(cancellation);
                if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition,
                    (uint)Marshal.SizeOf(typeof(DispositionInfo))))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return actualHash;
            }
        }

        internal static string VerifyForConfirmation(string path, string expectedSignature,
            string executable, string databasePath, string tempRoot, CancellationToken cancellation,
            DeletionDeadline deadline) {
            return VerifyFile(path, null, expectedSignature, executable, databasePath, tempRoot,
                cancellation, deadline, false);
        }

        internal static bool VerifyAndDelete(string path, string expectedHash, string expectedSignature,
            string executable, string databasePath, string tempRoot, CancellationToken cancellation,
            DeletionDeadline deadline) {
            string verifiedHash = VerifyFile(path, expectedHash, expectedSignature, executable,
                databasePath, tempRoot, cancellation, deadline, true);
            return !String.IsNullOrWhiteSpace(verifiedHash);
        }
    }
}

namespace ProtectionScanner {
    public sealed class DeletionRequest {
        public string Path { get; private set; }
        public string Sha256 { get; private set; }
        public string Signature { get; private set; }
        public DeletionRequest(string path, string sha256, string signature) {
            Path = path; Sha256 = sha256; Signature = signature;
        }
    }

    public sealed class DeletionResult {
        public string Path { get; private set; }
        public bool Deleted { get; private set; }
        public string Message { get; private set; }
        public string VerifiedHash { get; private set; }
        public DeletionResult(string path, bool deleted, string message, string verifiedHash) {
            Path = path; Deleted = deleted; Message = message; VerifiedHash = verifiedHash;
        }
    }

    public sealed class DeletionBatch {
        private readonly object sync = new object();
        private readonly List<DeletionResult> results = new List<DeletionResult>();
        private readonly DeletionRequest[] requests;
        private readonly string executable;
        private readonly string databasePath;
        private readonly string tempRoot;
        private readonly bool verifyOnly;
        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private Task worker;
        private int completed;
        public int TotalCount { get { return requests.Length; } }
        public int CompletedCount { get { return Interlocked.CompareExchange(ref completed, 0, 0); } }
        public bool IsCompleted { get { return worker != null && worker.IsCompleted; } }
        public bool IsCancellationRequested { get { return cancellation.IsCancellationRequested; } }

        public DeletionBatch(DeletionRequest[] requests, string executable, string databasePath, string tempRoot)
            : this(requests, executable, databasePath, tempRoot, false) { }

        public DeletionBatch(DeletionRequest[] requests, string executable, string databasePath, string tempRoot,
            bool verifyOnly) {
            this.requests = requests;
            this.executable = executable;
            this.databasePath = databasePath;
            this.tempRoot = tempRoot;
            this.verifyOnly = verifyOnly;
        }

        public void Start() {
            worker = Task.Run(() => {
                foreach (DeletionRequest request in requests) {
                    bool deleted = false;
                    string verifiedHash = null;
                    string message;
                    try {
                        cancellation.Token.ThrowIfCancellationRequested();
                        if (verifyOnly) {
                            verifiedHash = VerifyForConfirmationWithTimeout(request);
                            message = "Текущий файл повторно проверен.";
                        }
                        else {
                            deleted = VerifyAndDeleteWithTimeout(request);
                            message = deleted ? "Удалён пользователем после повторной проверки." : "Удаление не выполнено.";
                        }
                    }
                    catch (OperationCanceledException) { message = "Операция отменена."; }
                    catch (Exception ex) { message = ex.Message; }
                    lock (sync) { results.Add(new DeletionResult(request.Path, deleted, message, verifiedHash)); }
                    Interlocked.Increment(ref completed);
                    if (cancellation.IsCancellationRequested) break;
                }
            });
        }

        private bool VerifyAndDeleteWithTimeout(DeletionRequest request) {
            DeletionDeadline deadline = new DeletionDeadline();
            CancellationTokenSource operationCancellation =
                CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
            Task<bool> verification = Task.Run(() => SafeFileDeletion.VerifyAndDelete(
                request.Path, request.Sha256, request.Signature, executable, databasePath,
                tempRoot, operationCancellation.Token, deadline));
            try {
                while (!verification.IsCompleted) {
                    if (cancellation.IsCancellationRequested || deadline.HasExpired) {
                        if (!deadline.TryStop()) break;
                        operationCancellation.Cancel();
                        SafeFileDeletion.WaitForTask(verification, 5000);
                        if (verification.IsCompleted) return verification.GetAwaiter().GetResult();
                        string cleanupWarning = deadline.GetCleanupWarning();
                        if (cancellation.IsCancellationRequested)
                            throw new IOException("Отмена запрошена. " + cleanupWarning);
                        throw new TimeoutException("Повторная проверка файла превысила 2 минуты. " + cleanupWarning);
                    }
                    Thread.Sleep(100);
                }
                return verification.GetAwaiter().GetResult();
            }
            finally {
                if (verification.IsCompleted) {
                    operationCancellation.Dispose();
                }
                else {
                    verification.ContinueWith(task => {
                        try { task.GetAwaiter().GetResult(); } catch { }
                        operationCancellation.Dispose();
                    }, TaskScheduler.Default);
                }
            }
        }

        private string VerifyForConfirmationWithTimeout(DeletionRequest request) {
            DeletionDeadline deadline = new DeletionDeadline();
            CancellationTokenSource operationCancellation =
                CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
            Task<string> verification = Task.Run(() => SafeFileDeletion.VerifyForConfirmation(
                request.Path, request.Signature, executable, databasePath,
                tempRoot, operationCancellation.Token, deadline));
            try {
                while (!verification.IsCompleted) {
                    if (cancellation.IsCancellationRequested || deadline.HasExpired) {
                        if (!deadline.TryStop()) break;
                        operationCancellation.Cancel();
                        SafeFileDeletion.WaitForTask(verification, 5000);
                        if (verification.IsCompleted) return verification.GetAwaiter().GetResult();
                        string cleanupWarning = deadline.GetCleanupWarning();
                        if (cancellation.IsCancellationRequested)
                            throw new IOException("Отмена запрошена. " + cleanupWarning);
                        throw new TimeoutException("Проверка перед подтверждением превысила 2 минуты. " + cleanupWarning);
                    }
                    Thread.Sleep(100);
                }
                return verification.GetAwaiter().GetResult();
            }
            finally {
                if (verification.IsCompleted) {
                    operationCancellation.Dispose();
                }
                else {
                    operationCancellation.Cancel();
                    verification.ContinueWith(task => {
                        try { task.GetAwaiter().GetResult(); } catch { }
                        operationCancellation.Dispose();
                    }, TaskScheduler.Default);
                }
            }
        }

        public DeletionResult[] GetResults() {
            lock (sync) { return results.ToArray(); }
        }
        public void Cancel() { cancellation.Cancel(); }
    }
}
'@
}

function Find-ClamAV {
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $script:settingsPath) {
        try {
            $saved = [System.IO.File]::ReadAllText($script:settingsPath).Trim()
            if ($saved) { [void]$candidates.Add($saved) }
        } catch { }
    }

    $programFiles = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
    $programFilesX86 = [System.Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($programFiles) { [void]$candidates.Add((Join-Path $programFiles 'ClamAV\clamscan.exe')) }
    if ($programFilesX86) { [void]$candidates.Add((Join-Path $programFilesX86 'ClamAV\clamscan.exe')) }
    [void]$candidates.Add((Join-Path $PSScriptRoot 'ClamAV\clamscan.exe'))
    [void]$candidates.Add('C:\ClamAV\clamscan.exe')

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $script:enginePath = (Resolve-Path -LiteralPath $candidate).Path
            break
        }
    }
    if (-not $script:enginePath) {
        $command = Get-Command 'clamscan.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { $script:enginePath = $command.Source }
    }

    $script:freshclamPath = $null
    if ($script:enginePath) {
        $sibling = Join-Path (Split-Path -Parent $script:enginePath) 'freshclam.exe'
        if (Test-Path -LiteralPath $sibling -PathType Leaf) { $script:freshclamPath = $sibling }
    }
    if (-not $script:freshclamPath) {
        $updateCommand = Get-Command 'freshclam.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($updateCommand) { $script:freshclamPath = $updateCommand.Source }
    }
}

function Write-FreshClamConfig {
    $lines = @(
        '# Generated by Protection Scanner',
        ('DatabaseDirectory "{0}"' -f $script:databaseDirectory),
        'DatabaseMirror database.clamav.net',
        'Checks 24',
        'ConnectTimeout 60',
        'ReceiveTimeout 180',
        'Foreground yes'
    )
    [System.IO.File]::WriteAllLines($script:configPath, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-DatabaseFiles {
    @(Get-ChildItem -LiteralPath $script:databaseDirectory -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.cvd', '.cld') })
}

function Get-DatabaseReadiness {
    $files = Get-DatabaseFiles
    if ($files.Count -eq 0) {
        return [pscustomobject]@{
            Ready = $false
            StatusText = 'База сигнатур не загружена. Сначала нажмите «Обновить базы».'
            Reason = 'Missing'
            LastWriteTime = $null
        }
    }
    $latest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $age = (Get-Date) - $latest.LastWriteTime
    if ($age.TotalDays -gt 7) {
        return [pscustomobject]@{
            Ready = $false
            StatusText = ('Базы устарели: последняя дата {0:dd.MM.yyyy HH:mm}. Обновите их перед сканированием.' -f $latest.LastWriteTime)
            Reason = 'Stale'
            LastWriteTime = $latest.LastWriteTime
        }
    }
    return [pscustomobject]@{
        Ready = $true
        StatusText = ('Базы готовы. Последнее изменение: {0:dd.MM.yyyy HH:mm}.' -f $latest.LastWriteTime)
        Reason = 'Ready'
        LastWriteTime = $latest.LastWriteTime
    }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    for ($index = 0; $index -lt $Value.Length; $index++) {
        $character = $Value[$index]
        if ($character -eq [char]92) {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            if ($slashes -gt 0) { [void]$builder.Append([string]::new([char]92, ($slashes * 2))) }
            [void]$builder.Append([char]92)
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append([string]::new([char]92, $slashes))
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append([string]::new([char]92, ($slashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Update-DeleteButtonState {
    if (-not $script:deleteSelectedButton -or -not $script:resultsView) { return }
    $hasDetection = $false
    foreach ($row in $script:resultsView.SelectedItems) {
        if ($row.Tag -and $row.Tag.CanDelete -and $row.Tag.Signature) {
            $hasDetection = $true
            break
        }
    }
    $busy = [bool]($script:activeProcess -or $script:countJob -or $script:deletionBatch)
    $script:deleteSelectedButton.Enabled = (-not $busy) -and $hasDetection
}

function Set-ScanControls {
    param([bool]$Busy)
    $script:updateButton.Enabled = (-not $Busy) -and [bool]$script:freshclamPath
    $script:allDrivesButton.Enabled = (-not $Busy) -and [bool]$script:enginePath
    $script:folderButton.Enabled = (-not $Busy) -and [bool]$script:enginePath
    $script:quickScanButton.Enabled = (-not $Busy) -and [bool]$script:enginePath
    $script:locateButton.Enabled = -not $Busy
    $script:downloadButton.Enabled = -not $Busy
    $script:cancelButton.Enabled = $Busy
    $script:openLogsButton.Enabled = -not $Busy
    $script:progressBar.Style = if ($Busy) { [System.Windows.Forms.ProgressBarStyle]::Marquee } else { [System.Windows.Forms.ProgressBarStyle]::Blocks }
    $script:progressBar.MarqueeAnimationSpeed = if ($Busy) { 25 } else { 0 }
    $form.UseWaitCursor = $Busy
    Update-DeleteButtonState
}

function Update-StatusDisplay {
    if ($script:enginePath) {
        $script:engineLabel.Text = 'Движок: ' + $script:enginePath
        $script:engineLabel.ForeColor = [System.Drawing.Color]::DarkGreen
    }
    else {
        $script:engineLabel.Text = 'ClamAV не найден. Установите его с официального сайта или укажите путь к clamscan.exe.'
        $script:engineLabel.ForeColor = [System.Drawing.Color]::DarkRed
    }
    $databaseReadiness = Get-DatabaseReadiness
    $script:databaseLabel.Text = $databaseReadiness.StatusText
    $busy = [bool]($script:activeProcess -or $script:countJob -or $script:deletionBatch)
    if ($script:freshclamPath) {
        $script:updateButton.Enabled = -not $busy
    }
    else {
        $script:updateButton.Enabled = $false
    }
    $hasDatabase = [bool]$databaseReadiness.Ready
    $script:allDrivesButton.Enabled = (-not $busy) -and [bool]$script:enginePath -and $hasDatabase
    $script:folderButton.Enabled = (-not $busy) -and [bool]$script:enginePath -and $hasDatabase
    $script:quickScanButton.Enabled = (-not $busy) -and [bool]$script:enginePath -and $hasDatabase
    $script:saveReportButton.Enabled = [bool]$script:lastReportPath -and (Test-Path -LiteralPath $script:lastReportPath)
    $script:openReportButton.Enabled = $script:saveReportButton.Enabled
    Update-DeleteButtonState
}

function Start-ManagedProcess {
    param(
        [ValidateSet('Update', 'Scan')][string]$Kind,
        [string]$Executable,
        [string[]]$Arguments,
        [string]$ReportPath
    )

    if ($script:activeProcess -or $script:countJob) { return }
    $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
    $script:activeKind = $Kind
    if ($Kind -eq 'Scan' -and $ReportPath) { $script:activeReportPath = $ReportPath }
    $argumentList = [string[]]$Arguments

    try {
        if ($Kind -eq 'Scan') {
            $script:activeStdOutPath = $null
            $script:activeStdErrPath = $null
            $script:scanReportError = $null
            $script:scanMonitor = [ProtectionScanner.ScanOutputMonitor]::new($Executable, ($argumentList -join ' '), $ReportPath)
            $script:activeProcess = $script:scanMonitor.Process
        }
        else {
            $script:scanReportError = $null
            $script:activeStdOutPath = Join-Path $script:logsDirectory ($Kind.ToLowerInvariant() + '-' + $stamp + '.stdout.log')
            $script:activeStdErrPath = Join-Path $script:logsDirectory ($Kind.ToLowerInvariant() + '-' + $stamp + '.stderr.log')
            Remove-Item -LiteralPath $script:activeStdOutPath,$script:activeStdErrPath -Force -ErrorAction SilentlyContinue
            $script:activeProcess = Start-Process -FilePath $Executable -ArgumentList $argumentList -PassThru -WindowStyle Hidden -RedirectStandardOutput $script:activeStdOutPath -RedirectStandardError $script:activeStdErrPath -ErrorAction Stop
        }
        $script:wasCancelled = $false
        if ($Kind -eq 'Scan') {
            $script:scannedOutputCount = 0
            $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Blocks
            $script:progressBar.Value = 0
            $script:statusLabel.Text = 'Запускаю ClamAV; ожидаю первые результаты…'
        }
        else {
            $script:statusLabel.Text = 'Загружаю и обновляю базы ClamAV…'
        }
        Set-ScanControls -Busy $true
        if ($Kind -eq 'Scan') { $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Blocks }
        $script:timer.Start()
    }
    catch {
        if ($script:scanMonitor) {
            try { $script:scanMonitor.Dispose() } catch { }
            $script:scanMonitor = $null
        }
        $script:activeProcess = $null
        $script:activeKind = $null
        $script:timer.Stop()
        Set-ScanControls -Busy $false
        $script:statusLabel.Text = 'Не удалось запустить ClamAV.'
        [System.Windows.Forms.MessageBox]::Show(
            "Ошибка запуска:`r`n$($_.Exception.Message)",
            'Ошибка',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        Update-StatusDisplay
    }
}

function Start-DatabaseUpdate {
    if (-not $script:freshclamPath) {
        [System.Windows.Forms.MessageBox]::Show('Не найден freshclam.exe рядом с ClamAV. Переустановите ClamAV из официального пакета или укажите папку установки.', 'Нет обновлятора') | Out-Null
        return
    }
    Write-FreshClamConfig
    $arguments = @('--config-file="' + $script:configPath + '"', '--verbose')
    Start-ManagedProcess -Kind 'Update' -Executable $script:freshclamPath -Arguments $arguments
}

function Start-ClamScan {
    param([string[]]$Targets, [switch]$SkipCount)
    if (-not $script:enginePath) { return }
    $databaseReadiness = Get-DatabaseReadiness
    if (-not $databaseReadiness.Ready) {
        $caption = if ($databaseReadiness.Reason -eq 'Missing') { 'Нет баз' } else { 'База устарела' }
        [System.Windows.Forms.MessageBox]::Show($databaseReadiness.StatusText, $caption) | Out-Null
        return
    }

    $scanStamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
    $reportPath = Join-Path $script:logsDirectory ('scan-' + $scanStamp + '.log')
    $script:pendingScanTargets = [string[]]$Targets
    $script:activeKind = 'Count'
    $script:activeReportPath = $reportPath
    $script:scanResultLines = @()
    $script:scanResultHashes = @()
    $script:scanResultsTruncated = $false

    if ($SkipCount) {
        $script:scanTotalFiles = 0
        $script:wasCancelled = $false
        $script:resultsView.Items.Clear()
        $script:statusLabel.Text = 'Запускаю быструю проверку…'
        $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
        Set-ScanControls -Busy $true
        Start-ClamScanEngine
        return
    }

    $script:countProgressPath = Join-Path $script:logsDirectory ('count-' + $scanStamp + '.txt')
    $script:countTargetsPath = Join-Path $script:logsDirectory ('count-targets-' + $scanStamp + '.txt')
    Remove-Item -LiteralPath $script:countProgressPath -Force -ErrorAction SilentlyContinue
    $jobArguments = @($script:countTargetsPath, $script:countProgressPath)
    try {
        [System.IO.File]::WriteAllLines($script:countTargetsPath, [string[]]$script:pendingScanTargets, (New-Object System.Text.UTF8Encoding($true)))
        $script:countJob = Start-Job -ScriptBlock {
            param([string]$TargetsFile, [string]$ProgressFile)
            $fileCount = 0
            $scanTargets = [System.IO.File]::ReadAllLines($TargetsFile, [System.Text.Encoding]::UTF8)
            foreach ($scanTarget in $scanTargets) {
                try {
                    Get-ChildItem -LiteralPath $scanTarget -File -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        $fileCount = $fileCount + 1
                        if (($fileCount % 2000) -eq 0) {
                            try { [System.IO.File]::WriteAllText($ProgressFile, [string]$fileCount) } catch { }
                        }
                    }
                }
                catch { }
            }
            try { [System.IO.File]::WriteAllText($ProgressFile, [string]$fileCount) } catch { }
            $fileCount
        } -ArgumentList $jobArguments
        $script:scanTotalFiles = 0
        $script:wasCancelled = $false
        $script:resultsView.Items.Clear()
        $script:statusLabel.Text = 'Считаю файлы для оценки процента проверки…'
        $script:progressBar.Value = 0
        Set-ScanControls -Busy $true
        $script:timer.Start()
    }
    catch {
        $countError = $_.Exception.Message
        if ($script:countJob) {
            try { Stop-Job -Job $script:countJob -ErrorAction SilentlyContinue } catch { }
            try { Remove-Job -Job $script:countJob -Force -ErrorAction SilentlyContinue } catch { }
        }
        $script:countJob = $null
        Remove-Item -LiteralPath $script:countTargetsPath,$script:countProgressPath -Force -ErrorAction SilentlyContinue
        $script:scanTotalFiles = 0
        $script:wasCancelled = $false
        $script:resultsView.Items.Clear()
        $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
        $script:statusLabel.Text = 'Не удалось посчитать файлы для процента. Запускаю проверку без оценки прогресса…'
        Set-ScanControls -Busy $true
        Start-ClamScanEngine
        if (-not $script:activeProcess) {
            $script:statusLabel.Text = 'Подсчёт файлов и запуск сканера не удались: ' + $countError
            Update-StatusDisplay
        }
    }
}

function Start-ClamScanEngine {
    if (-not $script:enginePath) { return }
    $arguments = @(
        '--recursive', '--stdout', '--heuristic-alerts=yes', '--alert-encrypted=yes', '--alert-exceeds-max=yes',
        '--follow-dir-symlinks=0', '--follow-file-symlinks=0', '--fail-if-cvd-older-than=7',
        ('--database="' + $script:databaseDirectory + '"')
    )
    foreach ($target in $script:pendingScanTargets) {
        $normalized = $target
        if ($normalized -match '^[A-Za-z]:\\$') { $normalized += '.' }
        elseif ($normalized.Length -gt 3) { $normalized = $normalized.TrimEnd([char[]]@('\', '/')) }
        $arguments += ('"' + $normalized + '"')
    }
    Start-ManagedProcess -Kind 'Scan' -Executable $script:enginePath -Arguments $arguments -ReportPath $script:activeReportPath
}

function Update-ScanProgress {
    if (-not $script:scanMonitor) { return }
    $script:scannedOutputCount = $script:scanMonitor.FilesProcessed
    if ($script:scanTotalFiles -gt 0) {
        $percent = [int][Math]::Min(99, [Math]::Floor(100.0 * $script:scannedOutputCount / $script:scanTotalFiles))
        $displayCount = [long][Math]::Min($script:scannedOutputCount, $script:scanTotalFiles)
        $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Blocks
        $script:progressBar.Value = $percent
        $script:statusLabel.Text = ('Проверено примерно {0}% — {1:N0} из ~{2:N0} файлов.' -f $percent, $displayCount, $script:scanTotalFiles)
    }
    else {
        $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
        $script:progressBar.MarqueeAnimationSpeed = 25
        $script:statusLabel.Text = ('Проверка идёт. Обработано примерно {0:N0} файлов.' -f $script:scannedOutputCount)
    }
}

function Complete-ManagedProcess {
    param([int]$ExitCode)

    $kind = $script:activeKind
    if ($kind -eq 'Scan') { $script:lastReportPath = $script:activeReportPath }
    $script:activeProcess = $null
    $script:activeKind = $null
    Set-ScanControls -Busy $false
    Update-StatusDisplay

    if ($script:wasCancelled) {
        $script:statusLabel.Text = 'Операция остановлена. Отчёт может быть неполным.'
        if ($kind -eq 'Scan' -and $script:scanReportError) {
            $script:statusLabel.Text += ' Ошибка записи отчёта: ' + $script:scanReportError
        }
        if ($kind -eq 'Scan') { Add-ReportMatchesToList }
        return
    }
    if ($kind -eq 'Update') {
        if ($ExitCode -eq 0) {
            $script:statusLabel.Text = 'Базы ClamAV обновлены.'
        }
        else {
            $script:statusLabel.Text = "Обновление не завершилось успешно (код $ExitCode). Проверьте подключение к интернету; журналы: $script:logsDirectory"
        }
        Update-StatusDisplay
        return
    }

    if ($ExitCode -eq 0) {
        $script:statusLabel.Text = 'Сканирование завершено: ClamAV не сообщил о заражённых файлах. Проверьте отчёт на ошибки и превышение лимитов.'
    }
    elseif ($ExitCode -eq 1) {
        $script:statusLabel.Text = 'ClamAV сообщил о совпадениях. Откройте отчёт и проверьте каждую строку; файлы не изменены.'
    }
    else {
        $script:statusLabel.Text = "Сканирование завершено с ошибками (код $ExitCode); результаты могут быть неполными. Откройте отчёт."
    }
    if ($script:scanReportError) {
        $script:statusLabel.Text += ' Отчёт записан с ошибкой: ' + $script:scanReportError
    }
    Update-StatusDisplay
    Add-ReportMatchesToList
}

function Add-ReportMatchesToList {
    for ($index = 0; $index -lt $script:scanResultLines.Count; $index++) {
        $line = $script:scanResultLines[$index]
        if ($line -notmatch '^(.*):\s+(.*?\s+(?:FOUND|ERROR))$') {
            $resultLabel = if ($line -match '(?i)\bwarning\b') { 'WARNING' } else { 'ERROR' }
            $row = New-Object System.Windows.Forms.ListViewItem($resultLabel)
            [void]$row.SubItems.Add('')
            [void]$row.SubItems.Add($line)
            [void]$script:resultsView.Items.Add($row)
            continue
        }
        $filePath = $Matches[1]
        $resultText = $Matches[2]
        $row = New-Object System.Windows.Forms.ListViewItem($resultText)
        [void]$row.SubItems.Add($filePath)
        [void]$row.SubItems.Add('Результат сохранён в памяти')

        if (Test-CanDeleteDetection -ResultText $resultText) {
            try {
                $hash = if ($index -lt $script:scanResultHashes.Count) { $script:scanResultHashes[$index] } else { $null }
                if (-not $hash) { throw 'Не удалось сохранить хэш файла во время проверки.' }
                $signature = $resultText -replace '\s+FOUND$', ''
                $row.Tag = [pscustomobject]@{ Path = $filePath; Sha256 = $hash; Signature = $signature; CanDelete = $true }
                $row.SubItems[2].Text = 'Перед согласием и удалением содержимое будет перепроверено'
            }
            catch {
                $signature = $resultText -replace '\s+FOUND$', ''
                $row.Tag = [pscustomobject]@{ Path = $filePath; Sha256 = $null; Signature = $signature; CanDelete = $false }
                $row.SubItems[2].Text = 'Не удалось зафиксировать хэш; удаление отключено'
            }
        }
        else {
            $signature = $resultText -replace '\s+FOUND$', ''
            $row.Tag = [pscustomobject]@{ Path = $filePath; Sha256 = $null; Signature = $signature; CanDelete = $false }
            if ($resultText -match '\bFOUND$') { $row.SubItems[2].Text = 'Предупреждение или нежелательная программа; удаление отключено' }
        }
        [void]$script:resultsView.Items.Add($row)
    }
    if ($script:scanResultsTruncated) {
        $row = New-Object System.Windows.Forms.ListViewItem('Список ограничен 5000 строками')
        [void]$row.SubItems.Add('')
        [void]$row.SubItems.Add('Полный отчёт доступен отдельно')
        [void]$script:resultsView.Items.Add($row)
    }
    Update-DeleteButtonState
}

function Test-CanDeleteDetection {
    param([string]$ResultText)
    if ($ResultText -notmatch '\bFOUND$') { return $false }
    $signature = $ResultText -replace '\s+FOUND$', ''
    return $signature -notmatch '(?i)(^|\.)(Heuristics|PUA|Phishing|Broken|Encrypted|Limit|Limits|Exceeded)(\.|$)'
}

function Confirm-DeleteSelection {
    param([System.Windows.Forms.ListViewItem[]]$Rows)

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Подтверждение удаления'
    $dialog.StartPosition = 'CenterParent'
    $dialog.Size = New-Object System.Drawing.Size(780, 560)
    $dialog.MinimumSize = New-Object System.Drawing.Size(640, 420)
    $dialog.Font = $form.Font

    $warning = New-Object System.Windows.Forms.Label
    $warning.Text = 'Будут удалены целые файлы. Срабатывание ClamAV может быть ложным. Каждый файл уже перепроверен перед этим подтверждением; перед удалением хэш и сигнатура будут сверены ещё раз.'
    $warning.Location = New-Object System.Drawing.Point(14, 14)
    $warning.Size = New-Object System.Drawing.Size(735, 42)
    $warning.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $dialog.Controls.Add($warning)

    $list = New-Object System.Windows.Forms.ListView
    $list.Location = New-Object System.Drawing.Point(14, 64)
    $list.Size = New-Object System.Drawing.Size(735, 405)
    $list.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $list.View = [System.Windows.Forms.View]::Details
    $list.FullRowSelect = $true
    $list.GridLines = $true
    [void]$list.Columns.Add('Обнаружение', 220)
    [void]$list.Columns.Add('Путь файла', 495)
    foreach ($row in $Rows) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$row.Tag.Signature)
        [void]$item.SubItems.Add([string]$row.Tag.Path)
        [void]$list.Items.Add($item)
    }
    $dialog.Controls.Add($list)

    $deleteButton = New-Object System.Windows.Forms.Button
    $deleteButton.Text = 'Удалить файлы'
    $deleteButton.Location = New-Object System.Drawing.Point(488, 482)
    $deleteButton.Size = New-Object System.Drawing.Size(125, 32)
    $deleteButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $deleteButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $dialog.Controls.Add($deleteButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Отмена'
    $cancelButton.Location = New-Object System.Drawing.Point(624, 482)
    $cancelButton.Size = New-Object System.Drawing.Size(125, 32)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $dialog.Controls.Add($cancelButton)
    $dialog.CancelButton = $cancelButton

    try { return ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::Yes) }
    finally { $dialog.Dispose() }
}

function Apply-DeletionResults {
    param([object[]]$Results)

    while ($script:deletionAppliedCount -lt $Results.Count) {
        $result = $Results[$script:deletionAppliedCount]
        $path = [string]$result.Path
        $script:deletionProcessedPaths[$path] = $true
        $matchingRows = @($script:deletionRowsByPath[$path])
        if ($script:deletionMode -eq 'Verify') {
            $verifiedHash = [string]$result.VerifiedHash
            $verifiedSignature = [string]$script:deletionSignatureByPath[$path]
            $signatureRows = @($matchingRows | Where-Object {
                $_.Tag -and [string]$_.Tag.Signature -ieq $verifiedSignature
            })
            if ($verifiedHash -match '^[A-Fa-f0-9]{64}$' -and $verifiedSignature) {
                $script:verifiedDeletionByPath[$path] = [pscustomobject]@{
                    Sha256 = $verifiedHash
                    Signature = $verifiedSignature
                }
            }
            foreach ($row in $signatureRows) {
                if ($script:verifiedDeletionByPath.ContainsKey($path)) {
                    $row.Tag.Sha256 = $verifiedHash
                    $row.Tag.CanDelete = $true
                    $row.SubItems[0].Text = 'FOUND — перепроверен'
                    $row.SubItems[2].Text = 'Хэш и та же вирусная сигнатура подтверждены перед согласием'
                }
                elseif ($result.Message -eq 'Операция отменена.') {
                    $row.SubItems[0].Text = 'FOUND — проверка остановлена'
                    $row.SubItems[2].Text = 'Проверка перед подтверждением остановлена пользователем'
                }
                else {
                    $row.SubItems[0].Text = 'FOUND — не подтверждён'
                    $row.SubItems[2].Text = [string]$result.Message
                    $row.Tag.CanDelete = $false
                }
            }
        }
        else {
            if ($result.Deleted) {
                foreach ($row in $matchingRows) {
                    $row.SubItems[0].Text = 'FOUND — удалён'
                    $row.SubItems[2].Text = 'Удалён пользователем после повторной проверки'
                    $row.Tag.CanDelete = $false
                }
            }
            else {
                $signatureRows = @($matchingRows | Where-Object {
                    $_.Tag -and [string]$_.Tag.Signature -ieq [string]$script:deletionSignatureByPath[$path]
                })
                foreach ($row in $signatureRows) {
                    if ($result.Message -eq 'Операция отменена.') {
                        $row.SubItems[0].Text = 'FOUND — не удалён'
                        $row.SubItems[2].Text = 'Повторная проверка остановлена пользователем'
                    }
                    else {
                        $row.SubItems[0].Text = 'FOUND — удаление отменено'
                        $row.SubItems[2].Text = [string]$result.Message
                        $row.Tag.CanDelete = $false
                    }
                }
            }
        }
        $script:deletionAppliedCount++
    }
}

function Update-DeletionBatch {
    $batch = $script:deletionBatch
    if (-not $batch) { return }

    $results = @($batch.GetResults())
    Apply-DeletionResults -Results $results

    $total = [int]$batch.TotalCount
    $completed = [int]$batch.CompletedCount
    if ($total -gt 0) {
        $percent = [int][Math]::Min(99, [Math]::Floor(100.0 * $completed / $total))
        $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Blocks
        $script:progressBar.Value = $percent
        if ($batch.IsCancellationRequested) {
            $script:statusLabel.Text = if ($script:deletionMode -eq 'Verify') { 'Останавливаю проверку перед подтверждением…' } else { 'Запрошена отмена. Ожидаю завершения текущей операции…' }
        }
        elseif ($script:deletionMode -eq 'Verify') {
            $script:statusLabel.Text = ('Проверяю перед подтверждением: {0} из {1} файлов.' -f $completed, $total)
        }
        else {
            $script:statusLabel.Text = ('Повторная проверка и удаление: {0} из {1} файлов.' -f $completed, $total)
        }
    }
    if (-not $batch.IsCompleted) { return }

    $results = @($batch.GetResults())
    Apply-DeletionResults -Results $results

    if ($script:deletionMode -eq 'Verify') {
        $script:timer.Stop()
        $cancelled = [bool]$batch.IsCancellationRequested
        $verifiedCount = @($results | Where-Object { [string]$_.VerifiedHash -match '^[A-Fa-f0-9]{64}$' }).Count
        $failedCount = [Math]::Max(0, $total - $verifiedCount)
        $unprocessedCount = [Math]::Max(0, $total - $results.Count)
        $cleanupIncomplete = @($results | Where-Object { $_.Message -match '(?i)временн(ые|ых) данн' }).Count -gt 0
        foreach ($path in @($script:deletionRowsByPath.Keys)) {
            if ($script:deletionProcessedPaths.ContainsKey([string]$path)) { continue }
            $expectedSignature = [string]$script:deletionSignatureByPath[$path]
            $signatureRows = @($script:deletionRowsByPath[$path] | Where-Object {
                $_.Tag -and $_.Tag.CanDelete -and [string]$_.Tag.Signature -ieq $expectedSignature
            })
            foreach ($row in $signatureRows) {
                $row.SubItems[0].Text = 'FOUND — не проверен'
                $row.SubItems[2].Text = 'Пакет остановлен до подтверждения этой сигнатуры'
            }
        }

        if ($cancelled -or $verifiedCount -ne $total -or $results.Count -ne $total) {
            $script:deletionBatch = $null
            $script:deletionRowsByPath = New-ExactPathMap
            $script:deletionAppliedCount = 0
            $script:deletionProcessedPaths = New-ExactPathMap
            $script:deletionSignatureByPath = New-ExactPathMap
            $script:verifiedDeletionByPath = New-ExactPathMap
            $script:deletionMode = $null
            Set-ScanControls -Busy $false
            Update-StatusDisplay
            if ($cleanupIncomplete) {
                $script:statusLabel.Text = 'Не удалось подтвердить очистку временных данных повторной проверки.'
            }
            elseif ($cancelled) {
                $script:statusLabel.Text = 'Проверка перед подтверждением остановлена. Удаление не запускалось.'
            }
            else {
                $script:statusLabel.Text = 'Не все файлы прошли повторную проверку. Удаление не запускалось.'
            }
            if ($script:closeAfterDeletion) {
                $script:closeAfterDeletion = $false
                if (-not $cleanupIncomplete) {
                    $script:allowFormClose = $true
                    $form.Close()
                    return
                }
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Проверено перед подтверждением: $verifiedCount`r`nНе подтверждено: $failedCount`r`nНе обработано: $unprocessedCount`r`nУдаление не запускалось.",
                'Удаление не запущено',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        $rowsToConfirm = New-Object 'System.Collections.Generic.List[System.Windows.Forms.ListViewItem]'
        foreach ($path in @($script:deletionRowsByPath.Keys)) {
            $verifiedFile = $script:verifiedDeletionByPath[[string]$path]
            foreach ($row in @($script:deletionRowsByPath[$path] | Where-Object {
                $_.Tag -and $_.Tag.CanDelete -and [string]$_.Tag.Signature -ieq [string]$verifiedFile.Signature
            })) { $rowsToConfirm.Add($row) }
        }
        $confirmed = $false
        if (-not $script:closeAfterDeletion) {
            $confirmed = Confirm-DeleteSelection -Rows $rowsToConfirm.ToArray()
        }
        if (-not $confirmed -or $script:closeAfterDeletion) {
            $script:deletionBatch = $null
            $script:deletionRowsByPath = New-ExactPathMap
            $script:deletionAppliedCount = 0
            $script:deletionProcessedPaths = New-ExactPathMap
            $script:deletionSignatureByPath = New-ExactPathMap
            $script:verifiedDeletionByPath = New-ExactPathMap
            $script:deletionMode = $null
            Set-ScanControls -Busy $false
            Update-StatusDisplay
            if ($script:closeAfterDeletion) {
                $script:closeAfterDeletion = $false
                $script:allowFormClose = $true
                $form.Close()
                return
            }
            $script:statusLabel.Text = 'Удаление отменено пользователем после повторной проверки.'
            return
        }

        try {
            $requests = New-Object 'System.Collections.Generic.List[ProtectionScanner.DeletionRequest]'
            foreach ($path in @($script:deletionRowsByPath.Keys)) {
                $verifiedFile = $script:verifiedDeletionByPath[[string]$path]
                if (-not $verifiedFile -or $verifiedFile.Sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or -not $verifiedFile.Signature) {
                    throw ('Не найдены подтверждённые хэш и сигнатура для ' + [string]$path)
                }
                $requests.Add([ProtectionScanner.DeletionRequest]::new(
                    [string]$path, [string]$verifiedFile.Sha256, [string]$verifiedFile.Signature
                ))
            }
            if ($requests.Count -ne $total -or $script:verifiedDeletionByPath.Count -ne $total) {
                throw 'Состав подтверждённых файлов изменился; удаление не запущено.'
            }
            $script:deletionAppliedCount = 0
            $script:deletionProcessedPaths = New-ExactPathMap
            $script:deletionMode = 'Delete'
            $script:deletionBatch = [ProtectionScanner.DeletionBatch]::new(
                $requests.ToArray(), [string]$script:enginePath, [string]$script:databaseDirectory,
                [string](Join-Path $script:dataRoot 'verification-temp'), $false
            )
            $script:deletionBatch.Start()
            $script:progressBar.Value = 0
            $script:statusLabel.Text = ('Повторно сверяю и удаляю {0} файлов по вашему согласию…' -f $requests.Count)
            Set-ScanControls -Busy $true
            $script:timer.Start()
        }
        catch {
            $script:deletionBatch = $null
            $script:deletionRowsByPath = New-ExactPathMap
            $script:deletionAppliedCount = 0
            $script:deletionProcessedPaths = New-ExactPathMap
            $script:deletionSignatureByPath = New-ExactPathMap
            $script:verifiedDeletionByPath = New-ExactPathMap
            $script:deletionMode = $null
            Set-ScanControls -Busy $false
            Update-StatusDisplay
            $script:statusLabel.Text = 'Не удалось начать удаление; файлы не удалены.'
            [System.Windows.Forms.MessageBox]::Show(
                ('Не удалось начать удаление: ' + $_.Exception.Message),
                'Ошибка удаления',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
        return
    }

    $cancelled = [bool]$batch.IsCancellationRequested
    $deletedCount = @($results | Where-Object { $_.Deleted }).Count
    $failedCount = $results.Count - $deletedCount
    $unprocessedCount = [Math]::Max(0, $total - $results.Count)
    $cleanupIncomplete = @($results | Where-Object { $_.Message -match '(?i)временн(ые|ых) данн' }).Count -gt 0
    foreach ($path in @($script:deletionRowsByPath.Keys)) {
        if ($script:deletionProcessedPaths.ContainsKey([string]$path)) { continue }
        foreach ($row in @($script:deletionRowsByPath[$path])) {
            $row.SubItems[0].Text = 'FOUND — не обработан'
            $row.SubItems[2].Text = 'Пакет остановлен до повторной проверки файла'
        }
    }

    $script:deletionBatch = $null
    $script:deletionRowsByPath = New-ExactPathMap
    $script:deletionAppliedCount = 0
    $script:deletionProcessedPaths = New-ExactPathMap
    $script:deletionSignatureByPath = New-ExactPathMap
    $script:verifiedDeletionByPath = New-ExactPathMap
    $script:deletionMode = $null
    Set-ScanControls -Busy $false
    Update-StatusDisplay
    if ($script:closeAfterDeletion -and $cleanupIncomplete) {
        $script:closeAfterDeletion = $false
        $script:statusLabel.Text = 'Не удалось подтвердить очистку временных файлов. Проверьте строки ошибок перед закрытием.'
    }
    elseif ($script:closeAfterDeletion) {
        $script:closeAfterDeletion = $false
        $script:allowFormClose = $true
        $script:timer.Stop()
        $form.Close()
        return
    }
    if ($cleanupIncomplete) {
        $script:statusLabel.Text = 'Не удалось подтвердить очистку временных файлов. Проверьте строки ошибок перед закрытием.'
    }
    elseif ($cancelled) {
        $script:statusLabel.Text = 'Удаление остановлено. Уже удалённые файлы показаны в списке.'
    }
    else {
        $script:progressBar.Value = 100
        $script:statusLabel.Text = 'Удаление с повторной проверкой завершено.'
    }
    [System.Windows.Forms.MessageBox]::Show(
        "Удалено файлов: $deletedCount`r`nНе удалено: $failedCount`r`nНе обработано: $unprocessedCount",
        'Результат удаления',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Проверка компьютера — ClamAV'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(930, 650)
$form.MinimumSize = New-Object System.Drawing.Size(920, 600)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Проверка файлов ClamAV'
$title.Location = New-Object System.Drawing.Point(22, 16)
$title.Size = New-Object System.Drawing.Size(850, 34)
$title.Font = New-Object System.Drawing.Font('Segoe UI', 17, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($title)

$script:engineLabel = New-Object System.Windows.Forms.Label
$script:engineLabel.Location = New-Object System.Drawing.Point(24, 59)
$script:engineLabel.Size = New-Object System.Drawing.Size(860, 25)
$form.Controls.Add($script:engineLabel)

$script:databaseLabel = New-Object System.Windows.Forms.Label
$script:databaseLabel.Location = New-Object System.Drawing.Point(24, 87)
$script:databaseLabel.Size = New-Object System.Drawing.Size(860, 25)
$form.Controls.Add($script:databaseLabel)

$script:updateButton = New-Object System.Windows.Forms.Button
$script:updateButton.Text = 'Обновить базы'
$script:updateButton.Location = New-Object System.Drawing.Point(22, 126)
$script:updateButton.Size = New-Object System.Drawing.Size(155, 40)
$form.Controls.Add($script:updateButton)

$script:quickScanButton = New-Object System.Windows.Forms.Button
$script:quickScanButton.Text = 'Быстрая проверка'
$script:quickScanButton.Location = New-Object System.Drawing.Point(187, 126)
$script:quickScanButton.Size = New-Object System.Drawing.Size(135, 40)
$form.Controls.Add($script:quickScanButton)

$script:allDrivesButton = New-Object System.Windows.Forms.Button
$script:allDrivesButton.Text = 'Проверить локальные диски…'
$script:allDrivesButton.Location = New-Object System.Drawing.Point(332, 126)
$script:allDrivesButton.Size = New-Object System.Drawing.Size(220, 40)
$form.Controls.Add($script:allDrivesButton)

$script:folderButton = New-Object System.Windows.Forms.Button
$script:folderButton.Text = 'Выбрать папку…'
$script:folderButton.Location = New-Object System.Drawing.Point(562, 126)
$script:folderButton.Size = New-Object System.Drawing.Size(154, 40)
$form.Controls.Add($script:folderButton)

$script:locateButton = New-Object System.Windows.Forms.Button
$script:locateButton.Text = 'Найти clamscan.exe…'
$script:locateButton.Location = New-Object System.Drawing.Point(726, 126)
$script:locateButton.Size = New-Object System.Drawing.Size(170, 40)
$form.Controls.Add($script:locateButton)

$script:downloadButton = New-Object System.Windows.Forms.Button
$script:downloadButton.Text = 'Официальный сайт ClamAV'
$script:downloadButton.Location = New-Object System.Drawing.Point(22, 176)
$script:downloadButton.Size = New-Object System.Drawing.Size(170, 36)
$form.Controls.Add($script:downloadButton)

$script:cancelButton = New-Object System.Windows.Forms.Button
$script:cancelButton.Text = 'Остановить'
$script:cancelButton.Location = New-Object System.Drawing.Point(202, 176)
$script:cancelButton.Size = New-Object System.Drawing.Size(100, 36)
$script:cancelButton.Enabled = $false
$form.Controls.Add($script:cancelButton)

$script:openReportButton = New-Object System.Windows.Forms.Button
$script:openReportButton.Text = 'Открыть отчёт'
$script:openReportButton.Location = New-Object System.Drawing.Point(312, 176)
$script:openReportButton.Size = New-Object System.Drawing.Size(125, 36)
$script:openReportButton.Enabled = $false
$form.Controls.Add($script:openReportButton)

$script:saveReportButton = New-Object System.Windows.Forms.Button
$script:saveReportButton.Text = 'Сохранить копию отчёта…'
$script:saveReportButton.Location = New-Object System.Drawing.Point(447, 176)
$script:saveReportButton.Size = New-Object System.Drawing.Size(165, 36)
$script:saveReportButton.Enabled = $false
$form.Controls.Add($script:saveReportButton)

$script:deleteSelectedButton = New-Object System.Windows.Forms.Button
$script:deleteSelectedButton.Text = 'Удалить выбранные…'
$script:deleteSelectedButton.Location = New-Object System.Drawing.Point(622, 176)
$script:deleteSelectedButton.Size = New-Object System.Drawing.Size(150, 36)
$script:deleteSelectedButton.Enabled = $false
$form.Controls.Add($script:deleteSelectedButton)

$script:openLogsButton = New-Object System.Windows.Forms.Button
$script:openLogsButton.Text = 'Папка журналов'
$script:openLogsButton.Location = New-Object System.Drawing.Point(782, 176)
$script:openLogsButton.Size = New-Object System.Drawing.Size(105, 36)
$form.Controls.Add($script:openLogsButton)

$script:statusLabel = New-Object System.Windows.Forms.Label
$script:statusLabel.Text = 'Установите ClamAV и обновите базу сигнатур перед проверкой.'
$script:statusLabel.Location = New-Object System.Drawing.Point(24, 225)
$script:statusLabel.Size = New-Object System.Drawing.Size(860, 42)
$form.Controls.Add($script:statusLabel)

$script:progressBar = New-Object System.Windows.Forms.ProgressBar
$script:progressBar.Location = New-Object System.Drawing.Point(24, 270)
$script:progressBar.Size = New-Object System.Drawing.Size(860, 15)
$script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Blocks
$script:progressBar.Minimum = 0
$script:progressBar.Maximum = 100
$form.Controls.Add($script:progressBar)

$script:resultsView = New-Object System.Windows.Forms.ListView
$script:resultsView.Location = New-Object System.Drawing.Point(24, 299)
$script:resultsView.Size = New-Object System.Drawing.Size(860, 270)
$script:resultsView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$script:resultsView.View = [System.Windows.Forms.View]::Details
$script:resultsView.FullRowSelect = $true
$script:resultsView.GridLines = $true
[void]$script:resultsView.Columns.Add('Результат ClamAV', 230)
[void]$script:resultsView.Columns.Add('Файл', 440)
[void]$script:resultsView.Columns.Add('Примечание', 175)
$script:resultsView.Add_SelectedIndexChanged({ Update-DeleteButtonState })
$form.Controls.Add($script:resultsView)

$footer = New-Object System.Windows.Forms.Label
$footer.Text = 'Проверка только по запросу; ClamAV для Windows не обеспечивает постоянную защиту. Удаление обнаруженных файлов выполняется вручную после подтверждения.'
$footer.Location = New-Object System.Drawing.Point(24, 578)
$footer.Size = New-Object System.Drawing.Size(860, 28)
$footer.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$footer.ForeColor = [System.Drawing.Color]::DimGray
$form.Controls.Add($footer)

$script:timer = New-Object System.Windows.Forms.Timer
$script:timer.Interval = 750
$script:timer.Add_Tick({
    if ($script:deletionBatch) {
        Update-DeletionBatch
        return
    }
    if ($script:countJob) {
        $countSoFar = [long]0
        try {
            if (Test-Path -LiteralPath $script:countProgressPath) {
                $countText = [System.IO.File]::ReadAllText($script:countProgressPath).Trim()
                if ($countText -match '^\d+$') { $countSoFar = [long]$countText }
            }
        }
        catch { }
        $script:statusLabel.Text = ('Считаю файлы перед проверкой… найдено {0:N0}.' -f $countSoFar)

        if ($script:countJob.State -in @('Completed', 'Failed', 'Stopped')) {
            $jobState = [string]$script:countJob.State
            try {
                $jobOutput = @(Receive-Job -Job $script:countJob -ErrorAction SilentlyContinue)
                foreach ($item in $jobOutput) {
                    if ($item -is [ValueType]) { $countSoFar = [long]$item }
                }
            } catch { }
            try { Remove-Job -Job $script:countJob -Force -ErrorAction SilentlyContinue } catch { }
            $script:countJob = $null
            Remove-Item -LiteralPath $script:countTargetsPath,$script:countProgressPath -Force -ErrorAction SilentlyContinue
            if ($jobState -eq 'Stopped' -or $script:wasCancelled) {
                $script:timer.Stop()
                $script:activeKind = $null
                Set-ScanControls -Busy $false
                $script:statusLabel.Text = 'Подсчёт файлов остановлен.'
                Update-StatusDisplay
                return
            }
            $script:scanTotalFiles = if ($jobState -eq 'Completed') { $countSoFar } else { 0 }
            if ($script:scanTotalFiles -le 0) {
                $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
                $script:statusLabel.Text = 'Подсчёт не завершился. Запускаю проверку без процентной оценки…'
            }
            Start-ClamScanEngine
        }
        return
    }

    if ($script:activeProcess) {
        if ($script:activeKind -eq 'Scan') { Update-ScanProgress }
        try {
            if ($script:activeProcess.HasExited) {
                $exitCode = $script:activeProcess.ExitCode
                if ($script:activeKind -eq 'Scan') {
                    Update-ScanProgress
                    if ($script:scanMonitor) {
                        $monitor = $script:scanMonitor
                        $monitor.BeginComplete()
                        if (-not $monitor.IsComplete) {
                            $script:statusLabel.Text = 'Сканирование завершено. Завершаю обработку обнаружений…'
                            return
                        }
                        $exitCode = $monitor.Complete()
                        $script:scanReportError = $script:scanMonitor.ReportError
                        $script:scanResultLines = @($script:scanMonitor.GetResultLines())
                        $script:scanResultHashes = @($script:scanMonitor.GetResultHashes())
                        $script:scanResultsTruncated = $script:scanMonitor.ResultsTruncated
                        $script:scanMonitor.Dispose()
                        $script:scanMonitor = $null
                    }
                    if (-not $script:wasCancelled -and $exitCode -in @(0, 1)) { $script:progressBar.Value = 100 }
                }
                else {
                    $script:activeProcess.Dispose()
                }
                $script:timer.Stop()
                Complete-ManagedProcess -ExitCode $exitCode
            }
        }
        catch {
            $script:timer.Stop()
            $script:statusLabel.Text = 'Не удалось получить результат запущенного процесса. Проверьте журналы.'
            $script:activeProcess = $null
            Set-ScanControls -Busy $false
        }
    }
})

$script:updateButton.Add_Click({ Start-DatabaseUpdate })
$script:quickScanButton.Add_Click({
    $quickCandidates = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::DesktopDirectory),
        $env:TEMP,
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    $quickTargets = @()
    $seenTargets = @{}
    foreach ($candidate in $quickCandidates) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
        try { $normalizedCandidate = [System.IO.Path]::GetFullPath([string]$candidate) } catch { continue }
        if ((Test-Path -LiteralPath $normalizedCandidate -PathType Container) -and -not $seenTargets.ContainsKey($normalizedCandidate)) {
            $seenTargets[$normalizedCandidate] = $true
            $quickTargets += $normalizedCandidate
        }
    }
    if ($quickTargets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Не удалось найти стандартные папки для быстрой проверки.', 'Нет папок') | Out-Null
        return
    }
    $quickDescription = ($quickTargets -join [Environment]::NewLine)
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Будут проверены распространённые пользовательские папки:`r`n$quickDescription`r`n`r`nЭто быстрая проверка, она не заменяет проверку всех дисков. Продолжить?",
        'Быстрая проверка',
        [System.Windows.Forms.MessageBoxButtons]::OKCancel,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    if ($answer -eq [System.Windows.Forms.DialogResult]::OK) { Start-ClamScan -Targets $quickTargets -SkipCount }
})
$script:allDrivesButton.Add_Click({
    $drives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -in @([System.IO.DriveType]::Fixed, [System.IO.DriveType]::Removable) } | ForEach-Object { $_.RootDirectory.FullName })
    if ($drives.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Не удалось найти доступные локальные диски.', 'Нет дисков') | Out-Null
        return
    }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Будут проверены диски: $($drives -join ', '). Это может занять несколько часов. Продолжить?",
        'Полная проверка',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($answer -eq [System.Windows.Forms.DialogResult]::Yes) { Start-ClamScan -Targets $drives }
})
$script:folderButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Выберите папку для проверки ClamAV.'
    $dialog.ShowNewFolderButton = $false
    if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        Start-ClamScan -Targets @($dialog.SelectedPath)
    }
    $dialog.Dispose()
})
$script:locateButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = 'Укажите clamscan.exe'
    $dialog.Filter = 'ClamAV scanner (clamscan.exe)|clamscan.exe|Executable files (*.exe)|*.exe'
    $dialog.FileName = 'clamscan.exe'
    if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        if ([System.IO.Path]::GetFileName($dialog.FileName) -ine 'clamscan.exe') {
            [System.Windows.Forms.MessageBox]::Show('Нужно выбрать именно clamscan.exe.', 'Неверный файл') | Out-Null
        }
        else {
            $script:enginePath = $dialog.FileName
            [System.IO.File]::WriteAllText($script:settingsPath, $script:enginePath, (New-Object System.Text.UTF8Encoding($true)))
            Find-ClamAV
            Update-StatusDisplay
        }
    }
    $dialog.Dispose()
})
$script:downloadButton.Add_Click({ Start-Process 'https://www.clamav.net/downloads' })
$script:cancelButton.Add_Click({
    if ($script:deletionBatch) {
        $script:statusLabel.Text = 'Останавливаю повторную проверку и удаление…'
        try { $script:deletionBatch.Cancel() } catch { }
    }
    elseif ($script:countJob) {
        $script:wasCancelled = $true
        $script:statusLabel.Text = 'Останавливаю подсчёт файлов…'
        try { Stop-Job -Job $script:countJob -ErrorAction SilentlyContinue } catch { }
        try { Remove-Job -Job $script:countJob -Force -ErrorAction SilentlyContinue } catch { }
        $script:countJob = $null
        Remove-Item -LiteralPath $script:countTargetsPath,$script:countProgressPath -Force -ErrorAction SilentlyContinue
        $script:activeKind = $null
        $script:timer.Stop()
        Set-ScanControls -Busy $false
        $script:statusLabel.Text = 'Подсчёт файлов остановлен.'
        Update-StatusDisplay
    }
    elseif ($script:activeProcess) {
        $script:wasCancelled = $true
        $script:statusLabel.Text = 'Останавливаю ClamAV…'
        if ($script:scanMonitor) {
            try { $script:scanMonitor.CancelHashing() } catch { }
        }
        try { $script:activeProcess.Kill() } catch { }
    }
})
$script:openReportButton.Add_Click({
    if ($script:lastReportPath -and (Test-Path -LiteralPath $script:lastReportPath)) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList (Quote-ProcessArgument -Value $script:lastReportPath)
    }
})
$script:saveReportButton.Add_Click({
    if (-not $script:lastReportPath -or -not (Test-Path -LiteralPath $script:lastReportPath)) { return }
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = 'Сохранить копию отчёта ClamAV'
    $dialog.Filter = 'Текстовый отчёт (*.log)|*.log|Все файлы (*.*)|*.*'
    $dialog.FileName = [System.IO.Path]::GetFileName($script:lastReportPath)
    if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        Copy-Item -LiteralPath $script:lastReportPath -Destination $dialog.FileName -Force
    }
    $dialog.Dispose()
})
$script:deleteSelectedButton.Add_Click({
    $selectedRows = @($script:resultsView.SelectedItems | Where-Object { $_.Tag -and $_.Tag.CanDelete -and $_.Tag.Signature })
    $selectedByIdentity = New-ExactPathMap
    $identityByPath = New-ExactPathMap
    foreach ($row in $selectedRows) {
        $path = [string]$row.Tag.Path
        $fileIdentity = $null
        try { $fileIdentity = [ProtectionScanner.SafeFileDeletion]::GetFileIdentity($path) }
        catch {
            $hasCaseVariant = $false
            foreach ($candidateRow in $script:resultsView.Items) {
                if (-not $candidateRow.Tag) { continue }
                $candidatePath = [string]$candidateRow.Tag.Path
                if ([System.StringComparer]::OrdinalIgnoreCase.Equals($candidatePath, $path) -and
                    -not [System.StringComparer]::Ordinal.Equals($candidatePath, $path)) {
                    $hasCaseVariant = $true
                    break
                }
            }
            if ($hasCaseVariant) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Не удалось определить, какие записи с разным регистром относятся к тому же файлу. Удаление не запущено.',
                    'Не удалось проверить файл',
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return
            }
        }
        $identityKey = if ($fileIdentity) { 'FILE:' + $fileIdentity } else { 'PATH:' + $path }
        $selectedByIdentity[$identityKey] = $row
        $identityByPath[$path] = $fileIdentity
    }
    if ($selectedByIdentity.Count -eq 0) { return }

    $requests = New-Object 'System.Collections.Generic.List[ProtectionScanner.DeletionRequest]'
    $script:deletionRowsByPath = New-ExactPathMap
    $script:deletionProcessedPaths = New-ExactPathMap
    $script:deletionSignatureByPath = New-ExactPathMap
    $script:verifiedDeletionByPath = New-ExactPathMap
    $identityLookupFailed = $false
    foreach ($identityKey in @($selectedByIdentity.Keys)) {
        $selectedRow = $selectedByIdentity[$identityKey]
        $path = [string]$selectedRow.Tag.Path
        $sha256 = [string]$selectedRow.Tag.Sha256
        $signature = [string]$selectedRow.Tag.Signature
        $requests.Add([ProtectionScanner.DeletionRequest]::new(
            [string]$path, $sha256, [string]$signature
        ))
        $script:deletionSignatureByPath[[string]$path] = $signature
        $rowsForFile = New-Object 'System.Collections.Generic.List[System.Windows.Forms.ListViewItem]'
        $selectedIdentity = [string]$identityByPath[$path]
        foreach ($candidateRow in $script:resultsView.Items) {
            if (-not $candidateRow.Tag) { continue }
            $candidatePath = [string]$candidateRow.Tag.Path
            if ([System.StringComparer]::Ordinal.Equals($candidatePath, $path)) {
                $rowsForFile.Add($candidateRow)
                continue
            }
            if (-not $selectedIdentity -or -not [System.StringComparer]::OrdinalIgnoreCase.Equals($candidatePath, $path)) {
                continue
            }
            try {
                $candidateIdentity = [ProtectionScanner.SafeFileDeletion]::GetFileIdentity($candidatePath)
                if ([string]::Equals($candidateIdentity, $selectedIdentity, [System.StringComparison]::Ordinal)) {
                    $rowsForFile.Add($candidateRow)
                }
            }
            catch { $identityLookupFailed = $true }
        }
        $script:deletionRowsByPath[[string]$path] = $rowsForFile.ToArray()
    }
    if ($identityLookupFailed) {
        $script:deletionRowsByPath = New-ExactPathMap
        $script:deletionSignatureByPath = New-ExactPathMap
        [System.Windows.Forms.MessageBox]::Show(
            'Не удалось проверить идентификатор одного из файлов с похожим путём. Удаление не запущено.',
            'Не удалось проверить файл',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }

    try {
        $script:deletionAppliedCount = 0
        $script:deletionBatch = [ProtectionScanner.DeletionBatch]::new(
            $requests.ToArray(), [string]$script:enginePath, [string]$script:databaseDirectory,
            [string](Join-Path $script:dataRoot 'verification-temp'), $true
        )
        $script:deletionMode = 'Verify'
        $script:deletionBatch.Start()
        $script:progressBar.Value = 0
        $script:statusLabel.Text = ('Перед запросом согласия повторно проверяю {0} выбранных файлов…' -f $requests.Count)
        Set-ScanControls -Busy $true
        $script:timer.Start()
    }
    catch {
        $script:deletionBatch = $null
        $script:deletionRowsByPath = New-ExactPathMap
        $script:deletionSignatureByPath = New-ExactPathMap
        $script:verifiedDeletionByPath = New-ExactPathMap
        $script:deletionMode = $null
        Set-ScanControls -Busy $false
        [System.Windows.Forms.MessageBox]::Show(
            ('Не удалось начать проверку перед подтверждением: ' + $_.Exception.Message),
            'Ошибка проверки',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
})
$script:openLogsButton.Add_Click({ Start-Process -FilePath 'explorer.exe' -ArgumentList (Quote-ProcessArgument -Value $script:logsDirectory) })
$form.Add_FormClosing({
    param($sender, $eventArgs)
    if ($script:allowFormClose) { return }
    if ($script:deletionBatch) {
        $eventArgs.Cancel = $true
        $script:closeAfterDeletion = $true
        $script:statusLabel.Text = 'Жду остановки ClamAV и очистки временных файлов перед закрытием…'
        try { $script:deletionBatch.Cancel() } catch { }
        return
    }
    if ($script:scanMonitor) {
        try { $script:scanMonitor.CancelHashing() } catch { }
    }
    if ($script:activeProcess) {
        try { $script:activeProcess.Kill() } catch { }
    }
    if ($script:countJob) {
        try { Stop-Job -Job $script:countJob -ErrorAction SilentlyContinue } catch { }
        try { Remove-Job -Job $script:countJob -Force -ErrorAction SilentlyContinue } catch { }
    }
    Remove-Item -LiteralPath $script:countTargetsPath,$script:countProgressPath -Force -ErrorAction SilentlyContinue
})

Find-ClamAV
Write-FreshClamConfig
Update-StatusDisplay
[void]$form.ShowDialog()
