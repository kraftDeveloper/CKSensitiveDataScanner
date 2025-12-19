using Newtonsoft.Json;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using System.Web;

namespace CKSensitiveDataScanner
{
    class Program
    {
        private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromMinutes(15) };
        private static string _aiEndpoint;
        private static string _aiModel;
        private static string _apiKey;
        private static string _selectedAiService;
        private static string[] _relevantExtensions;
        private static string[] _excludeFolders;
        private static int _totalFiles = 0;
        private static int _filesSentToOllama = 0;
        private static int _filesWithFindings = 0;
        private static readonly List<(string FileName, string RelativePath, string FullFindings)> _findingsList = new();
        private static readonly List<(string FileName, string RelativePath, string RegexAlerts, string ProblematicSnippets)> _regexAlertsList = new();
        private static bool _showOllamaPrompt = false;
        private static bool _includeUnitTestProjects = true;
        private static bool _useFullContentForLargeFiles = true;
        private static int _truncationThreshold = 15000;
        private static StreamWriter _logWriter;
        private static TextWriter _originalConsoleOut;
        private class SolutionConfig
        {
            public int Id { get; set; }
            public string Path { get; set; }
        }
        private class Config
        {
            public string OllamaEndpoint { get; set; }
            public string OllamaModel { get; set; }
            public string OpenAIApiKey { get; set; }
            public string OpenAIModel { get; set; }
            public string GeminiApiKey { get; set; }
            public string GeminiModel { get; set; }
            public string AnthropicApiKey { get; set; }
            public string AnthropicModel { get; set; }
            public string GrokApiKey { get; set; }
            public string GrokModel { get; set; }
            public int TruncationThreshold { get; set; }
            public List<SolutionConfig> Solutions { get; set; }
            public string[] RelevantExtensions { get; set; }
            public string[] ExcludeFolders { get; set; }
        }
        private static Config _config;
        private class DualWriter : TextWriter
        {
            private readonly TextWriter _console;
            private readonly TextWriter _file;
            public DualWriter(TextWriter console, TextWriter file)
            {
                _console = console;
                _file = file;
            }
            public override Encoding Encoding => Encoding.UTF8;
            public override void Write(char value) { _console.Write(value); _file.Write(value); }
            public override void Write(string value) { _console.Write(value); _file.Write(value); }
            public override void WriteLine(string value) { _console.WriteLine(value); _file.WriteLine(value); }
            public override void Flush() { _console.Flush(); _file.Flush(); }
        }

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            _originalConsoleOut = Console.Out;
            while (true)
            {
                _totalFiles = 0;
                _filesSentToOllama = 0;
                _filesWithFindings = 0;
                _findingsList.Clear();
                _regexAlertsList.Clear();
                LoadConfig();
                Console.WriteLine("=== Sensitive Data Scanner ===\n");
                Console.WriteLine("Select AI service:");
                Console.WriteLine("1. Ollama (default)");
                Console.WriteLine("2. OpenAI / ChatGPT");
                Console.WriteLine("3. Google Gemini");
                Console.WriteLine("4. Anthropic Claude");
                Console.WriteLine("5. Grok (xAI)");
                Console.Write("\nChoice (1-5, Enter for Ollama): ");
                string choice = Console.ReadLine()?.Trim();
                switch (choice)
                {
                    case "2":
                        _selectedAiService = "openai";
                        _aiModel = _config.OpenAIModel ?? "gpt-4o-mini";
                        _apiKey = _config.OpenAIApiKey;
                        _aiEndpoint = "https://api.openai.com/v1/chat/completions";
                        break;
                    case "3":
                        _selectedAiService = "gemini";
                        _aiModel = _config.GeminiModel ?? "gemini-1.5-flash";
                        _apiKey = _config.GeminiApiKey;
                        _aiEndpoint = "https://generativelanguage.googleapis.com/v1beta/models/" + _aiModel + ":generateContent";
                        break;
                    case "4":
                        _selectedAiService = "anthropic";
                        _aiModel = _config.AnthropicModel ?? "claude-3-sonnet-20240229";
                        _apiKey = _config.AnthropicApiKey;
                        _aiEndpoint = "https://api.anthropic.com/v1/messages";
                        break;
                    case "5":
                        _selectedAiService = "grok";
                        _aiModel = _config.GrokModel ?? "grok-beta";
                        _apiKey = _config.GrokApiKey;
                        _aiEndpoint = "https://api.x.ai/v1/chat/completions";
                        break;
                    default:
                        _selectedAiService = "ollama";
                        _aiEndpoint = _config.OllamaEndpoint;
                        Console.WriteLine("\nAvailable Ollama models:");
                        Console.WriteLine("1. codestral:22b");
                        Console.WriteLine("2. deepseek-coder-v2:16b");
                        Console.WriteLine("3. gemma2:9b-instruct-q4_K_M");
                        Console.WriteLine("4. gemma3:27b");
                        Console.WriteLine("5. gpt-oss:20b (default)");
                        Console.WriteLine("6. hf.co/unsloth/Mistral-Small-3.2-24B-Instruct-2506-GGUF:UD-Q4_K_XL");
                        Console.WriteLine("7. llama3.1:8b-instruct-q5_K_M");
                        Console.WriteLine("8. mistral:latest");
                        Console.WriteLine("9. mistral-nemo:latest");
                        Console.WriteLine("10. phi4:14b");
                        Console.WriteLine("11. qwen2.5:7b-instruct-q5_K_M");
                        Console.WriteLine("12. qwen2.5-coder:14b");
                        Console.WriteLine("13. qwen2.5-coder:32b");
                        Console.WriteLine("14. qwen3:30b-a3b");
                        Console.Write("\nSelect Ollama model (1-13, Enter for gpt-oss:20b): ");
                        string modelChoice = Console.ReadLine()?.Trim();
                        _aiModel = modelChoice switch
                        {
                            "1" => "codestral:22b",
                            "2" => "deepseek-coder-v2:16b",
                            "3" => "gemma2:9b-instruct-q4_K_M",
                            "4" => "gemma3:27b",
                            "5" or "" => "gpt-oss:20b",
                            "6" => "hf.co/unsloth/Mistral-Small-3.2-24B-Instruct-2506-GGUF:UD-Q4_K_XL",
                            "7" => "llama3.1:8b-instruct-q5_K_M",
                            "8" => "mistral:latest",
                            "9" => "mistral-nemo:latest",
                            "10" => "phi4:14b",
                            "11" => "qwen2.5:7b-instruct-q5_K_M",
                            "12" => "qwen2.5-coder:14b",
                            "13" => "qwen2.5-coder:32b",
                            "14" => "qwen3:30b-a3b",
                            _ => "gpt-oss:20b"
                        };
                        break;
                }
                Console.WriteLine($"\nUsing: {_selectedAiService.ToUpper()} ({_aiModel})\n");
                if (_selectedAiService != "ollama" && string.IsNullOrEmpty(_apiKey))
                {
                    Console.WriteLine("API key missing for selected service.");
                    continue;
                }
                Console.Write("Show the full Ollama prompt for each file? (y/n, default: n): ");
                string input = Console.ReadLine()?.Trim().ToLower();
                _showOllamaPrompt = input == "y" || input == "yes";
                Console.WriteLine(_showOllamaPrompt ? "→ Full Ollama prompts will be displayed.\n" : "→ Ollama prompts will be hidden (quiet mode).\n");
                Console.Write("Include Unit Test projects (e.g., *.Tests, *.UnitTests)? (y/n, default: y): ");
                string testInput = Console.ReadLine()?.Trim().ToLower();
                _includeUnitTestProjects = string.IsNullOrEmpty(testInput) || testInput == "y" || testInput == "yes";
                Console.WriteLine(_includeUnitTestProjects ? "→ Unit Test projects will be included in the scan.\n" : "→ Unit Test projects will be skipped.\n");
                Console.Write("For large files (> threshold), send FULL content to Ollama or use truncated start+end? (f/t, default: f for full): ");
                string largeInput = Console.ReadLine()?.Trim().ToLower();
                _useFullContentForLargeFiles = string.IsNullOrEmpty(largeInput) || largeInput == "f" || largeInput == "full";
                if (!_useFullContentForLargeFiles)
                {
                    Console.Write($"Truncation threshold in characters (default: {_truncationThreshold}, press Enter to keep): ");
                    string threshInput = Console.ReadLine()?.Trim();
                    if (int.TryParse(threshInput, out int custom) && custom >= 1000)
                    {
                        _truncationThreshold = custom;
                        Console.WriteLine($"→ Threshold set to {_truncationThreshold} characters.\n");
                    }
                    else if (!string.IsNullOrEmpty(threshInput))
                    {
                        Console.WriteLine($"→ Invalid value. Using default: {_truncationThreshold} characters.\n");
                    }
                    else
                    {
                        Console.WriteLine($"→ Using default threshold: {_truncationThreshold} characters.\n");
                    }
                }
                else
                {
                    Console.WriteLine("→ All files will be sent in FULL to Ollama (may be slow or hit token limits).\n");
                }
                var solutions = new Dictionary<int, string>();
                if (_config?.Solutions != null && _config.Solutions.Count > 0)
                {
                    foreach (var sol in _config.Solutions)
                    {
                        solutions[sol.Id] = sol.Path;
                    }
                }
                else
                {
                    Console.WriteLine("No solutions defined in config. Exiting.");
                    return;
                }
                Console.WriteLine("\nSelect the solution to scan:");
                foreach (var kv in solutions.OrderBy(k => k.Key))
                {
                    string displayName = Path.GetFileName(Path.GetDirectoryName(kv.Value.TrimEnd(Path.DirectorySeparatorChar)));
                    Console.WriteLine($"{kv.Key,2}. {displayName}");
                }
                Console.Write("\nEnter number: ");
                string choiceNum = Console.ReadLine()?.Trim();
                if (!int.TryParse(choiceNum, out int selected) || !solutions.ContainsKey(selected))
                {
                    Console.WriteLine("Invalid selection.");
                    continue;
                }
                string selectedRoot = solutions[selected];
                var slnFiles = Directory.GetFiles(selectedRoot, "*.sln", SearchOption.TopDirectoryOnly);
                if (slnFiles.Length == 0)
                {
                    Console.WriteLine("No .sln file found in selected folder.");
                    continue;
                }
                string solutionPath = slnFiles[0];
                Console.WriteLine($"\nUsing solution: {solutionPath}\n");
                string solutionDir = Path.GetDirectoryName(solutionPath)!;
                string solutionName = Path.GetFileNameWithoutExtension(solutionPath);
                string selectedDisplayName = Path.GetFileName(Path.GetDirectoryName(selectedRoot.TrimEnd(Path.DirectorySeparatorChar)));
                string safeTargetName = string.Join("_", selectedDisplayName.Split(Path.GetInvalidFileNameChars()));
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                string outputDir = Environment.CurrentDirectory;
                string logFileName = $"SensitiveDataScan_Log_{safeTargetName}_{timestamp}.txt";
                string reportFileName = $"SensitiveDataScan_Report_{safeTargetName}_{timestamp}.html";
                string logPath = Path.Combine(outputDir, logFileName);
                string reportPath = Path.Combine(outputDir, reportFileName);
                _logWriter = new StreamWriter(logPath, false, Encoding.UTF8) { AutoFlush = true };
                Console.SetOut(new DualWriter(_originalConsoleOut, _logWriter));
                Console.WriteLine("=== Sensitive Data Scanner ===\n");
                Console.WriteLine($"Selected target: {selectedDisplayName}");
                Console.WriteLine($"Scan date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");
                var projectPaths = ParseSolutionFile(solutionPath);
                var filteredProjects = projectPaths
                    .Where(p => _includeUnitTestProjects ||
                                !(p.Contains("\\Tests\\", StringComparison.OrdinalIgnoreCase) ||
                                  p.Contains("/Tests/", StringComparison.OrdinalIgnoreCase) ||
                                  p.Contains("\\UnitTests\\", StringComparison.OrdinalIgnoreCase) ||
                                  p.Contains("/UnitTests/", StringComparison.OrdinalIgnoreCase) ||
                                  Path.GetFileNameWithoutExtension(p).EndsWith(".Tests", StringComparison.OrdinalIgnoreCase) ||
                                  Path.GetFileNameWithoutExtension(p).EndsWith(".Test", StringComparison.OrdinalIgnoreCase) ||
                                  Path.GetFileNameWithoutExtension(p).Contains("UnitTests", StringComparison.OrdinalIgnoreCase) ||
                                  Path.GetFileNameWithoutExtension(p).Contains("Tests", StringComparison.OrdinalIgnoreCase) ||
                                  Path.GetFileNameWithoutExtension(p).Contains(".UnitTests", StringComparison.OrdinalIgnoreCase)))
                    .ToList();
                Console.WriteLine($"Found {filteredProjects.Count} project(s) to scan (out of {projectPaths.Count} total in solution).\n");
                var allFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var relativeProjPath in filteredProjects)
                {
                    string fullProjPath = Path.Combine(solutionDir, relativeProjPath);
                    if (!File.Exists(fullProjPath))
                    {
                        Console.WriteLine($"Warning: Project file not found: {fullProjPath}");
                        continue;
                    }
                    string projectDir = Path.GetDirectoryName(fullProjPath)!;
                    Console.WriteLine($"Processing project: {Path.GetFileName(fullProjPath)}");
                    var projectFiles = CollectAllRelevantFiles(projectDir, fullProjPath);
                    Console.WriteLine($" → Found {projectFiles.Count} relevant files\n");
                    foreach (var file in projectFiles)
                    {
                        allFiles.Add(file);
                    }
                }
                var uniqueFiles = allFiles.OrderBy(f => f).ToList();
                _totalFiles = uniqueFiles.Count;
                Console.WriteLine($"Total files to scan with Ollama: {_totalFiles}\n");
                Console.WriteLine("Starting in-depth analysis...\n");
                int index = 0;
                foreach (var file in uniqueFiles)
                {
                    index++;
                    string relativePath = Path.GetRelativePath(solutionDir, file);
                    Console.WriteLine($"[{index}/{_totalFiles}] Analyzing: {Path.GetFileName(file)}");
                    Console.WriteLine($" Path: {relativePath}");
                    try
                    {
                        string content = File.ReadAllText(file);
                        long size = new FileInfo(file).Length;
                        Console.WriteLine($" Size: {size:#,##0} bytes");
                        if (string.IsNullOrWhiteSpace(content))
                        {
                            Console.WriteLine(" → Empty file. Skipping.\n");
                            continue;
                        }
                        var (regexHits, snippets) = QuickRegexScan(content);
                        if (regexHits.Any())
                        {
                            Console.WriteLine(new string('-', 80) + "\n");
                            Console.WriteLine(" *** QUICK REGEX ALERT ***");
                            foreach (var hit in regexHits) Console.WriteLine($" • {hit}");
                            Console.WriteLine(new string('-', 80) + "\n");
                            Console.WriteLine();
                            string alertsText = string.Join(" | ", regexHits);
                            string snippetText = string.Join(" | ", snippets.Take(3).Select(s => s.Length > 60 ? s.Substring(0, 57) + "..." : s));
                            if (snippets.Count > 3) snippetText += " | ...";
                            _regexAlertsList.Add((Path.GetFileName(file), relativePath, alertsText, snippetText));
                        }
                        _filesSentToOllama++;
                        Console.WriteLine(" → Sending to Ollama...");
                        var (prompt, _, truncated) = BuildOllamaPrompt(content, Path.GetFileName(file), size, relativePath);
                        if (_showOllamaPrompt)
                        {
                            Console.WriteLine(" === EXACT OLLAMA PROMPT ===");
                            Console.WriteLine(prompt);
                            Console.WriteLine(" === END OF PROMPT ===\n");
                        }
                        if (truncated)
                            Console.WriteLine(" → Content truncated (start + end shown)\n");
                        var sw = Stopwatch.StartNew();
                        string result = await SendToOllamaAsync(prompt);
                        sw.Stop();
                        Console.WriteLine($" → Response time: {sw.ElapsedMilliseconds} ms\n");
                        if (!string.IsNullOrWhiteSpace(result) &&
                            !result.Contains("No sensitive data found", StringComparison.OrdinalIgnoreCase))
                        {
                            _filesWithFindings++;
                            Console.WriteLine(new string('-', 80) + "\n");
                            Console.WriteLine(" *** OLLAMA DETECTED POTENTIAL SECRET(S) ***");
                            Console.Beep();
                            Console.WriteLine(result.Trim());
                            Console.WriteLine(new string('-', 80) + "\n");
                            _findingsList.Add((Path.GetFileName(file), relativePath, result.Trim()));
                        }
                        else
                        {
                            Console.WriteLine(" → Ollama: Clean – no sensitive data.\n");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($" *** ERROR: {ex.Message} ***\n");
                    }
                }
                Console.WriteLine("==========================================");
                Console.WriteLine(" SCAN COMPLETE ");
                Console.WriteLine("==========================================");
                Console.WriteLine($"Total files processed : {_totalFiles}");
                Console.WriteLine($"Sent to Ollama : {_filesSentToOllama}");
                Console.WriteLine($"With confirmed secrets (Ollama) : {_filesWithFindings}");
                Console.WriteLine($"Clean files : {_totalFiles - _filesWithFindings}");
                Console.WriteLine("==========================================\n");
                if (_filesWithFindings > 0)
                {
                    Console.WriteLine("CONFIRMED SECRETS FOUND (by Ollama):\n");
                    Console.WriteLine($"{"File".PadRight(35)} | {"Relative Path".PadRight(60)} | Finding Summary");
                    Console.WriteLine(new string('-', 160));
                    foreach (var finding in _findingsList)
                    {
                        string summary = finding.FullFindings.Length > 80 ? finding.FullFindings.Substring(0, 77) + "..." : finding.FullFindings;
                        Console.WriteLine($"{finding.FileName.PadRight(35)} | {finding.RelativePath.PadRight(60)} | {summary}");
                    }
                    Console.WriteLine(new string('-', 160));
                }
                else
                {
                    Console.WriteLine("🎉 No confirmed secrets detected by Ollama!\n");
                }
                if (_regexAlertsList.Any())
                {
                    Console.WriteLine("POTENTIAL ISSUES FOUND BY QUICK REGEX (to be manually checked):\n");
                    Console.WriteLine($"{"File".PadRight(35)} | {"Relative Path".PadRight(60)} | Alerts | Problematic Snippets");
                    Console.WriteLine(new string('-', 180));
                    foreach (var alert in _regexAlertsList)
                    {
                        Console.WriteLine($"{alert.FileName.PadRight(35)} | {alert.RelativePath.PadRight(60)} | {alert.RegexAlerts} | {alert.ProblematicSnippets}");
                    }
                    Console.WriteLine(new string('-', 180));
                    Console.WriteLine($"Note: These {_regexAlertsList.Count} file(s) triggered quick regex patterns.");
                    Console.WriteLine(" They may be false positives — manual review recommended.\n");
                }
                GenerateHtmlReport(reportPath, solutionName, _totalFiles, _filesSentToOllama, _filesWithFindings, _findingsList, _regexAlertsList);
                Console.WriteLine($"\nHTML detailed report saved to:\n{reportPath}\n");
                Console.WriteLine($"Full console log saved to:\n{logPath}\n");
                OpenHtmlReportInBrowser(reportPath);
                _logWriter.Close();
                Console.SetOut(_originalConsoleOut);
                Console.WriteLine("\nScan finished.");
                Console.Write("Start a new scan? (y/n): ");
                string again = Console.ReadLine()?.Trim().ToLower();
                if (again != "y" && again != "yes")
                {
                    Console.WriteLine("Goodbye!");
                    break;
                }
                Console.Clear();
            }
        }
        
        private static void LoadConfig()
        {
            string configPath = Path.Combine(Environment.CurrentDirectory, "config.json");
            _config = new Config
            {
                OllamaEndpoint = "http://192.168.10.12:11434/api/generate",
                OllamaModel = "gpt-oss:20b",
                TruncationThreshold = 15000,
                RelevantExtensions = new[] { ".cs", ".csproj", ".config", ".json", ".xml", ".settings", ".props", ".targets", ".txt", ".cshtml", ".razor" },
                ExcludeFolders = new[] { "bin", "obj", ".git", ".vs", "node_modules", "packages" },
                Solutions = new List<SolutionConfig>
                {
                    new() { Id = 1, Path = @"C:\m2trust\m2trust.BCL\src" },
                    new() { Id = 2, Path = @"C:\m2trust\m2trust.ClientAPI\src" },
                    new() { Id = 3, Path = @"C:\m2trust\m2trust.Core\src" },
                    new() { Id = 4, Path = @"C:\m2trust\m2trust.Enrollment\src" },
                    new() { Id = 5, Path = @"C:\m2trust\m2trust.Infrastructure\src" },
                    new() { Id = 6, Path = @"C:\m2trust\m2trust.Subsystem.DCP\src" },
                    new() { Id = 7, Path = @"C:\m2trust\m2trust.Subsystem.DeviceManagement\src" },
                    new() { Id = 8, Path = @"C:\m2trust\m2trust.Subsystem.PKI\src" },
                    new() { Id = 9, Path = @"C:\m2trust\m2trust.UserPortal\src" }
                }
            };
            if (!File.Exists(configPath))
            {
                Console.WriteLine("config.json not found. Using built-in defaults.");
                AssignConfigValues();
                return;
            }
            try
            {
                string json = File.ReadAllText(configPath);
                var loaded = JsonConvert.DeserializeObject<Config>(json);
                _config.OllamaEndpoint = loaded.OllamaEndpoint ?? _config.OllamaEndpoint;
                _config.OllamaModel = loaded.OllamaModel ?? _config.OllamaModel;
                _config.OpenAIApiKey = loaded.OpenAIApiKey;
                _config.OpenAIModel = loaded.OpenAIModel;
                _config.GeminiApiKey = loaded.GeminiApiKey;
                _config.GeminiModel = loaded.GeminiModel;
                _config.AnthropicApiKey = loaded.AnthropicApiKey;
                _config.AnthropicModel = loaded.AnthropicModel;
                _config.GrokApiKey = loaded.GrokApiKey;
                _config.GrokModel = loaded.GrokModel;
                _config.TruncationThreshold = loaded.TruncationThreshold > 0 ? loaded.TruncationThreshold : _config.TruncationThreshold;
                _config.RelevantExtensions = loaded.RelevantExtensions?.Length > 0 ? loaded.RelevantExtensions : _config.RelevantExtensions;
                _config.ExcludeFolders = loaded.ExcludeFolders?.Length > 0 ? loaded.ExcludeFolders : _config.ExcludeFolders;
                _config.Solutions = loaded.Solutions?.Count > 0 ? loaded.Solutions : _config.Solutions;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading config.json: {ex.Message}. Using defaults.");
            }
            AssignConfigValues();
        }
        private static void AssignConfigValues()
        {
            _relevantExtensions = _config.RelevantExtensions;
            _excludeFolders = _config.ExcludeFolders;
            _truncationThreshold = _config.TruncationThreshold;
        }
        private static (string prompt, string displayContent, bool truncated) BuildOllamaPrompt(string content, string fileName, long fileSize, string relativePath)
        {
            bool truncated = false;
            string processedContent = content;
            if (!_useFullContentForLargeFiles && content.Length > _truncationThreshold)
            {
                truncated = true;
                int part = Math.Min(7000, _truncationThreshold / 2);
                string start = content.Substring(0, part);
                string end = content.Length > part * 2 ? content.Substring(content.Length - part) : "";
                processedContent = $"{start}\n\n--- [TRUNCATED {content.Length - (start.Length + end.Length)} characters in the middle] ---\n\n{end}";
            }
            processedContent += $"\n\n// File: {fileName} | Path: {relativePath} | Size: {fileSize} bytes";
            string prompt = $@"You are an expert .NET/C# security analyst scanning source code for leaked secrets.
File: {fileName}
Relative Path: {relativePath}
Extension: {Path.GetExtension(fileName)}
Size: {fileSize} bytes
Content is {(truncated ? "PARTIAL (start + end only)" : "COMPLETE")}
TASK: Detect any sensitive data that should NEVER be committed to source control:
• Hardcoded passwords, connection strings, API keys, tokens
• AWS/Azure/GCP keys (e.g., AKIA..., Azure secrets)
• JWT secrets, private keys, certificates
• Internal endpoints with credentials
• Internal/private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
• Internal hostnames or FQDNs (e.g., server01.corp.company.com, db.internal)
• Real personal/colleague/partner email addresses (especially in tests, comments or config)
• Real credentials or PII in tests/configs
STRICT RESPONSE RULES — YOU MUST OBEY:
1. If NO sensitive data found → Respond EXACTLY: ""No sensitive data found.""
2. If secrets ARE found → Use ONLY this format (max 10 lines total):
   File: {fileName}
   Path: {relativePath}
   Findings:
   - Type: [e.g., API Key, Password, Internal IP, Internal FQDN, Email Address]
     Value: [exact snippet or pattern found]
     Location: [beginning / middle / end]
     Risk: [High / Medium / Low]
   - [next finding...]
3. Be extremely concise.
4. Never explain reasoning.
5. Never suggest fixes.
6. Never output code blocks.
7. NEVER output Python code or examples.
8. If showing code, use C# syntax ONLY.
Content:
{processedContent}";
            return (prompt, processedContent, truncated);
        }
        private static async Task<string> SendToOllamaAsync(string prompt)
        {
            try
            {
                string json;
                HttpContent content;
                HttpResponseMessage response;
                if (_selectedAiService == "ollama")
                {
                    json = JsonConvert.SerializeObject(new
                    {
                        model = _aiModel,
                        prompt,
                        stream = false,
                        options = new
                        {
                            temperature = 0.1,
                            num_ctx = 8192,
                            num_predict = 600
                        }
                    });
                    content = new StringContent(json, Encoding.UTF8, "application/json");
                    response = await _httpClient.PostAsync(_aiEndpoint, content);
                    if (!response.IsSuccessStatusCode)
                        return $"HTTP Error {response.StatusCode}: {await response.Content.ReadAsStringAsync()}";
                    dynamic obj = JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());
                    return obj?.response?.ToString()?.Trim() ?? "No sensitive data found.";
                }
                else if (_selectedAiService == "openai" || _selectedAiService == "grok")
                {
                    json = JsonConvert.SerializeObject(new
                    {
                        model = _aiModel,
                        messages = new[] { new { role = "user", content = prompt } },
                        temperature = 0.1,
                        max_tokens = 600
                    });
                    content = new StringContent(json, Encoding.UTF8, "application/json");
                    _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _apiKey);
                    response = await _httpClient.PostAsync(_aiEndpoint, content);
                    _httpClient.DefaultRequestHeaders.Authorization = null;
                    if (!response.IsSuccessStatusCode)
                        return $"HTTP Error {response.StatusCode}: {await response.Content.ReadAsStringAsync()}";
                    dynamic obj = JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());
                    return obj?.choices?[0]?.message?.content?.ToString()?.Trim() ?? "No sensitive data found.";
                }
                else if (_selectedAiService == "gemini")
                {
                    json = JsonConvert.SerializeObject(new
                    {
                        contents = new[] { new { role = "user", parts = new[] { new { text = prompt } } } },
                        generationConfig = new { temperature = 0.1, maxOutputTokens = 600 }
                    });
                    response = await _httpClient.PostAsync($"{_aiEndpoint}?key={_apiKey}", new StringContent(json, Encoding.UTF8, "application/json"));
                    if (!response.IsSuccessStatusCode)
                        return $"HTTP Error {response.StatusCode}: {await response.Content.ReadAsStringAsync()}";
                    dynamic obj = JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());
                    return obj?.candidates?[0]?.content?.parts?[0]?.text?.ToString()?.Trim() ?? "No sensitive data found.";
                }
                else if (_selectedAiService == "anthropic")
                {
                    json = JsonConvert.SerializeObject(new
                    {
                        model = _aiModel,
                        max_tokens = 600,
                        temperature = 0.1,
                        messages = new[] { new { role = "user", content = prompt } }
                    });
                    content = new StringContent(json, Encoding.UTF8, "application/json");
                    _httpClient.DefaultRequestHeaders.Clear();
                    _httpClient.DefaultRequestHeaders.Add("x-api-key", _apiKey);
                    _httpClient.DefaultRequestHeaders.Add("anthropic-version", "2023-06-01");
                    response = await _httpClient.PostAsync(_aiEndpoint, content);
                    _httpClient.DefaultRequestHeaders.Clear();
                    if (!response.IsSuccessStatusCode)
                        return $"HTTP Error {response.StatusCode}: {await response.Content.ReadAsStringAsync()}";
                    dynamic obj = JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());
                    return obj?.content?[0]?.text?.ToString()?.Trim() ?? "No sensitive data found.";
                }
                return "Error: Unknown AI service";
            }
            catch (TaskCanceledException)
            {
                return "Error: Request timed out";
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }
        private static void GenerateHtmlReport(string reportPath, string solutionName, int totalFiles, int sentToOllama, int filesWithFindings,
            List<(string FileName, string RelativePath, string FullFindings)> findings,
            List<(string FileName, string RelativePath, string RegexAlerts, string ProblematicSnippets)> regexAlerts)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Sensitive Data Scan Report</title>");
            sb.AppendLine("<style>body{font-family:Arial,sans-serif;margin:40px;background:#f9f9f9;color:#333;}h1{color:#d32f2f;}h2{color:#1976d2;}");
            sb.AppendLine("table{width:100%;border-collapse:collapse;margin:25px 0;background:white;box-shadow:0 2px 10px rgba(0,0,0,0.1);}");
            sb.AppendLine("th,td{padding:12px 15px;text-align:left;border-bottom:1px solid #ddd;}th{background:#1976d2;color:white;}tr:hover{background:#f1f1f1;}");
            sb.AppendLine(".summary{background:#e3f2fd;padding:20px;border-radius:8px;margin-bottom:30px;}.finding{white-space:pre-wrap;font-family:Consolas,monospace;background:#fff3e0;padding:10px;border-radius:5px;}");
            sb.AppendLine(".regex-alert{background:#fff8e1;padding:10px;border-left:4px solid #ffb300;border-radius:5px;}.no-findings{color:#2e7d32;font-weight:bold;}</style>");
            sb.AppendLine("</head><body>");
            sb.AppendLine($"<h1>Sensitive Data Scan Report - {solutionName}</h1>");
            sb.AppendLine($"<p><strong>Scan completed on:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine("<div class=\"summary\"><h2>Scan Summary</h2>");
            sb.AppendLine($"<p><strong>Total files processed:</strong> {totalFiles}</p>");
            sb.AppendLine($"<p><strong>Files sent to Ollama:</strong> {sentToOllama}</p>");
            sb.AppendLine($"<p><strong>Confirmed secrets (Ollama):</strong> {filesWithFindings}</p>");
            sb.AppendLine($"<p><strong>Clean files:</strong> {totalFiles - filesWithFindings}</p></div>");
            if (filesWithFindings > 0)
            {
                sb.AppendLine("<h2>Confirmed Secrets (detected by Ollama)</h2><table><thead><tr><th>File Name</th><th>Relative Path</th><th>Detailed Findings</th></tr></thead><tbody>");
                foreach (var finding in findings)
                {
                    string escaped = HttpUtility.HtmlEncode(finding.FullFindings).Replace("\n", "<br>");
                    sb.AppendLine($"<tr><td><strong>{HttpUtility.HtmlEncode(finding.FileName)}</strong></td><td>{HttpUtility.HtmlEncode(finding.RelativePath)}</td><td class=\"finding\">{escaped}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-findings\">🎉 No confirmed secrets detected by Ollama!</p>");
            }
            if (regexAlerts.Any())
            {
                sb.AppendLine("<h2>Potential Issues from Quick Regex Scan (manual review recommended)</h2>");
                sb.AppendLine("<table><thead><tr><th>File Name</th><th>Relative Path</th><th>Alerts</th><th>Problematic Snippets</th></tr></thead><tbody>");
                foreach (var alert in regexAlerts)
                {
                    string alertsEsc = HttpUtility.HtmlEncode(alert.RegexAlerts);
                    string snippetsEsc = HttpUtility.HtmlEncode(alert.ProblematicSnippets);
                    sb.AppendLine($"<tr><td><strong>{HttpUtility.HtmlEncode(alert.FileName)}</strong></td><td>{HttpUtility.HtmlEncode(alert.RelativePath)}</td><td class=\"regex-alert\">{alertsEsc}</td><td class=\"regex-alert\">{snippetsEsc}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
                sb.AppendLine("<p><strong>Note:</strong> These files triggered fast regex patterns (e.g., internal IPs, emails, password-like strings). They may include false positives and should be manually verified.</p>");
            }
            sb.AppendLine("</body></html>");
            File.WriteAllText(reportPath, sb.ToString());
        }
        private static void OpenHtmlReportInBrowser(string reportPath)
        {
            try
            {
                var psi = new ProcessStartInfo { FileName = reportPath, UseShellExecute = true };
                Process.Start(psi);
                Console.WriteLine("→ Report opened in default browser.");
            }
            catch
            {
                string[] browsers = { "msedge", "chrome", "firefox" };
                bool opened = false;
                foreach (var browser in browsers)
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo { FileName = browser, Arguments = $"\"{reportPath}\"", UseShellExecute = true });
                        Console.WriteLine($"→ Report opened in {browser}.");
                        opened = true;
                        break;
                    }
                    catch { }
                }
                if (!opened)
                {
                    Console.WriteLine("→ Could not open browser automatically. Please open manually:");
                    Console.WriteLine($" {reportPath}");
                }
            }
        }
        private static List<string> ParseSolutionFile(string solutionPath)
        {
            var projects = new List<string>();
            var lines = File.ReadAllLines(solutionPath);
            var regex = new Regex(@"Project\(""\{.*\}""\)\s*=\s*""[^""]*"",\s*""([^""]+\.csproj)"",\s*""\{.*\}""", RegexOptions.IgnoreCase);
            foreach (var line in lines)
            {
                var match = regex.Match(line);
                if (match.Success)
                {
                    string relativePath = match.Groups[1].Value.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar);
                    projects.Add(relativePath);
                }
            }
            return projects;
        }
        private static List<string> CollectAllRelevantFiles(string projectDir, string projectFilePath)
        {
            var files = new List<string>();
            try
            {
                var doc = XDocument.Load(projectFilePath);
                bool isSdkStyle = doc.Root?.Attribute("Sdk") != null;
                var items = doc.Descendants()
                    .Where(e => e.Name.LocalName is "Compile" or "None" or "Content" or "EmbeddedResource")
                    .Select(e => e.Attribute("Include")?.Value)
                    .Where(v => !string.IsNullOrEmpty(v));
                foreach (var include in items)
                {
                    string fullPath = Path.GetFullPath(Path.Combine(projectDir, include.Replace('\\', Path.DirectorySeparatorChar)));
                    if (File.Exists(fullPath) && IsRelevantFile(fullPath))
                        files.Add(fullPath);
                }
                if (isSdkStyle || !items.Any())
                    files.Clear();
            }
            catch { }
            var allInDir = Directory.GetFiles(projectDir, "*", SearchOption.AllDirectories)
                .Where(f => IsRelevantFile(f) && !IsInExcludedFolder(f))
                .ToList();
            files.AddRange(allInDir);
            if (!files.Contains(projectFilePath, StringComparer.OrdinalIgnoreCase))
                files.Add(projectFilePath);
            return files.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        private static bool IsRelevantFile(string path) => _relevantExtensions.Contains(Path.GetExtension(path).ToLowerInvariant());
        private static bool IsInExcludedFolder(string path)
        {
            string normalized = path.Replace('\\', '/');
            return _excludeFolders.Any(ex =>
                normalized.Contains($"/{ex}/", StringComparison.OrdinalIgnoreCase) ||
                normalized.EndsWith($"/{ex}", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains($"/{ex}."));
        }
        private static (List<string> findings, List<string> snippets) QuickRegexScan(string content)
        {
            var findings = new List<string>();
            var snippets = new List<string>();
            var patterns = new (string pattern, string desc)[]
            {
                (@"password\s*[:=].{0,50}[""'][^""']{4,}[""']", "Potential password"),
                (@"api.?key\s*[:=].{0,50}[""'][A-Za-z0-9*/+=-]{20,}[""']", "Potential API key"),
                (@"secret\s*[:=].{0,50}[""'][^""']{10,}[""']", "Potential secret"),
                (@"AKIA[0-9A-Z]{16}", "Potential AWS Access Key"),
                (@"ghp_[0-9a-zA-Z]{36}", "Potential GitHub PAT"),
                (@"-----BEGIN [A-Z ]+PRIVATE KEY-----", "Private key block"),
                (@"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b", "Potential internal/private IP address"),
                (@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "Potential email address (colleague/partner/real PII)"),
                (@"\b[a-zA-Z0-9-]+(\.(corp|internal|dev|local|intranet|company|mycompany|mydomain))\b", "Potential internal FQDN/hostname")
            };
            foreach (var (pattern, desc) in patterns)
            {
                var regex = new Regex(pattern, RegexOptions.IgnoreCase);
                if (regex.IsMatch(content))
                {
                    findings.Add(desc);
                    var matches = regex.Matches(content);
                    foreach (Match m in matches)
                    {
                        string snippet = content.Substring(Math.Max(0, m.Index - 30), Math.Min(m.Length + 60, content.Length - Math.Max(0, m.Index - 30)));
                        snippet = Regex.Replace(snippet, @"[\r\n]+", " ");
                        if (!snippets.Contains(snippet))
                            snippets.Add(snippet);
                    }
                }
            }
            return (findings, snippets);
        }
    }
}