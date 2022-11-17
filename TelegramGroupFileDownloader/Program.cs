using System.Security.Cryptography;
using System.Text;
using ByteSizeLib;
using HeyRed.Mime;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Starksoft.Net.Proxy;
using TelegramGroupFileDownloader;
using TelegramGroupFileDownloader.Config;
using TelegramGroupFileDownloader.Database;
using TelegramGroupFileDownloader.Documents;
using TL;

// ReSharper disable SwitchStatementMissingSomeEnumCasesNoDefault

const string apiId = "2252206";
const string apiHash = "4dcf9af0c05042ca938a0a44bfb522dd";

var date = DateTimeOffset.Now.ToString("u").Replace(':', '_');
var errorLogFilePath = Path.Combine(Environment.CurrentDirectory, $"error-{date}.log");
var duplicateLogFilePath = Path.Combine(Environment.CurrentDirectory, $"duplicate-{date}.csv");
var filteredLogFilePath = Path.Combine(Environment.CurrentDirectory, $"filtered-{date}.log");
Utilities.TestApplicationFolderPath();
if (!File.Exists(duplicateLogFilePath))
    File.WriteAllText(duplicateLogFilePath, "Duplicate File,Original File,Link" + Environment.NewLine);
Utilities.CleanupLogs();
var config = new Configuration();
try
{
    var debug = args.Contains("-d");
    AnsiConsole.Write(
        new FigletText("Telegram Downloader")
            .Centered()
            .Color(Color.Orange1));
    await AnsiConsole.Status()
        .StartAsync("Initializing...", async ctx =>
        {
            ctx.Spinner = Spinner.Known.Bounce;
            await using (var db = new DocumentContext())
            {
                await db.Database.MigrateAsync();
            }

            config = ConfigurationManager.GetConfiguration();
            WTelegram.Helpers.Log = (lvl, str) => System.Diagnostics.Debug.WriteLine($"{lvl}: {str}");
        });

    if (string.IsNullOrWhiteSpace(config.PhoneNumber))
    {
        config.PhoneNumber =
            AnsiConsole.Prompt(new TextPrompt<string?>("Enter Phonenumber in [yellow]+1xxxxxxx[/] format:"));
        ConfigurationManager.SaveConfiguration(config);
    }

    if (string.IsNullOrWhiteSpace(config.GroupName))
    {
        config.GroupName = AnsiConsole.Prompt(
            new TextPrompt<string?>("Enter Telegram group name:"));
        ConfigurationManager.SaveConfiguration(config);
    }

    if (string.IsNullOrWhiteSpace(config.DownloadPath))
    {
        config.DownloadPath = AnsiConsole.Prompt(
                                  new TextPrompt<string?>("Enter target download folder:"))
                              ?? Environment.CurrentDirectory;
        ConfigurationManager.SaveConfiguration(config);
    }

    if (string.IsNullOrWhiteSpace(config.DocumentExtensionFilter))
    {
        config.DocumentExtensionFilter = AnsiConsole.Prompt(
            new TextPrompt<string?>("Enter comma separated list of allowed extensions:"));
        ConfigurationManager.SaveConfiguration(config);
    }

    var searchKey = string.IsNullOrEmpty(config.SearchKey) ? string.Empty : $"#{config.SearchKey}";
    AnsiConsole.MarkupLine("[blue]Config: [/]");
    AnsiConsole.MarkupLine("    PhoneNumber: [yellow]{0}[/]", config.PhoneNumber!);
    AnsiConsole.MarkupLine("    SessionPath: [yellow]{0}[/]", config.SessionPath);
    AnsiConsole.MarkupLine("    DownloadPath: [yellow]{0}[/]", config.DownloadPath);
    AnsiConsole.MarkupLine("    GroupName: [yellow]{0}[/]", config.GroupName!);
    AnsiConsole.MarkupLine("    SearchKey: [yellow]{0}[/]", searchKey);
    if (!string.IsNullOrEmpty(config.Socks5Host) && config.Socks5Port > 0)
        AnsiConsole.MarkupLine("    Socks5Proxy: [yellow]{0}:{1}[/]", config.Socks5Host, config.Socks5Port);
    AnsiConsole.MarkupLine("    DocumentExtensionFilter: [yellow]{0}[/]", config.DocumentExtensionFilter!);
    if (debug)
    {
        WTelegram.Helpers.Log = (lvl, str) =>
            AnsiConsole.MarkupLineInterpolated($"WTelegram: {Enum.GetName(typeof(LogLevel), lvl)} - {str}");
    }

    if (string.IsNullOrWhiteSpace(config.GroupName))
        throw new ConfigValueException(nameof(config.GroupName));
    if (string.IsNullOrWhiteSpace(config.PhoneNumber))
        throw new ConfigValueException(nameof(config.PhoneNumber));

    Utilities.EnsurePathExists(config.DownloadPath);
    if (!string.IsNullOrWhiteSpace(config.SessionPath))
        Utilities.EnsurePathExists(config.SessionPath);
    using var client = new WTelegram.Client(Config);
    client.CollectAccessHash = true;
    client.PingInterval = 60;
    client.MaxAutoReconnects = 30;
    //client.FilePartSize = 10240;
    if (!string.IsNullOrEmpty(config.Socks5Host) && config.Socks5Port > 0)
    {
        client.TcpHandler = (address, port) =>
        {
            var proxy = new Socks5ProxyClient(config.Socks5Host, config.Socks5Port);
            return Task.FromResult(proxy.CreateConnection(address, port));
        };
    }
    await client.LoginUserIfNeeded();
    var groups = await client.Messages_GetAllChats();
    Channel? group = null;
    try
    {
        group = (Channel)groups.chats.First(x => x.Value.Title.Contains(config.GroupName) && x.Value.IsActive).Value;
    }
    catch (Exception)
    {
        AnsiConsole.MarkupLine($"[red]Not Found the group {config.GroupName}[/]");
        return;
    }
    var hc = client.GetAccessHashFor<Channel>(group.ID);
    var channel = new InputPeerChannel(group.ID, hc);

    var totalGroupFiles = 0;
    var dicMsg = new Dictionary<MessagesFilter, int>();
    totalGroupFiles += await getMsgFilterCount(searchKey, client, channel, new InputMessagesFilterPhotos(), "Photos", dicMsg);
    totalGroupFiles += await getMsgFilterCount(searchKey, client, channel, new InputMessagesFilterVideo(), "Videos", dicMsg);
    totalGroupFiles += await getMsgFilterCount(searchKey, client, channel, new InputMessagesFilterGif(), "Gifs", dicMsg);
    totalGroupFiles += await getMsgFilterCount(searchKey, client, channel, new InputMessagesFilterDocument(), "Documents", dicMsg);

    var delete = args.Contains("--delete");
    try
    {
        _ = await client.Channels_GetAdminLog(new InputChannel(group.ID, hc), string.Empty);
    }
    catch (RpcException)
    {
        AnsiConsole.MarkupLine($"Getting documents from group [yellow]{config.GroupName}[/]");
        delete = false;
    }

    var downloadedFiles = 0;
    var duplicateFiles = 0;
    var filteredFiles = 0;
    var existingFiles = 0;
    var erroredFiles = 0;
    long downloadedBytes = 0;
    long totalBytes = 0;
    var logs = new List<Markup>();
    var table = new Table()
        .Centered()
        .HideHeaders();
    table.AddColumn("1");
    table.Columns[0].NoWrap = true;
    var textData = Markup.FromInterpolated($"Found [green]{totalGroupFiles}[/] Files");
    logs = AddLog(logs, textData);
    table = BuildTable(table, logs, totalGroupFiles, 0, 0, 0, 0, 0);
    await AnsiConsole.Live(table)
        .StartAsync(async ctx =>
        {
            ctx.Refresh();
            foreach (var item in dicMsg)
            {
                for (var i = 0; i <= item.Value; i += 100)
                {
                    var msgs = await client.Messages_Search(channel, searchKey, item.Key, offset_id: 0, limit: 100, add_offset: i);
                    foreach (var groupMainMsg in msgs.Messages)
                    {
                        var groupId = ((Message)groupMainMsg).grouped_id;
                        var msgList = new List<MessageBase>();
                        if (!string.IsNullOrEmpty(searchKey))
                        {
                            msgList.AddRange((await client.Messages_Search(channel, string.Empty, offset_id: groupMainMsg.ID + 50)).Messages);
                        }
                        else
                        {
                            msgList.Add(groupMainMsg);
                        }
                        foreach (var msg in msgList)
                        {
                            if (msg is not Message)
                            {
                                continue;
                            }
                            var message = (Message)msg;
                            if (groupId != message.grouped_id)
                            {
                                continue;
                            }
                            var size = 0L;
                            var docId = 0L;
                            IObject? document = null;
                            var fileName = $"{msg.Date.AddHours(8):yyyy-MM-dd_HH_mm_ss}_{msg.ID}_{channel.channel_id}{(string.IsNullOrEmpty(message.message) ? "" : ("_" + message.message))}";
                            var ext = ".png";
                            if (msg is Message m && m.media is MessageMediaDocument mmd && mmd.document is Document d)
                            {
                                document = d;
                                size = d.size;
                                docId = d.ID;
                                if (!string.IsNullOrEmpty(d.Filename) && d.Filename.IndexOf(".") >= 0)
                                {
                                    var strList = d.Filename.Split('.').ToList();
                                    ext = $".{strList[^1]}";
                                    strList.RemoveAt(strList.Count - 1);
                                    fileName += $"_{string.Join(".", strList)}";
                                }
                                else
                                {
                                    ext = MimeTypesMap.GetExtension(d.mime_type);
                                }
                            }
                            else if (msg is Message { media: MessageMediaPhoto { photo: Photo p } })
                            {
                                document = p;
                                size = p.LargestPhotoSize.FileSize;
                                docId = p.ID;
                            }
                            else
                            {
                                erroredFiles++;
                                var link = await client.Channels_ExportMessageLink(channel, message.ID);
                                var logMsg =
                                    Markup.FromInterpolated(
                                        $"[yellow] Error: {link.link} [/]|[orange1] Message: {message.message}[/]");
                                if (delete)
                                {
                                    await client.DeleteMessages(channel, message.ID);
                                    Utilities.WriteLogToFile(errorLogFilePath,
                                        $"Error: Message: {message.message} | Deleting Message");
                                    logMsg =
                                        Markup.FromInterpolated(
                                            $"[red] Error: Delete Enabled Removing[/] | [orange1]Message: {message.message}[/]");
                                }
                                else
                                {
                                    Utilities.WriteLogToFile(errorLogFilePath,
                                        $"Error: {link.link} | Message: {message.message}");
                                }

                                logs = AddLog(logs, logMsg);
                                table = BuildTable(
                                    table,
                                    logs,
                                    totalGroupFiles,
                                    downloadedFiles,
                                    duplicateFiles,
                                    filteredFiles,
                                    existingFiles,
                                    erroredFiles);
                                ctx.Refresh();
                                continue;
                            }

                            var sanitizedName = SubString(RemoveNewlinesFromPath(fileName)) + ext;
                            var info = new FileInfo(config.DownloadPath + $"/{sanitizedName}");
                            var wanted = config.DocumentExtensionFilter!.Split(",");
                            if (wanted.Length > 0 && !wanted.Contains(info.Extension.Replace(".", "").ToLower()))
                            {
                                filteredFiles++;
                                var link = await client.Channels_ExportMessageLink(channel, msg.ID);
                                Utilities.WriteLogToFile(filteredLogFilePath, $"{info.Name} | {link.link}");
                                logs = AddLog(logs,
                                    Markup.FromInterpolated($"Skipping Filtered: {link.link} | [red]{sanitizedName}[/]"));
                                table = BuildTable(
                                    table,
                                    logs,
                                    totalGroupFiles,
                                    downloadedFiles,
                                    duplicateFiles,
                                    filteredFiles,
                                    existingFiles,
                                    erroredFiles);
                                ctx.Refresh();
                                continue;
                            }

                            var choice = await DocumentManager.DecidePreDownload(info, docId, size);
                            switch (choice)
                            {
                                case PreDownloadProcessingDecision.Update:
                                    {
                                        await using var db = new DocumentContext();
                                        var uHash = GetFileHash(info.FullName);
                                        if (await db.DocumentFiles.AnyAsync(x => x.Hash == uHash))
                                            break;
                                        await db.DocumentFiles.AddAsync(new DocumentFile()
                                        {
                                            Name = info.Name,
                                            Extension = info.Extension.Remove(0, 1),
                                            FullName = info.FullName,
                                            Hash = GetFileHash(info.FullName),
                                            TelegramId = docId
                                        });
                                        await db.SaveChangesAsync();
                                        totalBytes += info.Length;
                                        existingFiles++;
                                        logs = AddLog(logs,
                                            Markup.FromInterpolated($"Updating Existing: [green]{sanitizedName}[/]"));
                                        table = BuildTable(
                                            table,
                                            logs,
                                            totalGroupFiles,
                                            downloadedFiles,
                                            duplicateFiles,
                                            filteredFiles,
                                            existingFiles,
                                            erroredFiles);
                                        ctx.Refresh();
                                        continue;
                                    }
                                case PreDownloadProcessingDecision.Nothing:
                                    totalBytes += size;
                                    existingFiles++;
                                    logs = AddLog(logs,
                                        Markup.FromInterpolated($"Skipping Existing: [green]{sanitizedName}[/]"));
                                    table = BuildTable(
                                        table,
                                        logs,
                                        totalGroupFiles,
                                        downloadedFiles,
                                        duplicateFiles,
                                        filteredFiles,
                                        existingFiles,
                                        erroredFiles);
                                    ctx.Refresh();
                                    continue;
                                case PreDownloadProcessingDecision.ExistingDuplicate:
                                    {
                                        duplicateFiles++;
                                        await using var dupeDb = new DocumentContext();
                                        var existing = await dupeDb.DuplicateFiles.FirstAsync(x => x.TelegramId == docId);
                                        var link = await client.Channels_ExportMessageLink(channel, msg.ID);
                                        Utilities.WriteLogToFile(duplicateLogFilePath,
                                            $"{sanitizedName},{existing.OrignalName},{link.link}");
                                        logs = AddLog(logs,
                                            Markup.FromInterpolated(
                                                $"Existing Duplicate: {link.link} | [red]{sanitizedName}[/] is duplicate of [green]{existing.OrignalName}[/]"));
                                        table = BuildTable(
                                            table,
                                            logs,
                                            totalGroupFiles,
                                            downloadedFiles,
                                            duplicateFiles,
                                            filteredFiles,
                                            existingFiles,
                                            erroredFiles);
                                        ctx.Refresh();
                                        continue;
                                    }
                            }

                            switch (choice)
                            {
                                case PreDownloadProcessingDecision.ReDownload:
                                    logs = AddLog(logs,
                                        Markup.FromInterpolated(
                                            $"Re-downloading Partially Downloaded: [yellow] {sanitizedName}[/]"));
                                    table = BuildTable(
                                        table,
                                        logs,
                                        totalGroupFiles,
                                        downloadedFiles,
                                        duplicateFiles,
                                        filteredFiles,
                                        existingFiles,
                                        erroredFiles);
                                    ctx.Refresh();
                                    break;
                                case PreDownloadProcessingDecision.SaveAndDownload:
                                    logs = AddLog(logs, Markup.FromInterpolated($"Downloading: [yellow] {sanitizedName}[/]"));
                                    table = BuildTable(
                                        table,
                                        logs,
                                        totalGroupFiles,
                                        downloadedFiles,
                                        duplicateFiles,
                                        filteredFiles,
                                        existingFiles,
                                        erroredFiles);
                                    ctx.Refresh();
                                    break;
                            }

                            try
                            {
                                await using var fs = info.Create();
                                if (document is Document tempDoc)
                                    await client.DownloadFileAsync(tempDoc, fs);
                                else if (document is Photo tempPhoto)
                                    await client.DownloadFileAsync(tempPhoto, fs);
                                fs.Close();
                            }
                            catch (RpcException e)
                            {
                                erroredFiles++;
                                var errorMessage = Markup.FromInterpolated(
                                    $"Download Error: {e.Message} - [red]{sanitizedName}[/]");
                                var link = await client.Channels_ExportMessageLink(channel, msg.ID);
                                Utilities.WriteLogToFile(errorLogFilePath, $"{link.link} | {sanitizedName} - {e.Message}");
                                logs = AddLog(logs, errorMessage);
                                table = BuildTable(
                                    table,
                                    logs,
                                    totalGroupFiles,
                                    downloadedFiles,
                                    duplicateFiles,
                                    filteredFiles,
                                    existingFiles,
                                    erroredFiles);
                                ctx.Refresh();
                                continue;
                            }

                            var hash = GetFileHash(info.FullName);
                            var postChoice = await DocumentManager.DecidePostDownload(info, hash);
                            await using var context = new DocumentContext();
                            if (postChoice == PostDownloadProcessingDecision.ProcessDuplicate)
                            {
                                var dbFile = context.DocumentFiles.First(x => x.Hash == hash);
                                if (!context.DuplicateFiles.Any(x => x.TelegramId == docId))
                                {
                                    context.DuplicateFiles.Add(new DuplicateFile()
                                    {
                                        OrignalName = dbFile.Name,
                                        DuplicateName = sanitizedName,
                                        Hash = hash,
                                        TelegramId = docId
                                    });
                                    await context.SaveChangesAsync();
                                }

                                info.Delete();
                                duplicateFiles++;
                                var link = await client.Channels_ExportMessageLink(channel, msg.ID);
                                Utilities.WriteLogToFile(duplicateLogFilePath, $"{sanitizedName},{dbFile.Name}, {link.link}");
                                logs = AddLog(logs,
                                    Markup.FromInterpolated(
                                        $"Cleaned Up:[red] {sanitizedName}[/] is duplicate of [green] {dbFile.Name}[/]"));
                                table = BuildTable(
                                    table,
                                    logs,
                                    totalGroupFiles,
                                    downloadedFiles,
                                    duplicateFiles,
                                    filteredFiles,
                                    existingFiles,
                                    erroredFiles);
                                ctx.Refresh();
                                continue;
                            }

                            var doc = new DocumentFile()
                            {
                                Name = info.Name,
                                Extension = info.Extension.Replace(".", ""),
                                Hash = hash,
                                FullName = info.FullName,
                                TelegramId = docId
                            };
                            context.DocumentFiles.Add(doc);
                            await context.SaveChangesAsync();
                            downloadedBytes += info.Length;
                            totalBytes += info.Length;
                            downloadedFiles++;
                            logs = AddLog(logs,
                                Markup.FromInterpolated($"Downloaded:[green bold] {sanitizedName}[/]"));
                            table = BuildTable(
                                table,
                                logs,
                                totalGroupFiles,
                                downloadedFiles,
                                duplicateFiles,
                                filteredFiles,
                                existingFiles,
                                erroredFiles);
                            ctx.Refresh();
                        }
                    }
                }
            }
        });

    await using var docContext = new DocumentContext();
    var totalSize = string.Empty;
    var downloadedSize = string.Empty;
    var archiveSize = string.Empty;
    AnsiConsole.Clear();
    await AnsiConsole.Status()
        .StartAsync("Calculating results...", async ctx =>
        {
            ctx.Spinner(Spinner.Known.Pong);
            totalSize = await CalculateDirectorySize(new DirectoryInfo(config.DownloadPath));
            archiveSize = ConvertBytesToString(totalBytes);
            downloadedSize = ConvertBytesToString(downloadedBytes);
        });
    var finalTable = new Table().Centered().Expand();
    var runTable = new Table().Centered();
    var groupTable = new Table().Centered();

    runTable
        .AddColumn("Existing")
        .AddColumn("Downloaded")
        .AddColumn("Errored")
        .AddColumn("Filtered")
        .AddColumn("Download Folder Size")
        .AddColumn("Downloaded Files Size");

    groupTable
        .AddColumn("Total Files")
        .AddColumn("Duplicated Files")
        .AddColumn("Total Unique Files")
        .AddColumn("Total Archive Size");

    finalTable.AddColumn("Run Stats").AddColumn("Group Stats");

    runTable.AddRow(
        new Markup($"[green]{existingFiles}[/]"),
        new Markup($"[purple]{downloadedFiles}[/]"),
        new Markup($"[red]{erroredFiles}[/]"),
        new Markup($"[grey]{filteredFiles}[/]"),
        new Markup($"[green]{totalSize}[/]"),
        new Markup($"[green]{downloadedSize}[/]"));

    groupTable.AddRow(
        new Markup($"[green]{totalGroupFiles}[/]"),
        new Markup($"[red]{duplicateFiles}[/]"),
        new Markup($"[green]{existingFiles + downloadedFiles}[/]"),
        new Markup($"[green]{archiveSize}[/]")
    );

    finalTable.AddRow(runTable, groupTable);

    AnsiConsole.Write(finalTable);

    string Config(string what)
    {
        if (config is null)
            throw new ArgumentNullException(nameof(what));
        return what switch
        {
            "api_id" => apiId,
            "api_hash" => apiHash,
            "phone_number" => config.PhoneNumber!,
            "verification_code" => AnsiConsole.Prompt(new TextPrompt<string>("[bold red]Enter Verification Code:[/]")
                .PromptStyle("red")
                .Secret()),
            "first_name" => throw new ApplicationException("Please sign up for an account before you run this program"),
            "last_name" => throw new ApplicationException("Please sign up for an account before you run this program"),
            "password" => AnsiConsole.Prompt(new TextPrompt<string>("[bold red]Enter 2fa password:[/] ")
                .PromptStyle("red")
                .Secret()),
            "session_pathname" => Path.Combine(config.SessionPath, "tg.session"),
            _ => null!
        };
    }
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex);
}

string GetFileHash(string filename)
{
    using var sha256 = SHA256.Create();
    using var stream = File.OpenRead(filename);
    var hash = sha256.ComputeHash(stream);
    return BitConverter.ToString(hash).Replace("-", "");
}

async Task<string> CalculateDirectorySize(DirectoryInfo directory)
{
    var files = Array.Empty<FileInfo>();
    await Task.Run(() => files = directory.GetFiles());
    return ConvertBytesToString(files.Sum(file => file.Length));
}

static string ConvertBytesToString(long bytes)
{
    return ByteSize.FromBytes(bytes).ToBinaryString();
}

static string RemoveNewlinesFromPath(string value)
{
    var validCharacters = new char[value.Length];
    var next = 0;
    foreach (var c in value)
    {
        switch (c)
        {
            case '\r':
                break;
            case '\n':
                break;
            case ',':
                break;
            case ':':
                break;
            case '*':
                break;
            case '/':
                break;
            case '\\':
                break;
            case '?':
                break;
            case '"':
                break;
            case '>':
                break;
            case '<':
                break;
            case '|':
                break;
            default:
                validCharacters[next++] = c;
                break;
        }
    }

    return new string(validCharacters, 0, next).Trim();
}

static string SubString(string text)
{
    var limitSize = 260 - 5;
    byte[] bytes = Encoding.Unicode.GetBytes(text);
    int nByte = 0;
    int i = 0;
    for (; i < bytes.GetLength(0) && nByte < limitSize; i++)
    {
        if (i % 2 == 0)
        {
            nByte++;
        }
        else
        {
            if (bytes[i] > 0)
            {
                nByte++;
            }
        }
    }

    if (i % 2 == 1)
    {
        if (bytes[i] > 0)
            i--;
        else
            i++;
    }
    return Encoding.Unicode.GetString(bytes, 0, i);
}

static Table BuildTable(Table table,
    IEnumerable<Markup> logEntries,
    int totalFiles,
    int downloadedFiles,
    int duplicateFiles,
    int filteredFiles,
    int existingFiles,
    int erroredFiles)
{
    var data1 = new BreakdownChartItem("Existing", existingFiles, Color.Green);
    var data2 = new BreakdownChartItem("Downloaded", downloadedFiles, Color.Purple);
    var data3 = new BreakdownChartItem("Errored", erroredFiles, Color.Red3);
    var data4 = new BreakdownChartItem("Duplicate", duplicateFiles, Color.Red);
    var data5 = new BreakdownChartItem("Filtered", filteredFiles, Color.Grey);
    var data6 = new BreakdownChartItem("Unprocessed",
        totalFiles - (downloadedFiles + duplicateFiles + filteredFiles + existingFiles), Color.Orange1);
    table.Rows.Clear();
    table
        .AddRow(new BreakdownChart() { Data = { data1, data2, data3, data4, data5, data6 } })
        .AddRow(new Rule());
    foreach (var log in logEntries)
    {
        table.AddRow(log);
    }

    return table;
}

static List<Markup> AddLog(List<Markup> list, Markup markup, bool removeOld = true)
{
    if (removeOld && list.Count >= 15)
        list.Remove(list[0]);
    list.Add(markup);
    return list;
}

static async Task<int> getMsgFilterCount(string searchKey, WTelegram.Client client, InputPeerChannel channel, MessagesFilter messagesFilter, string fileType, Dictionary<MessagesFilter, int> dicMsg)
{
    var photoMsgs = await client.Messages_Search(channel, searchKey, messagesFilter);
    if (photoMsgs.Count > 0)
    {
        AnsiConsole.MarkupLine($"Found [green]{photoMsgs.Count}[/] {fileType}");
        dicMsg.Add(messagesFilter, photoMsgs.Count);
    }
    return photoMsgs.Count;
}