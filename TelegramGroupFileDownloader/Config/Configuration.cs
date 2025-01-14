// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

namespace TelegramGroupFileDownloader.Config;

public class Configuration
{
    public string? PhoneNumber { get; set; } = string.Empty;
    public string SessionPath { get; set; } = Environment.CurrentDirectory;
    public string DownloadPath { get; set; } = Environment.CurrentDirectory;
    public string? DocumentExtensionFilter { get; set; } = string.Empty;
    public string? GroupName { get; set; } = string.Empty;
    public string? Socks5Host { get; set; } = string.Empty;
    public int Socks5Port { get; set; } = 0;
    public string SearchKey { get; set; } = string.Empty;
}