using System.Text.Json;

// Серверное хранилище Refresh Token-ов.
// Refresh Token хранится в tokens.json на сервере, а не в куке браузера:
// кука доступна JavaScript-коду и сети, её размер ограничен, и она передаётся
// с каждым запросом — хранить долгоживущий Refresh Token в куке небезопасно.
public class TokenStorage
{
    private readonly string _filePath = Path.Combine(Directory.GetCurrentDirectory(), "tokens.json");

    // Гарантирует, что только один поток выполняет обмен Refresh Token в каждый момент времени.
    // Без синхронизации параллельные запросы браузера одновременно используют один Refresh Token,
    // что node-oidc-provider расценивает как атаку воспроизведения (replay attack)
    // и немедленно отзывает весь грант пользователя.
    public SemaphoreSlim RefreshLock { get; } = new SemaphoreSlim(1, 1);

    // Сохраняет пару Access Token - Refresh Token при первоначальном входе.
    public void SaveRefreshToken(string accessToken, string refreshToken)
    {
        var tokens = ReadFromFile();
        tokens[accessToken] = refreshToken;
        WriteToFile(tokens);
    }

    // Возвращает Refresh Token по текущему Access Token.
    // Результат null означает: Access Token не найден, Refresh Token уже ротирован или удалён после ошибки.
    public string? FindRefreshByAccess(string accessToken)
    {
        var tokens = ReadFromFile();
        return tokens.TryGetValue(accessToken, out var refreshToken) ? refreshToken : null;
    }

    // Заменяет старую пару Access Token - Refresh Token новой после успешного обновления (Refresh Token rotation).
    // Серверы OIDC выдают новый Refresh Token при каждом обновлении; старый немедленно инвалидируется.
    public void UpdateRotatedTokens(string oldAccessToken, string newAccessToken, string newRefreshToken)
    {
        var tokens = ReadFromFile();
        tokens.Remove(oldAccessToken);
        tokens[newAccessToken] = newRefreshToken;
        WriteToFile(tokens);
    }

    // Удаляет запись при выходе пользователя или при невосстановимой ошибке обновления.
    // После удаления FindRefreshByAccess вернёт null — параллельные потоки, ожидающие семафора,
    // увидят пустой результат и не будут повторять заведомо провальный запрос к серверу.
    public void RemoveTokens(string accessToken)
    {
        if (string.IsNullOrEmpty(accessToken))
            return;

        var tokens = ReadFromFile();
        if (tokens.Remove(accessToken))
        {
            WriteToFile(tokens);
            Console.WriteLine("Сессия завершена: токены удалены из tokens.json.");
        }
    }

    private Dictionary<string, string> ReadFromFile()
    {
        if (!File.Exists(_filePath))
            return [];

        var json = File.ReadAllText(_filePath);
        return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? [];
    }

    private void WriteToFile(Dictionary<string, string> tokens)
    {
        File.WriteAllText(
            _filePath,
            JsonSerializer.Serialize(tokens, new JsonSerializerOptions { WriteIndented = true }));
    }
}
