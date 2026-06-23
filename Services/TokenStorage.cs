using System.Text.Json;

public class TokenStorage
{
    // Имя файла, в котором будут храниться refresh токены. Сам файл будет создан в корне проекта, рядом с Program.cs
    // привязываем путь к рабочей директории запущенного проекта (корню)
    private readonly string _filePath = Path.Combine(Directory.GetCurrentDirectory(), "tokens.json");

    // Сохраняет или обновляет refresh token пользователя.
    public void SaveRefreshToken(string accessToken, string refreshToken)
    {
        // Key   = access token
        // Value = refresh token
        Dictionary<string, string> tokens;

        // Проверяем существует ли файл с токенами
        if (File.Exists(_filePath))
        {
            // Читаем весь JSON из файла
            var json = File.ReadAllText(_filePath);
            // Преобразуем JSON в словарь
            tokens = JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                     ?? [];

            //var result = JsonSerializer.Deserialize<Dictionary<string, string>>(json);

            //if (result == null)
            //{
            //    tokens = [];
            //}
            //else
            //{
            //    tokens = result;
            //}

            // tokens = result ?? new Dictionary<string, string>();
        }
        // Если файла нет, создаем пустой словарь
        else
        {
            tokens = [];
        }

        // Добавляеv запись.
        tokens[accessToken] = refreshToken;

        // Сериализуем словарь обратно в JSON
        File.WriteAllText(
            _filePath,
            JsonSerializer.Serialize(tokens, new JsonSerializerOptions
            {
                WriteIndented = true
            }));
    }

    // Возвращает refresh token пользователя
    public string? FindRefreshByAccess(string accessToken)
    {
        // Если файла нет, значит токены еще не сохранялись
        if (!File.Exists(_filePath))
            return null;

        // Читаем JSON
        var json = File.ReadAllText(_filePath);

        // Преобразуем JSON в словарь
        var tokens = JsonSerializer.Deserialize<Dictionary<string, string>>(json);

        // Если произошла ошибка чтения
        if (tokens == null)
            return null;

        // Ищем пользователя в словаре
        return tokens.TryGetValue(accessToken, out var token)
            ? token
            : null;
        //if (tokens.TryGetValue(accessToken, out var token))
        //{
        //    return token;
        //}

        //return null;
    }


    public void UpdateRotatedTokens(string oldAccess, string newAccess, string newRefresh)
    {
        Dictionary<string, string> tokens;

        // 1. Прочитать файл и получить словарь 
        if (File.Exists(_filePath))
        {
            var json = File.ReadAllText(_filePath);
            tokens = JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? [];
        }
        else
        {
            tokens = [];
        }

        // 2. Удалить старую пару
        tokens.Remove(oldAccess);

        // 3. Записать новую пару
        tokens[newAccess] = newRefresh;

        // 4. Сохранить словарь обратно в файл
        File.WriteAllText(
            _filePath,
            JsonSerializer.Serialize(tokens, new JsonSerializerOptions
            {
                WriteIndented = true
            }));
    }



    // Метод для полного удаления токенов при выходе пользователя (Logout)
    public void RemoveTokens(string accessToken)
    {
        // Если токена нет или файла не существует — удалять нечего
        if (string.IsNullOrEmpty(accessToken) || !File.Exists(_filePath))
            return;

        // 1. Читаем текущие токены из файла
        var json = File.ReadAllText(_filePath);
        var tokens = JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? [];

        // 2. Пытаемся удалить запись по ключу (Access Token)
        // Метод Remove возвращает true, если ключ был найден и успешно удален
        if (tokens.Remove(accessToken))
        {
            // 3. Сохраняем обновленный словарь обратно в файл
            File.WriteAllText(
                _filePath,
                JsonSerializer.Serialize(tokens, new JsonSerializerOptions
                {
                    WriteIndented = true
                }));

            Console.WriteLine("Локальная сессия закрыта. Токены удалены из tokens.json.");
        }
    }
}