using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var oidcSettings = builder.Configuration.GetSection("OidcSettings");

builder.Services.AddControllersWithViews();

// Singleton: один экземпляр хранилища на всё приложение.
// Хранит пары Access Token - Refresh Token в файле tokens.json и обеспечивает синхронизацию
// параллельных запросов через SemaphoreSlim RefreshLock.
builder.Services.AddSingleton<TokenStorage>();

builder.Services.AddAuthentication(options =>
{
    // "Cookies" — основная схема: зашифрованная сессионная кука хранит токены
    // и claims пользователя между запросами к нашему приложению.
    options.DefaultScheme = "Cookies";

    // "OpenIdConnect" — схема-вызов: при попытке анонимного доступа к [Authorize]-ресурсу
    // автоматически перенаправляет браузер на сервер Авторизы для входа.
    options.DefaultChallengeScheme = "OpenIdConnect";
})
.AddCookie("Cookies", options =>
{
    options.Events = new Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationEvents
    {
        // Выполняется при каждом аутентифицированном запросе.
        // Проверяет срок действия Access Token и при необходимости обновляет его через Refresh Token.
        OnValidatePrincipal = async context =>
        {
            var expiresAtString = context.Properties.GetTokenValue("expires_at");

            if (!DateTimeOffset.TryParse(expiresAtString, out var expiresAt))
                return;

            // Обновляем заблаговременно — за 5 минут до истечения.
            // Это предотвращает ситуацию, когда Access Token истекает в середине обработки запроса.
            if (expiresAt >= DateTimeOffset.UtcNow.AddMinutes(5))
                return;

            var oldAccessToken = context.Properties.GetTokenValue("access_token");
            var storage = context.HttpContext.RequestServices.GetRequiredService<TokenStorage>();

            // Семафор гарантирует, что только один поток выполняет обновление в каждый момент.
            // Без него параллельные запросы браузера (ресурсы страницы, AJAX) одновременно
            // отправят один Refresh Token на сервер
            await storage.RefreshLock.WaitAsync();
            try
            {
                // Перепроверяем после захвата блокировки: пока мы ждали в очереди,
                // другой поток мог уже обновить или удалить Refresh Token.
                var refreshToken = storage.FindRefreshByAccess(oldAccessToken);

                if (string.IsNullOrEmpty(refreshToken))
                {
                    // Refresh Token уже ротирован или удалён параллельным потоком — пропускаем.
                    Console.WriteLine("Пропускаем: Refresh Token уже обработан параллельным запросом.");
                    return;
                }

                Console.WriteLine("\nAccess Token истекает через 5 минут. Запускаем автообновление...");

                var config       = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
                var clientId     = config["OidcSettings:ClientId"];
                var clientSecret = config["OidcSettings:ClientSecret"];

                // Адрес Token Endpoint берём из Discovery Document
                var oidcOptions = context.HttpContext.RequestServices
                    .GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<OpenIdConnectOptions>>()
                    .Get("OpenIdConnect");
                var oidcConfig = await oidcOptions.ConfigurationManager
                    .GetConfigurationAsync(CancellationToken.None);

                using var httpClient = new HttpClient();
                var requestBody = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type",    "refresh_token"),
                    new KeyValuePair<string, string>("refresh_token", refreshToken),
                    new KeyValuePair<string, string>("client_id",     clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret)
                });

                var response = await httpClient.PostAsync(oidcConfig.TokenEndpoint, requestBody);

                if (response.IsSuccessStatusCode)
                {
                    var json = System.Text.Json.JsonDocument.Parse(
                        await response.Content.ReadAsStringAsync());

                    var newAccessToken = json.RootElement.GetProperty("access_token").GetString();
                    var newRefreshToken = json.RootElement.TryGetProperty("refresh_token", out var refreshTokenProperty)
                                          ? refreshTokenProperty.GetString()
                                          : refreshToken;
                    var expiresInSeconds = json.RootElement.GetProperty("expires_in").GetInt32();

                    storage.UpdateRotatedTokens(oldAccessToken, newAccessToken, newRefreshToken);

                    // Обновляем Access Token и время истечения в куке.
                    // ShouldRenew = true сигнализирует middleware перевыпустить куку в ответе.
                    context.Properties.UpdateTokenValue("access_token", newAccessToken);
                    context.Properties.UpdateTokenValue("expires_at",
                        DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds).ToString("o"));
                    context.ShouldRenew = true;

                    Console.WriteLine("Автообновление успешно. Новый Access Token:");
                    Console.WriteLine($"  {newAccessToken?.Substring(0, Math.Min(30, newAccessToken?.Length ?? 0))}...\n");
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Сервер отклонил Refresh Token: {response.StatusCode} — {error}");

                    // Удаляем невалидный Refresh Token немедленно, чтобы потоки, стоящие в очереди
                    // на семафоре, увидели null и не повторяли заведомо провальный запрос.
                    storage.RemoveTokens(oldAccessToken);
                    context.RejectPrincipal();
                }
            }
            finally
            {
                storage.RefreshLock.Release();
            }
        }
    };
})
.AddOpenIdConnect("OpenIdConnect", options =>
{
    options.Authority    = oidcSettings["Authority"];
    options.ClientId     = oidcSettings["ClientId"];
    options.ClientSecret = oidcSettings["ClientSecret"];

    // Authorization Code Flow: сервер возвращает только временный короткоживущий код,
    // а не токены напрямую в URL — защита от перехвата через историю браузера.
    options.ResponseType = "code";
    options.ResponseMode = "query";

    // PKCE (Proof Key for Code Exchange): клиент генерирует случайный code_verifier,
    // отправляет его хэш (code_challenge) вместе с запросом авторизации, а сервер
    // проверяет оригинальный verifier при обмене кода на токены.
    // Защищает от перехвата authorization code злоумышленником.
    options.UsePkce = true;

    options.Scope.Clear();
    options.Scope.Add("openid");         // обязательный scope OIDC; сервер выпускает ID Token
    options.Scope.Add("profile");        // имя, фамилия и другие данные профиля пользователя
    options.Scope.Add("email");          // адрес электронной почты
    options.Scope.Add("offline_access"); // запрашивает Refresh Token для обновления сессии
                                         // без повторного входа пользователя

    options.CallbackPath = "/callback";

    // Сохраняет id_token и access_token в куку.
    // Необходимо, чтобы контроллер мог получить их через HttpContext.GetTokenAsync()
    // и отобразить содержимое токенов на странице.
    options.SaveTokens = true;

    options.Events = new OpenIdConnectEvents
    {
        // Делает куку постоянной (с явным сроком истечения).
        // По умолчанию кука сессионная — браузер удаляет её при закрытии окна.
        // Постоянная кука сохраняет сессию между перезапусками браузера.
        OnTicketReceived = context =>
        {
            context.Properties.IsPersistent = true;
            return Task.CompletedTask;
        },

        // Позволяет добавить prompt=consent в запрос авторизации.
        // Используется действием ForceLogin: принудительный новый consent гарантирует
        // создание нового гранта и, следовательно, нового Refresh Token от сервера.
        OnRedirectToIdentityProvider = context =>
        {
            if (context.Properties.Items.ContainsKey("ForceConsent"))
                context.ProtocolMessage.Prompt = "consent";

            return Task.CompletedTask;
        },

        // ШАГ 1: перехватываем сырой ответ Token Endpoint и временно сохраняем
        // Access Token и Refresh Token в Properties.Items для передачи в OnTokenValidated.
        // В OnTokenValidated токены недоступны напрямую — только через Properties.
        OnTokenResponseReceived = context =>
        {
            var parameters = context.TokenEndpointResponse?.Parameters;

            if (parameters != null)
            {
                if (parameters.TryGetValue("refresh_token", out var rawRefreshToken))
                    context.Properties.Items["MySecretRefreshToken"] = rawRefreshToken.ToString();

                if (parameters.TryGetValue("access_token", out var rawAccessToken))
                    context.Properties.Items["MySecretAccessToken"] = rawAccessToken.ToString();
            }

            return Task.CompletedTask;
        },

        // ШАГ 2: переносим Access Token - Refresh Token в серверное хранилище и удаляем Refresh Token из куки.
        // Refresh Token в куке — нарушение безопасности: он доступен JS-коду на странице
        // и передаётся браузером с каждым запросом к нашему домену.
        // В tokens.json Refresh Token хранится только на сервере и не покидает его.
        OnTokenValidated = context =>
        {
            var storage = context.HttpContext.RequestServices.GetRequiredService<TokenStorage>();

            if (context.Properties.Items.TryGetValue("MySecretRefreshToken", out var refreshToken) &&
                context.Properties.Items.TryGetValue("MySecretAccessToken", out var accessToken))
            {
                storage.SaveRefreshToken(accessToken, refreshToken);
                context.Properties.Items.Remove("MySecretRefreshToken");
                context.Properties.Items.Remove("MySecretAccessToken");
            }

            // Удаляем Refresh Token из набора токенов, которые SaveTokens запишет в куку.
            var tokens = context.Properties.GetTokens()
                .Where(t => t.Name != "refresh_token")
                .ToList();
            context.Properties.StoreTokens(tokens);

            return Task.CompletedTask;
        }
    };
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // HSTS: браузер получает директиву работать с сайтом только по HTTPS в течение 30 дней.
    // Защищает сессионные куки от перехвата при downgrade-атаке с HTTPS на HTTP.
    app.UseHsts();
}

// Перенаправляет HTTP-запросы на HTTPS — шифрует трафик между браузером и сервером.
app.UseHttpsRedirection();
app.UseRouting();

// Порядок критически важен:
// Authentication читает куку и устанавливает HttpContext.User (Principal),
// Authorization затем проверяет права Principal на запрошенный ресурс ([Authorize]).
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
