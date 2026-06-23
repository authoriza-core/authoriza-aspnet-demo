using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using static System.Runtime.InteropServices.JavaScript.JSType;

var builder = WebApplication.CreateBuilder(args);
var oidcSettings = builder.Configuration.GetSection("OidcSettings");

// Add services to the container.
builder.Services.AddControllersWithViews();
// Регистрируем сервис для работы с токенами
builder.Services.AddSingleton<TokenStorage>();

builder.Services.AddAuthentication(options =>
{
    // "Cookies" — Основная схема для поддержания локальной сессии. 
    // Если пользователь успешно вошел, его зашифрованные данные сохраняются в куках браузера.
    options.DefaultScheme = "Cookies";
    // "OpenIdConnect" — Схема-вызов. Если анонимный пользователь пытается зайти 
    // на страницу с атрибутом [Authorize], .NET автоматически перенаправляет его на сервер Авторизы.
    options.DefaultChallengeScheme = "OpenIdConnect";
})
.AddCookie("Cookies", options =>
{
    options.Events = new Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationEvents
    {
        // Это событие срабатывает при каждом запросе пользователя к нашему сайту
        OnValidatePrincipal = async context =>
        {
            // 1. Смотрим, когда протухает текущий Access Token в куке
            var expiresAtString = context.Properties.GetTokenValue("expires_at");

            if (DateTimeOffset.TryParse(expiresAtString, out var expiresAt))
            {
                // 2. Если до смерти токена осталось меньше 5 минут или он уже умер
                if (expiresAt < DateTimeOffset.UtcNow.AddMinutes(5))
                {
                    Console.WriteLine("\nAccess Token протухает! Начинаем обновление...");

                    var oldAccessToken = context.Properties.GetTokenValue("access_token");
                    var storage = context.HttpContext.RequestServices.GetRequiredService<TokenStorage>();

                    // 3. Идем в хранилище и ищем Refresh Token по старому Access
                    var refreshToken = storage.FindRefreshByAccess(oldAccessToken);

                    if (!string.IsNullOrEmpty(refreshToken))
                    {
                        // 4. Достаем настройки, чтобы отправить запрос на Авторизу
                        var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
                        var authority = config["OidcSettings:Authority"];
                        var clientId = config["OidcSettings:ClientId"];
                        var clientSecret = config["OidcSettings:ClientSecret"];

                        // Формируем запрос обмена токенов
                        using var httpClient = new HttpClient();
                        var requestBody = new FormUrlEncodedContent(new[]
                        {
                            new KeyValuePair<string, string>("grant_type", "refresh_token"),
                            new KeyValuePair<string, string>("refresh_token", refreshToken),
                            new KeyValuePair<string, string>("client_id", clientId),
                            new KeyValuePair<string, string>("client_secret", clientSecret)
                        });

                        var oidcOptions = context.HttpContext.RequestServices
                            .GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<OpenIdConnectOptions>>()
                            .Get("OpenIdConnect");

                        var oidcConfig = await oidcOptions.ConfigurationManager.GetConfigurationAsync(CancellationToken.None);

                        var tokenEndpoint = oidcConfig.TokenEndpoint;

                        // отправляем запрос по динамическому адресу
                        var response = await httpClient.PostAsync(tokenEndpoint, requestBody);

                        if (response.IsSuccessStatusCode)
                        {
                            var responseContent = await response.Content.ReadAsStringAsync();
                            var json = System.Text.Json.JsonDocument.Parse(responseContent);

                            var newAccessToken = json.RootElement.GetProperty("access_token").GetString();

                            var newRefreshToken = json.RootElement.TryGetProperty("refresh_token", out var rfProp)
                                                  ? rfProp.GetString()
                                                  : refreshToken;

                            var expiresInSeconds = json.RootElement.GetProperty("expires_in").GetInt32();

                            // 5. Стираем старую пару из файла и записываем новую
                            storage.UpdateRotatedTokens(oldAccessToken, newAccessToken, newRefreshToken);

                            // 6. Обновляем локальную куку пользователя (чтобы он не заметил подмены)
                            context.Properties.UpdateTokenValue("access_token", newAccessToken);

                            var newExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds);
                            context.Properties.UpdateTokenValue("expires_at", newExpiresAt.ToString("o"));

                            // .NET перевыпускает куку в браузере с новыми данными
                            context.ShouldRenew = true;

                            Console.WriteLine("Успешно! Токены обновлены.\n");
                        }
                        else
                        {
                            Console.WriteLine($"Авториза отклонила запрос. Ошибка: {response.StatusCode}");
                            context.RejectPrincipal();
                        }
                    }
                    else
                    {
                        Console.WriteLine("Рефреш-токен не найден в базе. Юзер зашел с другого устройства?");
                        context.RejectPrincipal();
                    }
                }
            }
        }
    };
})
.AddOpenIdConnect("OpenIdConnect", options =>
{
    // 1. Привязываем данные JSON oidcSettings
    options.Authority = oidcSettings["Authority"];
    options.ClientId = oidcSettings["ClientId"];
    options.ClientSecret = oidcSettings["ClientSecret"];

    // 2. Режим Authorization Code с временным кодом
    options.ResponseType = "code";

    // 3. Включаем PKCE
    options.UsePkce = true;
    options.ResponseMode = "query";

    // 4. Запрашиваем необходимые Scope
    options.Scope.Clear();

    // openid — Базовый и обязательный scope для протокола OpenID Connect.
    // Даёт команду Авторизе выпустить ID Token (цифровой JWT-паспорт пользователя)    options.Scope.Add("openid");
    // Из него бэкенд .NET автоматически считывает системный идентификатор "sub" (Subject) —
    // уникальный, зашифрованный UUID профиля этого юзера конкретно внутри проекта
    options.Scope.Add("openid");

    // profile — Запрос доступа к человеческим данным пользователя
    // Даёт нашему бэкенду официальное разрешение использовать Access Token для походов
    // на UserInfo Endpoint, чтобы скачать оттуда имя, фамилию и email
    // Если этот scope убрать, Авториза пришлёт только безликий технический GUID (sub)
    options.Scope.Add("profile");

    // запрашиваем email
    options.Scope.Add("email");

    //offline_access — Запрос на долгосрочный доступ без участия пользователя.
    // Приказывает серверу Авторизы выдать нашему приложению Refresh Token (ключ обновления)
    // Он критически необходим, чтобы бэкенд мог автоматически по таймеру или вручную
    // по кнопке обновлять протухшие токены доступа, не выкидывая юзера на экран логина
    options.Scope.Add("offline_access");

    // Перенастраиваем скрытый обработчик .NET на адрес /callback
    options.CallbackPath = "/callback";

    // Приказываем .NET сохранить полученные токены (ID, Access, Refresh) внутри авторизационной куки,
    // чтобы мы могли вытащить их в контроллере и вывести на экран для отчета по практике.
    options.SaveTokens = true; // .NET сохранит id_token и access_token в куку
    //options.UseTokenLifetime = true; // привязывает жизнь локальных куки к access token чтобы когда он протухнет при попытке зайти на страницу в правами меня выкинуло.

    // Автоматически сходить на UserInfo один раз при логине 
    // и сохранить все полученные данные в локальную куку пользователя.
    // Она ломает вход с ошибкой 401))
    //options.GetClaimsFromUserInfoEndpoint = true;
    
    options.Events = new OpenIdConnectEvents
    {
        // Делаем куку браузера постоянной - защита от разлогина при закрытии браузера
        OnTicketReceived = context =>
        {
            context.Properties.IsPersistent = true;
            return Task.CompletedTask;
        },

        //Запрос refresh token при необходимости
        OnRedirectToIdentityProvider = context =>
        {

            // проверяем, попросил ли контроллер принудительно выдать consent
            if (context.Properties.Items.ContainsKey("ForceConsent"))
            {
                // Если сайт попросил — отдаем строку!
                context.ProtocolMessage.Prompt = "consent";
            }
            // Если флага нет, мы ничего не трогаем, и Авториза пускает прозрачно (SSO)

            return Task.CompletedTask;
        },

        // ШАГ 1: Ловим сырой ответ от Авторизы и прячем refresh token в служебное хранилище
        OnTokenResponseReceived = context =>
        {
            var parameters = context.TokenEndpointResponse?.Parameters;

           
            if (parameters != null)
            {
                // Ловим Refresh Token
                if (parameters.TryGetValue("refresh_token", out var rawRefreshToken))
                {
                    context.Properties.Items["MySecretRefreshToken"] = rawRefreshToken.ToString();
                }

                // Ловим Access Token
                if (parameters.TryGetValue("access_token", out var rawAccessToken))
                {
                    context.Properties.Items["MySecretAccessToken"] = rawAccessToken.ToString();
                }
            }
            return Task.CompletedTask;
        },

        // ШАГ 2: Достаем токены из хранилища и сохраняем на сервере
        OnTokenValidated = context =>
        {
            var storage = context.HttpContext.RequestServices.GetRequiredService<TokenStorage>();

            // Достаем оба токена из наших служебных карманов
            if (context.Properties.Items.TryGetValue("MySecretRefreshToken", out var refreshToken) &&
                context.Properties.Items.TryGetValue("MySecretAccessToken", out var accessToken))
            {
                // Передаем в класс хранения по схеме: [Access][Refresh]
                storage.SaveRefreshToken(accessToken, refreshToken);

                // Удаляем временные переменные из служебного словаря
                context.Properties.Items.Remove("MySecretRefreshToken");
                context.Properties.Items.Remove("MySecretAccessToken");
            }

            if (context.Properties.UpdateTokenValue("refresh_token", null))
            {
                // пытаемся обновить значение refresh_token на null. 
                // Но чтобы он вообще не попал в куку, нужно удалить его из внутренней коллекции.
                var tokens = context.Properties.GetTokens()
                    .Where(t => t.Name != "refresh_token")
                    .ToList(); // материализуем до передачи
                context.Properties.StoreTokens(tokens);
            }



            return Task.CompletedTask;
        }
    };
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error"); // Перенаправление на безопасную и красивую страницу ошибки

    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    // Включаем механизм HSTS (HTTP Strict Transport Security).
    // Он жестко приказывает браузерам общаться с нашим сайтом по защищенному HTTPS.
    // Это защищает сессионные куки от перехвата в открытых или недоверенных сетях.
    app.UseHsts();
}

// Автоматически перенаправляет любые небезопасные HTTP-запросы на защищенный протокол HTTPS.
// Гарантирует, что данные между браузером и сервером всегда шифруются.
app.UseHttpsRedirection();

// Включает механизм маршрутизации. Маршрутизатор сопоставляет URL-адрес из запроса браузера 
// со структурой проекта и определяет, какой контроллер и событие должны обработать этот запрос.
app.UseRouting();

// Порядок имеет критическое значение!
app.UseAuthentication(); // 1. Сначала проверяем: "Кто этот пользователь? (Читаем куку/токен)"
app.UseAuthorization();  // 2. Затем проверяем: "А имеет ли этот пользователь право сюда заходить?"

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();
