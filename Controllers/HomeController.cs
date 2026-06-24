using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using PetrAuthDemo.Models;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;

namespace PetrAuthDemo.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index() => View();

        [Authorize]
        public IActionResult Privacy() => View();

        // Главная страница после входа: отображает все выданные токены, их JWT-payload,
        // статус и оставшееся время жизни Access Token.
        // При fetchUserInfo=true сразу выполняет запрос к UserInfo Endpoint —
        // это требование ТЗ: "после успешного входа приложение должно выполнять
        // запрос к UserInfo Endpoint".
        [Authorize]
        public async Task<IActionResult> TokenInfo(bool fetchUserInfo = false)
        {
            // Токены хранятся в зашифрованной куке (SaveTokens = true в Program.cs).
            // Refresh Token из куки намеренно удалён в OnTokenValidated — он хранится только
            // на сервере в tokens.json.
            var accessToken  = await HttpContext.GetTokenAsync("access_token");
            var idToken      = await HttpContext.GetTokenAsync("id_token");
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token") ?? "Хранится на сервере";
            var tokenType    = await HttpContext.GetTokenAsync("token_type") ?? "Bearer";
            var expiresAt    = await HttpContext.GetTokenAsync("expires_at");

            string expiresIn       = "";
            string expiresAtDisplay = expiresAt ?? "Неизвестно";
            if (DateTimeOffset.TryParse(expiresAt, out var expDate))
            {
                var timeRemaining = expDate - DateTimeOffset.UtcNow;
                expiresIn = Math.Max(0, (int)timeRemaining.TotalSeconds).ToString() + " секунд";

                // Передаём время в ISO 8601 для JS-таймера обратного отсчёта.
                ViewBag.ExpiresAtJs = expDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

                // Кука хранит время в UTC с суффиксом +00:00 — приводим к локальному для отображения.
                expiresAtDisplay = expDate.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
            }

            var handler = new JwtSecurityTokenHandler();

            string idTokenPayload = "Пусто";
            if (!string.IsNullOrEmpty(idToken) && handler.CanReadToken(idToken))
                idTokenPayload = handler.ReadJwtToken(idToken).Payload.SerializeToJson();

            string accessTokenPayload = "Пусто";
            string lastRefreshTime    = "Неизвестно";
            string scope = User.FindFirst("scope")?.Value ?? "openid profile email offline_access";

            if (!string.IsNullOrEmpty(accessToken) && handler.CanReadToken(accessToken))
            {
                var accessTokenJwt = handler.ReadJwtToken(accessToken);
                accessTokenPayload = accessTokenJwt.Payload.SerializeToJson();

                // IssuedUtc куки устаревает при автообновлении: новая кука записывается
                // только в конце ответа (ShouldRenew), а текущий запрос видит ещё старое значение.
                // Клейм iat из самого Access Token всегда отражает момент выдачи текущего токена.
                lastRefreshTime = accessTokenJwt.IssuedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");

                // Scope в claims Principal может быть неполным (зависит от конфигурации middleware).
                // Достоверный источник — payload самого Access Token.
                scope = accessTokenJwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value ?? scope;
            }

            if (fetchUserInfo)
                await LoadUserInfoDataAsync(accessToken, idToken);
            else
            {
                ViewBag.UserInfoJson = "Нажмите кнопку для запроса";
                ViewBag.FetchTime    = "Не запрашивалось";
            }

            ViewBag.AccessToken        = accessToken;
            ViewBag.IdToken            = idToken;
            ViewBag.RefreshToken       = refreshToken;
            ViewBag.TokenType          = tokenType;
            ViewBag.ExpiresAt          = expiresAtDisplay;
            ViewBag.ExpiresIn          = expiresIn;
            ViewBag.IdTokenPayload     = idTokenPayload;
            ViewBag.AccessTokenPayload = accessTokenPayload;
            ViewBag.LastRefreshTime    = lastRefreshTime;
            ViewBag.Scope              = scope;

            ViewBag.UserName = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value
                            ?? User.FindFirst("name")?.Value
                            ?? "Нет данных";
            ViewBag.UserEmail = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                             ?? User.FindFirst("email")?.Value
                             ?? "Нет данных";

            return View();
        }

        // AJAX-endpoint: вызывается кнопкой "Запросить UserInfo" без перезагрузки страницы.
        // Защищён антифorgery-токеном — JS передаёт его в заголовке RequestVerificationToken.
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> FetchUserInfo()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            var idToken     = await HttpContext.GetTokenAsync("id_token");
            await LoadUserInfoDataAsync(accessToken, idToken);
            return PartialView("_UserInfoPartial");
        }

        // Запрашивает UserInfo Endpoint и заполняет ViewBag.UserInfoJson / ViewBag.FetchTime.
        // При ошибке сервера применяет fallback на ID Token: Авториза хранит JTI в памяти
        // и теряет их после перезапуска / переключения между экземплярами сервера.
        // ID Token подписан и не зависит от серверного состояния — надёжный источник данных профиля.
        private async Task LoadUserInfoDataAsync(string? accessToken, string? idToken = null)
        {
            string userInfoJson = "Нет данных";
            string fetchTime    = "Не запрашивалось";

            if (string.IsNullOrEmpty(accessToken))
            {
                ViewBag.UserInfoJson = userInfoJson;
                ViewBag.FetchTime    = fetchTime;
                return;
            }

            try
            {
                // Адрес UserInfo Endpoint берём из Discovery Document (кэшируется).
                // Не допускается хардкодить OIDC-эндпоинты вручную — требование ТЗ.
                var oidcOptions = HttpContext.RequestServices
                    .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                    .Get("OpenIdConnect");
                var oidcConfig = await oidcOptions.ConfigurationManager
                    .GetConfigurationAsync(CancellationToken.None);

                Console.WriteLine($"[UserInfo] Access Token: {accessToken.Substring(0, Math.Min(30, accessToken.Length))}...");
                Console.WriteLine($"[UserInfo] Endpoint: {oidcConfig.UserInfoEndpoint}");

                // RFC 6750: Access Token передаётся в заголовке Authorization: Bearer <token>.
                using var client = new HttpClient();
                client.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken.Trim());

                var response = await client.GetAsync(oidcConfig.UserInfoEndpoint);

                Console.WriteLine($"[UserInfo] Ответ: {(int)response.StatusCode} {response.StatusCode}");

                if (response.IsSuccessStatusCode)
                {
                    userInfoJson = await response.Content.ReadAsStringAsync();
                    fetchTime    = DateTime.Now.ToString("HH:mm:ss (dd.MM.yyyy)");
                }
                else
                {
                    var endpointError = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"[UserInfo] Ошибка: {endpointError}. Пробуем ID Token fallback...");

                    // Fallback: читаем данные профиля из ID Token.
                    // Это поведение идентично большинству OIDC-библиотек (Authlib, oidc-client и др.):
                    // они приоритетно используют userinfo из ID Token, а к эндпоинту обращаются
                    // только если данные там актуальнее.
                    var jwtHandler = new JwtSecurityTokenHandler();
                    if (!string.IsNullOrEmpty(idToken) && jwtHandler.CanReadToken(idToken))
                    {
                        var idTokenJwt = jwtHandler.ReadJwtToken(idToken);

                        // Группируем дублирующиеся claims (System.IdentityModel может дублировать некоторые).
                        var claimsDict = idTokenJwt.Claims
                            .GroupBy(c => c.Type)
                            .ToDictionary(
                                g => g.Key,
                                g => g.Count() == 1
                                    ? (object)g.First().Value
                                    : g.Select(c => c.Value).ToArray());

                        var idTokenData = System.Text.Json.JsonSerializer.Serialize(
                            claimsDict,
                            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

                        userInfoJson = $"[Источник: ID Token — UserInfo Endpoint вернул ошибку]\n{endpointError}\n\n{idTokenData}";
                        fetchTime    = DateTime.Now.ToString("HH:mm:ss (dd.MM.yyyy)");
                        Console.WriteLine("[UserInfo] ID Token fallback применён успешно.");
                    }
                    else
                    {
                        userInfoJson = $"Код ошибки: {response.StatusCode}\nОтвет сервера: {endpointError}";
                    }
                }
            }
            catch (Exception ex)
            {
                userInfoJson = $"Сетевая ошибка: {ex.Message}";
            }

            ViewBag.UserInfoJson = userInfoJson;
            ViewBag.FetchTime    = fetchTime;
        }

        // Стандартный вход через SSO: если у пользователя уже есть активная сессия на Авторизе,
        // он пропустит экран логина и сразу получит токены (прозрачный re-login).
        [HttpGet]
        public IActionResult Login()
        {
            return Challenge(
                new AuthenticationProperties { RedirectUri = "/Home/TokenInfo?fetchUserInfo=true" },
                "OpenIdConnect");
        }

        // Принудительный вход с запросом нового consent.
        // Параметр prompt=consent гарантирует создание нового гранта на сервере,
        // даже если у пользователя уже есть активная SSO-сессия.
        // Используется после истечения или отзыва Refresh Token.
        [HttpGet]
        public IActionResult ForceLogin()
        {
            var properties = new AuthenticationProperties { RedirectUri = "/Home/TokenInfo?fetchUserInfo=true" };

            // Флаг читается в OnRedirectToIdentityProvider - добавляет prompt=consent в запрос.
            properties.Items["ForceConsent"] = "true";
            return Challenge(properties, "OpenIdConnect");
        }

        // Ручное обновление токенов по кнопке на странице.
        // После успешного обновления перенаправляет на TokenInfo с повторным запросом
        // UserInfo Endpoint — требование ТЗ: "после обновления повторно получить данные UserInfo".
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RefreshTokens()
        {
            var authResult = await HttpContext.AuthenticateAsync("Cookies");
            if (!authResult.Succeeded)
                return RedirectToAction("Login");

            var oldAccessToken = authResult.Properties.GetTokenValue("access_token");
            var storage        = HttpContext.RequestServices.GetRequiredService<TokenStorage>();
            var refreshToken   = storage.FindRefreshByAccess(oldAccessToken ?? "");

            if (string.IsNullOrEmpty(refreshToken))
                return RedirectToAction("ForceLogin");

            var config       = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var clientId     = config["OidcSettings:ClientId"];
            var clientSecret = config["OidcSettings:ClientSecret"];

            // Адрес Token Endpoint из Discovery Document — не хардкодим URL вручную (требование ТЗ).
            var oidcOptions = HttpContext.RequestServices
                .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
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

            try
            {
                var response = await httpClient.PostAsync(oidcConfig.TokenEndpoint, requestBody);

                if (response.IsSuccessStatusCode)
                {
                    var json = System.Text.Json.JsonDocument.Parse(
                        await response.Content.ReadAsStringAsync());

                    var newAccessToken = json.RootElement.GetProperty("access_token").GetString();
                    var expiresIn      = json.RootElement.GetProperty("expires_in").GetInt32();
                    var newRefreshToken = json.RootElement.TryGetProperty("refresh_token", out var refreshTokenProperty)
                                         ? refreshTokenProperty.GetString() : refreshToken;

                    storage.UpdateRotatedTokens(oldAccessToken, newAccessToken, newRefreshToken);
                    authResult.Properties.UpdateTokenValue("access_token", newAccessToken);
                    authResult.Properties.UpdateTokenValue("expires_at",
                        DateTimeOffset.UtcNow.AddSeconds(expiresIn).ToString("o"));

                    await HttpContext.SignInAsync("Cookies", authResult.Principal, authResult.Properties);

                    return RedirectToAction("TokenInfo", new { fetchUserInfo = true });
                }

                var errorBody = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[RefreshTokens] Сервер отклонил запрос: {response.StatusCode} — {errorBody}");
                storage.RemoveTokens(oldAccessToken ?? "");
                return RedirectToAction("ForceLogin");
            }
            catch (HttpRequestException ex)
            {
                // Соединение оборвалось до получения ответа (нестабильность бета-сервера Авторизы).
                // Возвращаем на страницу токенов — пользователь может попробовать снова.
                Console.WriteLine($"[RefreshTokens] Соединение прервано: {ex.Message}");
                return RedirectToAction("TokenInfo");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            // Удаляем Refresh Token из серверного хранилища до уничтожения сессии,
            // пока Access Token из куки ещё доступен для поиска соответствующей записи.
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(accessToken))
            {
                var storage = HttpContext.RequestServices.GetRequiredService<TokenStorage>();
                storage.RemoveTokens(accessToken);
            }

            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                "Cookies");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
