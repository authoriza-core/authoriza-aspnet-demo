using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PetrAuthDemo.Models;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;

namespace PetrAuthDemo.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> TokenInfo(bool fetchUserInfo = false)
        {
            var authResult = await HttpContext.AuthenticateAsync("Cookies");
            ViewBag.LastRefreshTime = authResult.Properties?.IssuedUtc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss") ?? "Неизвестно";

            // 1. Достаем токены и метаданные из защищенной сессионной куки
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            var idToken = await HttpContext.GetTokenAsync("id_token");
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token") ?? "Refresh Token не выдан";
            var tokenType = await HttpContext.GetTokenAsync("token_type") ?? "Bearer";
            var expiresAt = await HttpContext.GetTokenAsync("expires_at");

            // 2. Считаем, сколько секунд осталось до смерти токена
            string expiresIn = "";
            if (DateTimeOffset.TryParse(expiresAt, out var expDate))
            {
                var timeRemaining = expDate - DateTimeOffset.UtcNow;
                expiresIn = Math.Max(0, (int)timeRemaining.TotalSeconds).ToString() + " секунд";
                // Добавь после строки где считаешь expiresIn
                ViewBag.ExpiresAtJs = expDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
            }

            // 3. Расшифровываем JWT-токены, чтобы достать их Payload
            var handler = new JwtSecurityTokenHandler();

            string idTokenPayload = "Пусто";
            if (!string.IsNullOrEmpty(idToken) && handler.CanReadToken(idToken))
            {
                var jwt = handler.ReadJwtToken(idToken);
                idTokenPayload = jwt.Payload.SerializeToJson();
            }

            string accessTokenPayload = "Пусто";
            if (!string.IsNullOrEmpty(accessToken) && handler.CanReadToken(accessToken))
            {
                var jwt = handler.ReadJwtToken(accessToken);
                accessTokenPayload = jwt.Payload.SerializeToJson();
            }


            if (fetchUserInfo)
                await LoadUserInfoDataAsync(accessToken);
            else
            {
                ViewBag.UserInfoJson = "Нажмите кнопку для запроса";
                ViewBag.FetchTime = "Не запрашивалось";
            }

            // 4. Упаковываем всё в ViewBag для отправки на страницу
            ViewBag.AccessToken = accessToken;
            ViewBag.IdToken = idToken;
            ViewBag.RefreshToken = refreshToken;
            ViewBag.TokenType = tokenType;
            ViewBag.ExpiresAt = expiresAt;
            ViewBag.ExpiresIn = expiresIn;
            ViewBag.IdTokenPayload = idTokenPayload;
            ViewBag.AccessTokenPayload = accessTokenPayload;


            ViewBag.UserName = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value
                               ?? User.FindFirst("name")?.Value
                               ?? "Нет данных";

            ViewBag.UserEmail = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                                ?? User.FindFirst("email")?.Value
                                ?? "Нет данных";

            // Scope ищем в клеймах, либо выводим дефолтный
            ViewBag.Scope = User.FindFirst("scope")?.Value ?? "openid profile";

            return View();
        }


        [HttpPost]
        [Authorize]
        public async Task<IActionResult> FetchUserInfo()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            await LoadUserInfoDataAsync(accessToken);

            // Возвращаем только кусок страницы с результатом
            return PartialView("_UserInfoPartial");
        }

        private async Task LoadUserInfoDataAsync(string? accessToken)
        {
            string userInfoJson = "Нет данных";
            string fetchTime = "Не запрашивалось";

            if (!string.IsNullOrEmpty(accessToken))
            {
                try
                {
                    // 1. Достаем динамический адрес UserInfo из закэшированного Discovery
                    var oidcOptions = HttpContext.RequestServices
                        .GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>>()
                        .Get("OpenIdConnect");

                    var oidcConfig = await oidcOptions.ConfigurationManager.GetConfigurationAsync(CancellationToken.None);

                    Console.WriteLine($"=== UserInfo Debug ===");
                    Console.WriteLine($"Token is null: {accessToken == null}");
                    Console.WriteLine($"Token length: {accessToken?.Length}");
                    Console.WriteLine($"Token prefix: {accessToken?.Substring(0, Math.Min(50, accessToken.Length))}");
                    Console.WriteLine($"UserInfo endpoint: {oidcConfig.UserInfoEndpoint}");

                    // 2. Делаем HTTP-запрос
                    using var client = new HttpClient();

                    var requestBody = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("access_token", accessToken)
                    });

                    var response = await client.PostAsync(oidcConfig.UserInfoEndpoint, requestBody);

                    if (response.IsSuccessStatusCode)
                    {
                        userInfoJson = await response.Content.ReadAsStringAsync();
                        fetchTime = DateTime.Now.ToString("HH:mm:ss (dd.MM.yyyy)");
                    }
                    else
                    {
                        var errorDetails = await response.Content.ReadAsStringAsync();
                        userInfoJson = $"Код ошибки: {response.StatusCode}\nПричина от Авторизы: {errorDetails}";
                    }
                }
                catch (Exception ex)
                {
                    userInfoJson = $"Внутренняя ошибка сети: {ex.Message}";
                }
            }

            ViewBag.UserInfoJson = userInfoJson;
            ViewBag.FetchTime = fetchTime;
        }

        //Обычный вход (SSO)
        [HttpGet]
        public IActionResult Login()
        {
            return Challenge(new AuthenticationProperties { RedirectUri = "/" }, "OpenIdConnect");
        }

        //Жесткий вход (Запрос Refresh Token)
        [HttpGet]
        public IActionResult ForceLogin()
        {
            var properties = new AuthenticationProperties { RedirectUri = "/" };

            // Ставим флаг для Program.cs
            properties.Items["ForceConsent"] = "true";

            return Challenge(properties, "OpenIdConnect");
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> RefreshTokens()
        {
            var authResult = await HttpContext.AuthenticateAsync("Cookies");
            if (!authResult.Succeeded) return RedirectToAction("Login");

            var oldAccessToken = authResult.Properties.GetTokenValue("access_token");
            var storage = HttpContext.RequestServices.GetRequiredService<TokenStorage>();
            var refreshToken = storage.FindRefreshByAccess(oldAccessToken ?? "");

            if (string.IsNullOrEmpty(refreshToken)) return RedirectToAction("ForceLogin");

            var config = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var authority = config["OidcSettings:Authority"];
            var clientId = config["OidcSettings:ClientId"];
            var clientSecret = config["OidcSettings:ClientSecret"];

            using var httpClient = new HttpClient();
            var requestBody = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
            });

            var response = await httpClient.PostAsync($"{authority.TrimEnd('/')}/token", requestBody);

            if (response.IsSuccessStatusCode)
            {
                var json = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var newAccessToken = json.RootElement.GetProperty("access_token").GetString();
                var expiresIn = json.RootElement.GetProperty("expires_in").GetInt32();
                var newRefresh = json.RootElement.TryGetProperty("refresh_token", out var r) ? r.GetString() : refreshToken;

                storage.UpdateRotatedTokens(oldAccessToken, newAccessToken, newRefresh);
                authResult.Properties.UpdateTokenValue("access_token", newAccessToken);
                authResult.Properties.UpdateTokenValue("expires_at", DateTimeOffset.UtcNow.AddSeconds(expiresIn).ToString("o"));

                await HttpContext.SignInAsync("Cookies", authResult.Principal, authResult.Properties);
                return RedirectToAction("TokenInfo");
                // return RedirectToAction("TokenInfo", new { fetchUserInfo = true }); // для автоматического запроса UserInfo после обновления токена
            }
            return RedirectToAction("ForceLogin");
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            // Закомментировано для тестирования json

            //// 1. Успеваем достать Access Token до того, как сессия будет уничтожена
            //var accessToken = await HttpContext.GetTokenAsync("access_token");

            //if (!string.IsNullOrEmpty(accessToken))
            //{
            //    // 2. Обращаемся к нашему хранилищу и приказываем удалить эту пару токенов
            //    var storage = HttpContext.RequestServices.GetRequiredService<TokenStorage>();
            //    storage.RemoveTokens(accessToken);
            //}

            //// 3. SignOut очистит локальную куку в браузере и перенаправит на главную
            return SignOut(
                new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = "/" },
                "Cookies"
            );
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
