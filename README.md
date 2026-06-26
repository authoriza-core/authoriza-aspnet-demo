# ASP.NET интеграция Авториза с OIDC Authorization Code Flow

## Назначение проекта

Демо-приложение на ASP.NET Core 10 MVC, реализующее интеграцию с сервисом **Авториза** по протоколу OpenID Connect.

**Основной функционал:**
- Вход через Авторизу с поддержкой SSO
- Хранение Refresh Token на сервере (не в куке)
- Автоматическое обновление Access Token до истечения срока
- Запрос UserInfo Endpoint с fallback на ID Token
- Выход из системы с очисткой токенов

---

## Стек и используемые библиотеки

| Компонент | Технология | Назначение |
|---|---|---|
| **Веб-фреймворк** | ASP.NET Core 10 MVC | Маршрутизация, контроллеры, views |
| **OIDC-клиент** | Microsoft.AspNetCore.Authentication.OpenIdConnect 10.0.9 | Authorization Code Flow, PKCE |
| **Токены** | System.IdentityModel.Tokens.Jwt | Декодирование JWT payload |

---

## Требования к окружению

- **.NET SDK:** 10.0+
- **ОС:** Windows / macOS / Linux
- **Браузер:** с поддержкой cookie

---

## Установка зависимостей

```bash
dotnet restore
```

Установка LibMan CLI (один раз на машину) и восстановление клиентских библиотек:

```bash
dotnet tool install -g Microsoft.Web.LibraryManager.Cli
libman restore
```

---

## Настройка приложения в Авторизе

### Регистрация приложения

1. Перейдите в панель управления Авторизы
2. Создайте новый проект и приложение в нём
3. Укажите **Redirect URI**: `https://localhost:7094/callback`
4. Тип приложения: **Confidential**

### Получение credentials

Скопируйте из конфигурации приложения:
- **client_id**
- **client_secret**

### Настройка конфигурации

В `appsettings.json` укажите `Authority` и `ClientId`:

```json
"OidcSettings": {
  "Authority": "https://<ваш-сервер-авторизы>/oidc",
  "ClientId": "ваш-client-id",
  "ClientSecret": "SECRET"
}
```

`ClientSecret` рекомендуется хранить через .NET User Secrets:

```bash
dotnet user-secrets init
dotnet user-secrets set "OidcSettings:ClientSecret" "ваш-client-secret"
```

---

## Запуск проекта

```bash
dotnet run
```

После запуска приложение доступно по адресу: **https://localhost:7094**

---

## Проверка основных сценариев

### 1. Вход (SSO)

```
1. Откройте https://localhost:7094
2. Нажмите "Войти (SSO)"
3. Введите учётные данные в форме Авторизы
4. После успешного входа — редирект на /TokenInfo
```

**Ожидаемый результат:** на странице отображаются Access Token, ID Token, их JWT Payload и данные пользователя из UserInfo Endpoint.

### 2. Автоматическое обновление токенов

```
1. Авторизуйтесь в приложении
2. Дождитесь момента, когда до истечения Access Token останется < 5 минут
3. Выполните любой запрос к приложению
```

**Ожидаемый результат:** токены обновляются автоматически в фоне, пользователь не замечает подмены. В консоли приложения появится:
```
Access Token истекает через 5 минут. Запускаем автообновление...
Автообновление успешно. Новый Access Token: eyJhbG...
```

### 3. Ручное обновление токенов

```
1. Авторизуйтесь в приложении
2. На странице /TokenInfo нажмите "Обновить токены"
```

**Ожидаемый результат:** Access Token обновлён, страница перезагрузилась с новыми данными, UserInfo пересчитан.

### 4. Запрос UserInfo Endpoint

```
1. Авторизуйтесь в приложении
2. На странице /TokenInfo нажмите "Запросить UserInfo"
```

**Ожидаемый результат:** в блоке "Данные профиля" появляется JSON-ответ от UserInfo Endpoint Авторизы с полями `sub`, `email`, `name` и другими.

### 5. Выход

```
1. Нажмите "Выйти" в навигационной панели
```

**Ожидаемый результат:** Refresh Token удалён из `tokens.json`, куки очищена, пользователь перенаправлен на главную страницу.

---

## Структура репозитория

| Файл | Назначение |
|---|---|
| `Program.cs` | Конфигурация OIDC, middleware, автообновление токенов |
| `Controllers/HomeController.cs` | Маршруты: Index, TokenInfo, FetchUserInfo, RefreshTokens, Login, Logout |
| `Services/TokenStorage.cs` | Хранение Refresh Token в `tokens.json`|
| `Views/Home/TokenInfo.cshtml` | Отображение токенов, JWT Payload, UserInfo |
| `Views/Shared/_UserInfoPartial.cshtml` | Partial view для AJAX-запроса UserInfo |
| `appsettings.json` | Конфигурация OIDC (Authority, ClientId) |
| `tokens.json` | Серверное хранилище Refresh Token (создаётся автоматически) |
