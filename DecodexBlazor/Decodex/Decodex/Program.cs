
using System.Security.Claims;
using System.Threading.RateLimiting;
using Decodex.Components;
using Decodex.Data;
using Decodex.DTOs.Auth;
using Decodex.Models.Auth;
using Decodex.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// BLAZOR
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();

// DATABASE
string connectionString =
    builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException(
        "Connection string DefaultConnection lipseste.");

builder.Services.AddDbContextFactory<AppDbContext>(options =>
    options.UseSqlServer(connectionString));

// SERVICII
builder.Services.AddSingleton<PasswordService>();
builder.Services.AddScoped<AuthService>();

// COOKIE AUTHENTICATION
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "Decodex.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;

        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";

        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();

// LIMITARE INCERCARI DE AUTENTIFICARE
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode =
        StatusCodes.Status429TooManyRequests;

    options.AddPolicy("auth", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey:
                context.Connection.RemoteIpAddress?.ToString()
                ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

var app = builder.Build();

// HTTP PIPELINE
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error",
        createScopeForErrors: true);

    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute(
    "/not-found",
    createScopeForStatusCodePages: true);

app.UseHttpsRedirection();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAntiforgery();

app.MapStaticAssets();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// ==========================
// REGISTER
// ==========================
app.MapPost("/auth/register", async (
    HttpContext http,
    IAntiforgery antiforgery,
    AuthService authService) =>
{
    if (!await antiforgery.IsRequestValidAsync(http))
        return Results.BadRequest("Cerere invalida.");

    var form = await http.Request.ReadFormAsync();

    var request = new RegisterRequest
    {
        FullName = form["FullName"].ToString(),
        Email = form["Email"].ToString(),
        Password = form["Password"].ToString(),
        ConfirmPassword = form["ConfirmPassword"].ToString()
    };

    var result = await authService.RegisterAsync(request);

    if (result.User is null)
    {
        string error = result.Error ?? "invalid";

        return Results.Redirect(
            "/register?error=" +
            Uri.EscapeDataString(error));
    }

    await SignInUserAsync(http, result.User, false);

    return Results.Redirect("/dashboard");
})
.RequireRateLimiting("auth");

// ==========================
// LOGIN
// ==========================
app.MapPost("/auth/login", async (
    HttpContext http,
    IAntiforgery antiforgery,
    AuthService authService) =>
{
    if (!await antiforgery.IsRequestValidAsync(http))
        return Results.BadRequest("Cerere invalida.");

    var form = await http.Request.ReadFormAsync();

    var request = new LoginRequest
    {
        Email = form["Email"].ToString(),
        Password = form["Password"].ToString(),
        RememberMe =
            form["RememberMe"].ToString() == "true"
    };

    AppUser? user =
        await authService.LoginAsync(request);

    if (user is null)
        return Results.Redirect("/login?error=invalid");

    await SignInUserAsync(
        http,
        user,
        request.RememberMe);

    return Results.Redirect("/dashboard");
})
.RequireRateLimiting("auth");

// ==========================
// LOGOUT
// ==========================
app.MapPost("/auth/logout", async (
    HttpContext http,
    IAntiforgery antiforgery) =>
{
    if (!await antiforgery.IsRequestValidAsync(http))
        return Results.BadRequest("Cerere invalida.");

    await http.SignOutAsync(
        CookieAuthenticationDefaults.AuthenticationScheme);

    return Results.Redirect("/");
})
.RequireAuthorization();

// COOKIE SIGN-IN
static async Task SignInUserAsync(
    HttpContext http,
    AppUser user,
    bool rememberMe)
{
    var claims = new List<Claim>
    {
        new(
            ClaimTypes.NameIdentifier,
            user.Id.ToString()),

        new(
            ClaimTypes.Name,
            user.FullName),

        new(
            ClaimTypes.Email,
            user.Email)
    };

    var identity = new ClaimsIdentity(
        claims,
        CookieAuthenticationDefaults.AuthenticationScheme);

    var principal = new ClaimsPrincipal(identity);

    var properties = new AuthenticationProperties
    {
        IsPersistent = rememberMe
    };

    if (rememberMe)
    {
        properties.ExpiresUtc =
            DateTimeOffset.UtcNow.AddDays(14);
    }

    await http.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        principal,
        properties);
}

app.Run();
