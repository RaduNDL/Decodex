
using System.ComponentModel.DataAnnotations;
using Decodex.Data;
using Decodex.DTOs.Auth;
using Decodex.Models.Auth;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Decodex.Services;

public sealed class AuthService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly PasswordService _passwordService;

    public AuthService(
        IDbContextFactory<AppDbContext> dbFactory,
        PasswordService passwordService)
    {
        _dbFactory = dbFactory;
        _passwordService = passwordService;
    }

    public async Task<(AppUser? User, string? Error)>
        RegisterAsync(RegisterRequest request)
    {
        string name = request.FullName.Trim();
        string email = request.Email.Trim();

        if (name.Length < 2 || name.Length > 80)
            return (null, "name");

        if (email.Length > 256 ||
            !new EmailAddressAttribute().IsValid(email))
        {
            return (null, "email");
        }

        if (request.Password.Length < 12 ||
            request.Password.Length > 128)
        {
            return (null, "password");
        }

        if (request.Password != request.ConfirmPassword)
            return (null, "confirm");

        string normalizedEmail = email.ToUpperInvariant();

        await using AppDbContext db =
            await _dbFactory.CreateDbContextAsync();

        bool exists = await db.Users
            .AnyAsync(user =>
                user.NormalizedEmail == normalizedEmail);

        if (exists)
            return (null, "exists");

        var user = new AppUser
        {
            FullName = name,
            Email = email,
            NormalizedEmail = normalizedEmail,
            PasswordHash =
                _passwordService.HashPassword(request.Password)
        };

        db.Users.Add(user);

        try
        {
            await db.SaveChangesAsync();
        }
        catch (DbUpdateException ex)
            when (ex.InnerException is SqlException
            { Number: 2601 or 2627 })
        {
            return (null, "exists");
        }

        return (user, null);
    }

    public async Task<AppUser?> LoginAsync(
        LoginRequest request)
    {
        string normalizedEmail =
            request.Email.Trim().ToUpperInvariant();

        if (normalizedEmail.Length > 256 ||
            string.IsNullOrEmpty(request.Password))
        {
            return null;
        }

        await using AppDbContext db =
            await _dbFactory.CreateDbContextAsync();

        AppUser? user = await db.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u =>
                u.NormalizedEmail == normalizedEmail);

        if (user is null)
            return null;

        bool validPassword =
            _passwordService.VerifyPassword(
                request.Password,
                user.PasswordHash
            );

        return validPassword ? user : null;
    }
}
