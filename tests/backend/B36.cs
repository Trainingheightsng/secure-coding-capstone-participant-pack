// Test B36: Transaction search

builder.Services.AddRateLimiter(o => o.AddFixedWindowLimiter("search", l =>
    { l.PermitLimit = 30; l.Window = TimeSpan.FromMinutes(1); }));

app.MapGet("/api/transactions/search",
    async (string q, int? size, ClaimsPrincipal user, BankDb db) =>
    {
        var text = q.Length > 100 ? q[..100] : q;
        var take = Math.Clamp(size ?? 20, 1, 100);
        return await db.Transactions
            .Where(t => t.AccountId == user.AccountId()
                     && t.Narration.Contains(text))
            .Take(take)
            .ToListAsync();
    })
   .RequireRateLimiting("search");
