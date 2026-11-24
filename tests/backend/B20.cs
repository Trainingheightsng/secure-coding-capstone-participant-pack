// Test B20: Transaction search

app.MapGet("/api/transactions/search",
    async (string q, int? size, ClaimsPrincipal user, BankDb db) =>
        await db.Transactions
            .Where(t => t.AccountId == user.AccountId()
                     && t.Narration.Contains(q))
            .Take(size ?? 20)
            .ToListAsync());
