// Test B10: Customer search with EF Core

public Task<List<Customer>> Search(string name, string sortBy)
{
    return _db.Customers
        .FromSqlRaw(
            $"SELECT * FROM Customers WHERE Name = '{name}' " +
            $"ORDER BY {sortBy}")
        .ToListAsync();
}
