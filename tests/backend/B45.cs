// Test B45: Customer search repository

public async Task<List<Customer>> SearchAsync(string name)
{
    var sql =
        "SELECT Id, Name FROM Customers " +
        "WHERE Name = '" + name + "'";
    using var cmd =
        new SqlCommand(sql, _connection);
    using var reader =
        await cmd.ExecuteReaderAsync();
    return await MapCustomersAsync(reader);
}
