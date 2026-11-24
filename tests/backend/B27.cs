// Test B27: Account details endpoint

[Authorize]
[HttpGet("{id}")]
public async Task<IActionResult> GetAccount(long id)
{
    var account = await _db.Accounts.FindAsync(id);
    if (account is null)
        return NotFound();
    return Ok(account);
}
