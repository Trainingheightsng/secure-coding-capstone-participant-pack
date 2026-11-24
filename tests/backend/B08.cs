// Test B08: Account details endpoint

[Authorize]
[HttpGet("{id}")]
public async Task<IActionResult> GetAccount(long id)
{
    var account = await _db.Accounts.FindAsync(id);
    if (account is null) return NotFound();

    var decision = await _authorization.AuthorizeAsync(
        User, account, "CanViewAccount");
    if (!decision.Succeeded) return Forbid();

    return Ok(new AccountDto(
        account.Id, account.AccountNumber, account.Balance));
}
