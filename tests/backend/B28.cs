// Test B28: Changing a daily limit

public record LimitChange(int DailyLimit);

[HttpPost("me/limits")]
public IActionResult Change(LimitChange change)
{
    _limits.SetDailyLimit(User.AccountNo(), change.DailyLimit);
    return Ok();
}
