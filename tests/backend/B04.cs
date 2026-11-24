// Test B04: Sanctions screening at onboarding

public async Task<bool> IsSanctionedAsync(Customer c)
{
    try
    {
        var r = await _screening.CheckAsync(c.Bvn);   // null on timeout
        return r.Matches.Count > 0;
    }
    catch (Exception ex)
    {
        _log.LogWarning(ex, "Screening failed for {Id}", c.Id);
        return false;
    }
}
