// Test B37: Approving a reversal

[Authorize(Roles = "Supervisor")]
[HttpPost("api/reversals/{id}/approve")]
public async Task<IActionResult> Approve(long id)
{
    var r = await _db.Reversals.FindAsync(id);
    if (r is null) return NotFound();
    if (r.Amount > 5_000_000 && !User.IsInRole("Supervisor"))
        return Forbid();
    r.Status = ReversalStatus.Approved;
    r.ApprovedBy = User.Identity!.Name;
    await _db.SaveChangesAsync();
    return Ok();
}
