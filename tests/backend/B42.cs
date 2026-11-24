// Test B42: Beneficiary form handler

[HttpPost]
public async Task<IActionResult> AddBeneficiary(
    AddBeneficiaryRequest request)
{
    await _service.AddBeneficiaryAsync(User, request);
    return Ok();
}
