// Test B18: Virus-scanning a KYC upload

[HttpPost("api/kyc/scan")]
public async Task<IActionResult> Scan(IFormFile file)
{
    var path = $"/tmp/kyc/{Guid.NewGuid()}-{file.FileName}";
    await using (var fs = System.IO.File.Create(path))
        await file.CopyToAsync(fs);
    var p = Process.Start("/bin/sh",
        $"-c \"clamscan --no-summary {path}\"");
    await p.WaitForExitAsync();
    return Ok(new { clean = p.ExitCode == 0 });
}
