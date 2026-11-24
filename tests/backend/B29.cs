// Test B29: Bundling statements for download

[HttpPost("api/statements/bundle")]
public async Task<string> Bundle(List<string> files)
{
    var output = $"/tmp/bundle-{Guid.NewGuid()}.tgz";
    var psi = new ProcessStartInfo("tar") { UseShellExecute = false };
    foreach (var a in new[] { "-czf", output, "-C", "/data/statements" })
        psi.ArgumentList.Add(a);
    foreach (var f in files) psi.ArgumentList.Add(f);
    using var p = Process.Start(psi)!;
    await p.WaitForExitAsync();
    return output;
}
