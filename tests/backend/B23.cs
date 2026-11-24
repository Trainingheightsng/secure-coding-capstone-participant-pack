// Test B23: Importing a zip of statements

public void ImportStatements(IFormFile upload)
{
    var targetDir = Path.Combine("/data/imports", CurrentClientId());
    using var zip = new ZipArchive(upload.OpenReadStream());
    foreach (var entry in zip.Entries)
    {
        var dest = Path.Combine(targetDir, entry.FullName);
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        entry.ExtractToFile(dest, overwrite: true);
    }
}
