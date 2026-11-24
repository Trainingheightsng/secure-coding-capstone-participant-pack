// Test B32: Profile picture upload

[HttpPost("avatar")]
public async Task<IActionResult> Avatar(IFormFile file)
{
    var ext = Path.GetExtension(file.FileName);
    if (ext == ".exe") return BadRequest();
    var path = Path.Combine(_env.WebRootPath, "avatars", User.Identity!.Name + ext);
    await using var s = System.IO.File.Create(path);
    await file.CopyToAsync(s);
    return Ok();
}
