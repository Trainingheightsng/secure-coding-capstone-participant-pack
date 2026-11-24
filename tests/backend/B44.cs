// Test B44: Branch notice

[HttpGet("notice")]
public IActionResult Notice(string branch)
{
    var html = $"<h3>Branch notice</h3><div>Welcome to the {branch} branch</div>";
    return Content(html, "text/html");
}
