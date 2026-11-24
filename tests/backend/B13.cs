// Test B13: Saved dashboard layout

[HttpGet("api/dashboard")]
public IActionResult Dashboard()
{
    var raw = Request.Cookies["layout"];
    var settings = new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.Auto
    };
    var layout = JsonConvert.DeserializeObject<DashboardLayout>(raw, settings);
    return Ok(BuildDashboard(layout));
}
