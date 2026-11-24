// Test B09: Saved dashboard layout

[HttpGet("api/dashboard")]
public IActionResult Dashboard()
{
    var raw = Request.Cookies["layout"] ?? "{}";
    // Plain data only: widget kinds are strings like "chart"
    var dto = JsonSerializer.Deserialize<DashboardLayoutDto>(raw)
              ?? DashboardLayoutDto.Default;
    // Our code maps "chart" → ChartWidget from a fixed list
    return Ok(BuildDashboard(dto.ToWidgets()));
}
