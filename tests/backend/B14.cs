// Test B14: Statement query error handling

try
{
    return Ok(await _repo.Statement(accountNo, from, to));
}
catch (SqlException ex)
{
    return StatusCode(500, new { error = ex.Message, query = ex.Data["sql"], ex.StackTrace });
}
