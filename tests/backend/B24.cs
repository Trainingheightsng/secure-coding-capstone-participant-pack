// Test B24: Statement email templates

public async Task<string> RenderAsync(string template, Customer customer)
{
    // template example: "Dear {Name}, your balance is {Balance}"
    var code = "$\"" + template + "\"";
    return await CSharpScript.EvaluateAsync<string>(code,
        globals: customer);
}
