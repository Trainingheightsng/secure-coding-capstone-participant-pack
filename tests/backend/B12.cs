// Test B12: Testing a partner webhook

[HttpPost("api/webhooks/test")]
public async Task<string> TestWebhook(WebhookRequest req)
{
    var res = await _http.PostAsJsonAsync(
        req.CallbackUrl, SamplePayment());
    var body = await res.Content.ReadAsStringAsync();
    return $"Partner replied {(int)res.StatusCode}: {body}";
}
