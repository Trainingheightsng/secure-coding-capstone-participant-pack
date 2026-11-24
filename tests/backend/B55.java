// Test B55: Testing a partner webhook

@PostMapping("/api/webhooks/test")
public String testWebhook(@RequestBody WebhookRequest req) {
    RestTemplate rest = new RestTemplate();
    ResponseEntity<String> res = rest.postForEntity(
        req.callbackUrl(), samplePayment(), String.class);
    return "Partner replied " + res.getStatusCode() + ": " + res.getBody();
}
