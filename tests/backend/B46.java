// Test B46: Transfer receipt page

@GetMapping(value = "/receipt", produces = MediaType.TEXT_HTML_VALUE)
@ResponseBody
public String receipt(@RequestParam String payee, @RequestParam BigDecimal amount) {
    return "<html><body><h2>Transfer sent</h2>"
         + "<p>Paid " + amount + " to " + payee + "</p>"
         + "</body></html>";
}
