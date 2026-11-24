// Test B26: Virus-scanning a KYC upload

@PostMapping("/api/kyc/scan")
public Map<String, Boolean> scan(@RequestParam MultipartFile file) throws Exception {
    Path path = Paths.get("/tmp/kyc", UUID.randomUUID() + "-" + file.getOriginalFilename());
    file.transferTo(path);
    Process p = Runtime.getRuntime().exec(new String[] {
        "sh", "-c", "clamscan --no-summary " + path });
    return Map.of("clean", p.waitFor() == 0);
}
