// Test B47: KYC document upload

@PostMapping("/kyc/documents")
public String upload(@RequestParam MultipartFile doc) throws IOException {
    if (!doc.getContentType().startsWith("image/")) throw new BadRequestException();
    Path target = Paths.get("/var/www/portal/static/kyc", doc.getOriginalFilename());
    doc.transferTo(target);
    return "/kyc/" + doc.getOriginalFilename();
}
