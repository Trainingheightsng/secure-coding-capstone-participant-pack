// Test B38: Importing a zip of statements

public void importStatements(MultipartFile upload) throws IOException {
    Path targetDir = Paths.get("/data/imports", currentClientId());
    try (ZipInputStream zip = new ZipInputStream(upload.getInputStream())) {
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path out = targetDir.resolve(entry.getName());
            Files.createDirectories(out.getParent());
            Files.copy(zip, out, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
