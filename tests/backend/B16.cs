// Test B16: Setting up statement storage

public async Task SetUpStatementStorageAsync()
{
    var container = new BlobContainerClient(_connectionString, "statements");
    await container.CreateIfNotExistsAsync();
    await container.SetAccessPolicyAsync(
        PublicAccessType.BlobContainer);   // so React can link to PDFs
}
// React links to https://providus.blob.core.windows.net/statements/<customerId>/<month>.pdf
