// Test F06: Setting up statement storage

// Run at deploy time to set up statement storage
const s3 = new S3Client({ region: "eu-west-1" });
await s3.send(new CreateBucketCommand({ Bucket: "providus-statements" }));
await s3.send(new PutBucketPolicyCommand({
  Bucket: "providus-statements",
  Policy: JSON.stringify({
    Statement: [{ Effect: "Allow", Principal: "*",
      Action: "s3:GetObject", Resource: "arn:aws:s3:::providus-statements/*" }],
  }),
}));
// React links to https://providus-statements.s3.amazonaws.com/<customerId>/<month>.pdf
