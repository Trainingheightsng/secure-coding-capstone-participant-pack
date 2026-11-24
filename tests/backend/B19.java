// Test B19: Setting up statement storage

// Run at deploy time to set up statement storage
s3.createBucket(b -> b.bucket("providus-statements"));
String policy = """
    { "Statement": [{ "Effect": "Allow", "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::providus-statements/*" }] }
    """;
s3.putBucketPolicy(b -> b.bucket("providus-statements").policy(policy));
// React links to https://providus-statements.s3.amazonaws.com/<customerId>/<month>.pdf
