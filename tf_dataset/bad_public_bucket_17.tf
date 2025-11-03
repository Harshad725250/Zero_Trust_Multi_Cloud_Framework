resource "aws_s3_bucket" "bad_public_bucket_17" {
  name = "bad_public_bucket_17"
  acl = "public-read"
}
