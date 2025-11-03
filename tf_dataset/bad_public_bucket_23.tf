resource "aws_s3_bucket" "bad_public_bucket_23" {
  name = "bad_public_bucket_23"
  acl = "public-read"
}
