resource "aws_s3_bucket" "bad_public_bucket_5" {
  name = "bad_public_bucket_5"
  acl = "public-read"
}
