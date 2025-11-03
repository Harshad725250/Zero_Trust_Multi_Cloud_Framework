resource "aws_s3_bucket" "bad_public_bucket_32" {
  name = "bad_public_bucket_32"
  acl = "public-read"
}
