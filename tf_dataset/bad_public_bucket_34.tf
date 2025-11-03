resource "aws_s3_bucket" "bad_public_bucket_34" {
  name = "bad_public_bucket_34"
  acl = "public-read"
}
