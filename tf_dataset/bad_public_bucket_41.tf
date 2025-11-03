resource "aws_s3_bucket" "bad_public_bucket_41" {
  name = "bad_public_bucket_41"
  acl = "public-read"
}
