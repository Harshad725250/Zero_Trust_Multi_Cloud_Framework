resource "aws_s3_bucket" "bad_public_bucket_40" {
  name = "bad_public_bucket_40"
  acl = "public-read"
}
