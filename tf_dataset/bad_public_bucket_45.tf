resource "aws_s3_bucket" "bad_public_bucket_45" {
  name = "bad_public_bucket_45"
  acl = "public-read"
}
