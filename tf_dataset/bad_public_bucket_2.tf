resource "aws_s3_bucket" "bad_public_bucket_2" {
  name = "bad_public_bucket_2"
  acl = "public-read"
}
