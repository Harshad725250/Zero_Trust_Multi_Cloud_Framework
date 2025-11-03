resource "aws_s3_bucket" "bad_public_rw_bucket_37" {
  name = "bad_public_rw_bucket_37"
  acl = "public-read-write"
}
