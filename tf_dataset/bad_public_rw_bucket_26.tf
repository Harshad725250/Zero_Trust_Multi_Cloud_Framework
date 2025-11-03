resource "aws_s3_bucket" "bad_public_rw_bucket_26" {
  name = "bad_public_rw_bucket_26"
  acl = "public-read-write"
}
