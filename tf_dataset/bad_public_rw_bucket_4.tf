resource "aws_s3_bucket" "bad_public_rw_bucket_4" {
  name = "bad_public_rw_bucket_4"
  acl = "public-read-write"
}
