resource "aws_s3_bucket" "bad_public_rw_bucket_21" {
  name = "bad_public_rw_bucket_21"
  acl = "public-read-write"
}
