resource "aws_s3_bucket" "bad_public_rw_bucket_15" {
  name = "bad_public_rw_bucket_15"
  acl = "public-read-write"
}
