resource "aws_iam_policy" "good_policy_25" {
  name = "good_policy_25"
  policy = jsonencode({ Statement = [{ Action = ["s3:GetObject"], Effect = "Allow", Resource = ["arn:aws:s3:::mybucket/*"] }] })
}
