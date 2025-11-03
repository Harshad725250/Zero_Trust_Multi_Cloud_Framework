resource "aws_iam_policy" "good_policy_0" {
  name = "good_policy_0"
  policy = jsonencode({ Statement = [{ Action = ["s3:GetObject"], Effect = "Allow", Resource = ["arn:aws:s3:::mybucket/*"] }] })
}
