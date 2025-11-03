resource "aws_iam_policy" "bad_wild_policy_16" {
  name = "bad_wild_policy_16"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
