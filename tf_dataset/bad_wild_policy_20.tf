resource "aws_iam_policy" "bad_wild_policy_20" {
  name = "bad_wild_policy_20"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
