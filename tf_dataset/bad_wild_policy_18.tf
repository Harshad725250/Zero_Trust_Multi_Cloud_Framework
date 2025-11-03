resource "aws_iam_policy" "bad_wild_policy_18" {
  name = "bad_wild_policy_18"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
