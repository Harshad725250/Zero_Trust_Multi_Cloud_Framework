resource "aws_iam_policy" "bad_wild_policy_22" {
  name = "bad_wild_policy_22"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
