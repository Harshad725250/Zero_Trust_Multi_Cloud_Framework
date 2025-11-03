resource "aws_iam_policy" "bad_wild_policy_3" {
  name = "bad_wild_policy_3"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
