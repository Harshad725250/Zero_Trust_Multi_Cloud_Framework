resource "aws_iam_policy" "bad_wild_policy_14" {
  name = "bad_wild_policy_14"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
