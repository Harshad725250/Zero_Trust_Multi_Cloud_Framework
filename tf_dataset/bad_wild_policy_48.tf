resource "aws_iam_policy" "bad_wild_policy_48" {
  name = "bad_wild_policy_48"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
