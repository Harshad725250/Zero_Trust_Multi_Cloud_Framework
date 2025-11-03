resource "aws_iam_policy" "bad_wild_policy_47" {
  name = "bad_wild_policy_47"
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
