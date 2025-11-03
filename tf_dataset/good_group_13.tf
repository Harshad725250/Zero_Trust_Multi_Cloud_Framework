resource "aws_security_group" "good_group_13" {
  name = "good_group_13"
  ingress { from_port = 22 to_port = 22 cidr_blocks = ["10.0.0.0/24"] }
}
