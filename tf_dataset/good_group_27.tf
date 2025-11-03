resource "aws_security_group" "good_group_27" {
  name = "good_group_27"
  ingress { from_port = 22 to_port = 22 cidr_blocks = ["10.0.0.0/24"] }
}
