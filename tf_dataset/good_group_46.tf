resource "aws_security_group" "good_group_46" {
  name = "good_group_46"
  ingress { from_port = 22 to_port = 22 cidr_blocks = ["10.0.0.0/24"] }
}
