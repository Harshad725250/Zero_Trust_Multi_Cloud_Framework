resource "aws_security_group" "bad_open_group_36" {
  name = "bad_open_group_36"
  ingress { from_port = 0 to_port = 65535 cidr_blocks = ["0.0.0.0/0"] }
}
