resource "aws_s3_bucket" "logs" {
  bucket = "corp-logs"
  acl    = "private"
}

resource "aws_security_group" "app" {
  name = "app-sg"

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks     = ["10.0.0.0/8"]
    description     = "HTTPS from VPC"
  }
}
