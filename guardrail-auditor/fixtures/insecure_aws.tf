terraform {
  required_version = ">= 1.0"
}

resource "aws_s3_bucket" "data" {
  bucket = "corp-data"
  acl    = "public-read"
}

resource "aws_security_group" "ssh" {
  name = "wide-open-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role_policy" "admin" {
  name = "inline-admin"
  role = "example-role"
  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
  EOF
}
