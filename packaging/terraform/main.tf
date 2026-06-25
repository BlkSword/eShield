terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  default = "us-east-1"
}

variable "instance_type" {
  default = "t3.medium"
}

variable "key_name" {
  description = "AWS EC2 key pair name"
}

variable "allowed_cidr" {
  description = "CIDR allowed to access the dashboard"
  default     = "0.0.0.0/0"
}

provider "aws" {
  region = var.region
}

resource "aws_security_group" "eshield" {
  name_prefix = "eshield-"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  ingress {
    description = "eShield Web / API / Prometheus"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "eshield" {
  ami                    = data.aws_ami.debian.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.eshield.id]
  user_data              = file("${path.module}/user-data.sh")

  tags = {
    Name = "eshield-node"
  }
}

data "aws_ami" "debian" {
  most_recent = true
  owners      = ["136693071363"] # Debian official account

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }
}

output "instance_ip" {
  value = aws_instance.eshield.public_ip
}
