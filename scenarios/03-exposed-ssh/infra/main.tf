# Scenario 03 stands up an SSH-listening host behind a security group. The group is born
# closed (egress only) ON PURPOSE: the attack introduces the 0.0.0.0/0 -> 22 ingress that
# the range is built to detect and remediate, so the dangerous rule fires a real
# AuthorizeSecurityGroupIngress event instead of being baked in at apply time.
# tfsec/Checkov findings on this instance/group are expected.

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_security_group" "ssh" {
  name        = "${var.project_name}-lab-ssh"
  description = "Lab SSH host - born closed, opened by the attack"
  vpc_id      = data.aws_vpc.default.id

  # No ingress here: the attack adds the 0.0.0.0/0 -> 22 rule out-of-band.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project  = var.project_name
    Scenario = "03-exposed-ssh"
    Intent   = "intentionally-vulnerable"
  }
}

# Public IP so the attack can prove real internet reachability to port 22 with a TCP
# connect, the way scenario 01 proved anonymous reads - exposure shown, not asserted.
resource "aws_instance" "target" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.ssh.id]
  associate_public_ip_address = true

  tags = {
    Name     = "${var.project_name}-lab-ssh-host"
    Project  = var.project_name
    Scenario = "03-exposed-ssh"
    Intent   = "intentionally-vulnerable"
  }
}
