# Backend module — FastAPI on ECS Fargate behind an ALB. Stateless and
# autoscaled; all state lives in Aurora / Redis / EFS. Heavy Ghidra work is
# dispatched to Batch (COMPUTE_BACKEND=aws_batch), so this task stays small.

resource "aws_ecr_repository" "backend" {
  name                 = "${var.name}-backend"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "backend" {
  name              = "/wairz/${var.name}/backend"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name}-backend"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# --- Security groups --------------------------------------------------------
resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Public HTTP(S) to the ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "ingress" {
    for_each = var.certificate_arn == "" ? [] : [1]
    content {
      description = "HTTPS"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-alb" }
}

resource "aws_security_group" "service" {
  name_prefix = "${var.name}-svc-"
  description = "ALB to backend task on the app port"
  vpc_id      = var.vpc_id

  ingress {
    description     = "From ALB"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-svc" }
}

# --- ALB --------------------------------------------------------------------
resource "aws_lb" "this" {
  name               = "${var.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
  idle_timeout       = 4000 # long-lived websockets (xterm, live polling)
}

resource "aws_lb_target_group" "this" {
  name        = "${var.name}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = var.health_check_path
    matcher             = "200-399"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# Optional HTTPS listener (when an ACM cert is supplied). For ALB-level Cognito
# auth, add an authenticate-cognito action here — requires this HTTPS listener.
resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# --- Task definition + service ----------------------------------------------
locals {
  efs_volumes = {
    firmware        = { ap = var.efs_firmware_access_point_id, path = "/data/firmware" }
    ghidra-projects = { ap = var.efs_ghidra_projects_access_point_id, path = "/data/ghidra_projects" }
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name}-backend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  dynamic "volume" {
    for_each = local.efs_volumes
    content {
      name = volume.key
      efs_volume_configuration {
        file_system_id     = var.efs_id
        transit_encryption = "ENABLED"
        authorization_config {
          access_point_id = volume.value.ap
          iam             = "DISABLED"
        }
      }
    }
  }

  container_definitions = jsonencode([{
    name         = "backend"
    image        = "${aws_ecr_repository.backend.repository_url}:${var.image_tag}"
    essential    = true
    portMappings = [{ containerPort = var.container_port, protocol = "tcp" }]

    environment = [
      { name = "COMPUTE_BACKEND", value = "aws_batch" },
      { name = "AWS_REGION", value = var.aws_region },
      { name = "STORAGE_ROOT", value = "/data/firmware" },
      { name = "GHIDRA_PROJECT_ROOT", value = "/data/ghidra_projects" },
      { name = "REDIS_URL", value = var.redis_url },
      { name = "BATCH_JOB_QUEUE", value = var.batch_job_queue },
      { name = "BATCH_JOB_DEFINITION", value = var.batch_job_definition_name },
      { name = "MAX_UPLOAD_SIZE_MB", value = tostring(var.max_upload_size_mb) },
    ]
    secrets = [
      { name = "DATABASE_URL", valueFrom = var.database_url_secret_arn },
    ]
    mountPoints = [
      for k, v in local.efs_volumes : { sourceVolume = k, containerPath = v.path, readOnly = false }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.backend.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "backend"
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  name            = "${var.name}-backend"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "backend"
    container_port   = var.container_port
  }

  # Migrations run on container start (alembic upgrade head in the image CMD).
  depends_on = [aws_lb_listener.http]
}

# --- Autoscaling on CPU -----------------------------------------------------
resource "aws_appautoscaling_target" "this" {
  max_capacity       = var.max_count
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension
  service_namespace  = aws_appautoscaling_target.this.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = var.cpu_target_percent
  }
}

# Allow the backend task to mount EFS (NFS) — the EFS SG allows the VPC CIDR,
# which already covers the private subnets, so no extra rule is needed here.
