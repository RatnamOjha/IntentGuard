# Reproducible deployment

## Local production-like stack

The root `docker-compose.yml` starts PostgreSQL, Redis, OPA, Keycloak, the
database migration and deterministic seed jobs, the FastAPI gateway, protected
mock booking connector, Tempo, Prometheus, Grafana, and the operator frontend.
Long-running services have health checks and start only after required
dependencies are healthy or one-shot jobs have completed successfully.

Copy `.env.compose.example` to `.env.compose`, replace every local password,
and pass it to Compose:

```powershell
docker compose --env-file .env.compose up --build -d --wait
docker compose --env-file .env.compose down
```

With the checked-in local defaults, the shorter lifecycle commands are:

```powershell
./scripts/stack.ps1 up
./scripts/stack.ps1 status
./scripts/stack.ps1 down
```

Use `./scripts/stack.ps1 reset` only when you intentionally want to delete the
local PostgreSQL, Redis, Prometheus, Tempo, and Grafana volumes.

| Service | Local URL |
| --- | --- |
| Operator console | `http://localhost:3000` |
| Governance API | `http://localhost:8000/docs` |
| Protected connector | `http://localhost:8100/health` |
| Keycloak | `http://localhost:8080` |
| OPA | `http://localhost:8181/health` |
| Prometheus | `http://localhost:9090` |
| Grafana | `http://localhost:3002` |

The imported `intentguard` realm has local-only users `admin`, `reviewer`,
`demo-agent`, and `demo-customer`. Their passwords are deliberately obvious in
the realm JSON and must never be reused outside an isolated workstation. The
connector uses an OAuth service account and refreshes its client-credentials
token automatically.

Obtain an admin access token for API calls with:

```powershell
$token = Invoke-RestMethod -Method Post `
  -Uri http://localhost:8080/realms/intentguard/protocol/openid-connect/token `
  -Body @{grant_type='password';client_id='intentguard-api';username='admin';password='admin-local-only'}
$token.access_token
```

## Migrations and seed data

`migrate` records each successfully applied SQL file in `schema_migrations`.
It can be rerun safely and never marks a failed migration as complete. `seed`
runs only after migrations and OPA are healthy and uses the idempotent demo
bootstrap to create dashboard data.

## AWS ECS/Fargate target

`deploy/aws/ecs-fargate.yml` deploys the smaller public version: an
internet-facing application load balancer, a private Fargate gateway service,
CloudWatch logging, autoscaling-ready networking, and secrets injected from
AWS Secrets Manager. RDS PostgreSQL and ElastiCache Redis endpoints are passed
as Secrets Manager values so databases are not embedded in the task or exposed
publicly.

Build and push the root Dockerfile to ECR, then deploy the template:

```text
aws cloudformation deploy --template-file deploy/aws/ecs-fargate.yml \
  --stack-name intentguard --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ImageUri=<account>.dkr.ecr.<region>.amazonaws.com/intentguard:<sha> \
  DatabaseUrlSecretArn=<secret-arn> RedisUrlSecretArn=<secret-arn> \
  JwksUrl=<issuer-jwks-url> JwtIssuer=<issuer> PublicSubnetIds=<subnet-a,subnet-b> \
  PrivateSubnetIds=<subnet-c,subnet-d> VpcId=<vpc-id>
```

The template intentionally does not create identity, database, or cache
credentials. Use an existing production identity provider, encrypted RDS, and
encrypted ElastiCache, and restrict their security groups to the Fargate task
security group. The deployment cannot be executed from this repository alone:
an AWS account, ECR image, network IDs, secrets, and deployment authority are
required.
