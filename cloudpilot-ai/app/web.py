
import os
import time
import uuid
import json
import datetime
from pathlib import Path
from typing import Any, Optional

import boto3

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field

from app import aws_tools


# ============================================================
# CONFIGURATION & PRODUCTION SECURITY
# ============================================================

REGION = os.getenv("AWS_REGION", "ap-south-1")

MODEL = os.getenv(
    "BEDROCK_MODEL_ID",
    "global.amazon.nova-2-lite-v1:0"
)

API_KEY = os.getenv("CLOUDPILOT_API_KEY", "")

ROOT = Path(__file__).resolve().parent.parent
AUDIT_LOG_PATH = ROOT / "audit.log"

PENDING = {}
TTL = 300

app = FastAPI(title="CloudPilot AI - Hardened AWS Assistant")


def log_audit(event_type: str, details: dict, client_ip: str = "127.0.0.1"):
    """Durable append-only audit trail logger"""
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "client_ip": client_ip,
        "region": REGION,
        "details": details
    }
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception:
        pass


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.mount(
    "/static",
    StaticFiles(directory=ROOT / "static"),
    name="static"
)


def authenticate_request(request: Request):
    """Enforces API Key check if CLOUDPILOT_API_KEY is configured in the environment."""
    if not API_KEY:
        return True
    key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Valid X-API-Key or Bearer token required"
        )
    return True


# ============================================================
# REQUEST MODELS
# ============================================================

class LoginIn(BaseModel):
    username: str
    password: str


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    history: list[dict[str, str]] = Field(default_factory=list)


class ApprovalIn(BaseModel):
    approval_id: str


# ============================================================
# BEDROCK TOOL DEFINITIONS
# ============================================================

def spec(name, desc, props, required=None):

    if required is None:
        required = []

    return {
        "toolSpec": {
            "name": name,
            "description": desc,
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": props,
                    "required": required
                }
            }
        }
    }


strp = {"type": "string"}
boolp = {"type": "boolean"}
intp = {"type": "integer"}


TOOLS = [

    spec(
        "list_ec2",
        "List EC2 instances.",
        {"region": strp}
    ),

    spec(
        "list_vpcs",
        "List VPCs.",
        {"region": strp}
    ),

    spec(
        "list_subnets",
        "List subnets.",
        {"region": strp}
    ),

    spec(
        "list_sgs",
        "List security groups.",
        {"region": strp}
    ),

    spec(
        "audit_sg",
        "Audit a security group.",
        {"group_id": strp, "region": strp},
        ["group_id"]
    ),

    spec(
        "list_s3",
        "List S3 buckets.",
        {"region": strp}
    ),

    spec(
        "list_s3_objects",
        "List objects within a specific S3 bucket.",
        {"bucket_name": strp, "prefix": strp, "region": strp},
        ["bucket_name"]
    ),

    spec(
        "get_s3_object_url",
        "Generate a secure presigned download URL for an S3 object.",
        {"bucket_name": strp, "key": strp, "region": strp},
        ["bucket_name", "key"]
    ),

    spec(
        "prepare_upload_s3_object",
        "Prepare uploading content or a file to an S3 bucket. Preview only. Requires confirmation.",
        {
            "bucket_name": strp,
            "key": strp,
            "content": strp,
            "region": strp
        },
        ["bucket_name", "key", "content"]
    ),

    spec(
        "prepare_delete_s3_object",
        "Prepare deleting an object from an S3 bucket. Preview only. Requires confirmation.",
        {
            "bucket_name": strp,
            "key": strp,
            "region": strp
        },
        ["bucket_name", "key"]
    ),

    spec(
        "list_rds",
        "List RDS DB instances.",
        {"region": strp}
    ),

    spec(
        "list_lambda",
        "List Lambda functions.",
        {"region": strp}
    ),

    spec(
        "list_alarms",
        "List CloudWatch alarms.",
        {"region": strp}
    ),

    spec(
        "list_iam_roles",
        "List IAM role names and ARNs. Never show secrets.",
        {"region": strp}
    ),

    spec(
        "prepare_create_iam_role",
        "Prepare creating an IAM service role (e.g. for Lambda or EC2). Preview only. Requires confirmation.",
        {
            "role_name": strp,
            "service_principal": strp,
            "description": strp,
            "attach_policy_arn": strp,
            "region": strp
        },
        ["role_name"]
    ),

    spec(
        "prepare_delete_iam_role",
        "Prepare deleting an IAM role. Preview only. Requires confirmation.",
        {
            "role_name": strp,
            "region": strp
        },
        ["role_name"]
    ),

    spec(
        "prepare_create_sg",
        "Prepare security group creation preview only.",
        {
            "name": strp,
            "description": strp,
            "vpc_id": strp,
            "region": strp
        },
        ["name", "vpc_id"]
    ),

    spec(
        "prepare_create_s3",
        "Prepare private S3 bucket creation preview only.",
        {"bucket_name": strp, "region": strp},
        ["bucket_name"]
    ),

    spec(
        "prepare_create_vpc",
        "Prepare VPC creation preview only.",
        {"cidr": strp, "name": strp, "region": strp},
        ["cidr", "name"]
    ),

    spec(
        "prepare_create_subnet",
        "Prepare subnet creation preview only.",
        {
            "vpc_id": strp,
            "cidr": strp,
            "az": strp,
            "name": strp,
            "region": strp
        },
        ["vpc_id", "cidr", "az", "name"]
    ),

    spec(
        "prepare_launch_ec2",
        "Prepare one EC2 launch preview only. Never execute directly.",
        {
            "name": strp,
            "ami_id": strp,
            "instance_type": strp,
            "subnet_id": strp,
            "sg_id": strp,
            "key_name": strp,
            "associate_public_ip": boolp,
            "region": strp
        },
        [
            "ami_id",
            "instance_type",
            "subnet_id",
            "sg_id",
            "key_name"
        ]
    ),

    spec(
        "prepare_start_ec2",
        "Prepare starting a stopped EC2 instance. Preview only. Requires confirmation.",
        {
            "instance_id": strp,
            "region": strp
        },
        ["instance_id"]
    ),

    spec(
        "prepare_stop_ec2",
        "Prepare stopping a running EC2 instance. Preview only. Requires confirmation.",
        {
            "instance_id": strp,
            "region": strp
        },
        ["instance_id"]
    ),

    spec(
        "prepare_reboot_ec2",
        "Prepare rebooting an EC2 instance. Preview only. Requires confirmation.",
        {
            "instance_id": strp,
            "region": strp
        },
        ["instance_id"]
    ),

    spec(
        "prepare_terminate_ec2",
        "Prepare terminating (permanently deleting) an EC2 instance. Preview only. Requires confirmation.",
        {
            "instance_id": strp,
            "region": strp
        },
        ["instance_id"]
    ),

    spec(
        "prepare_add_sg_rule",
        "Prepare adding an inbound (ingress) rule to a Security Group. Preview only. Requires confirmation.",
        {
            "group_id": strp,
            "protocol": strp,
            "from_port": intp,
            "to_port": intp,
            "cidr_ip": strp,
            "description": strp,
            "region": strp
        },
        ["group_id", "protocol", "from_port", "to_port"]
    ),

    spec(
        "prepare_remove_sg_rule",
        "Prepare removing an inbound (ingress) rule from a Security Group. Preview only. Requires confirmation.",
        {
            "group_id": strp,
            "protocol": strp,
            "from_port": intp,
            "to_port": intp,
            "cidr_ip": strp,
            "region": strp
        },
        ["group_id", "protocol", "from_port", "to_port"]
    ),

    spec(
        "prepare_create_rds",
        "Prepare creating a managed RDS database instance (e.g. Postgres/MySQL). Preview only. Requires confirmation.",
        {
            "db_identifier": strp,
            "engine": strp,
            "db_class": strp,
            "allocated_storage": intp,
            "master_username": strp,
            "region": strp
        },
        ["db_identifier"]
    ),

    spec(
        "prepare_delete_rds",
        "Prepare deleting an RDS database instance. Preview only. Requires confirmation.",
        {
            "db_identifier": strp,
            "skip_final_snapshot": boolp,
            "region": strp
        },
        ["db_identifier"]
    ),

    spec(
        "prepare_create_lambda",
        "Prepare creating a serverless AWS Lambda function. Preview only. Requires confirmation.",
        {
            "function_name": strp,
            "role_arn": strp,
            "handler": strp,
            "runtime": strp,
            "inline_code": strp,
            "s3_bucket": strp,
            "s3_key": strp,
            "region": strp
        },
        ["function_name", "role_arn"]
    ),

    spec(
        "prepare_delete_lambda",
        "Prepare deleting an AWS Lambda function. Preview only. Requires confirmation.",
        {
            "function_name": strp,
            "region": strp
        },
        ["function_name"]
    ),

    spec(
        "estimate_resource_cost",
        "Calculate estimated monthly cost in USD for AWS resources (EC2, RDS, EBS, S3, Lambda) in Mumbai region.",
        {
            "resource_type": strp,
            "instance_type": strp,
            "storage_gb": intp,
            "count": intp,
            "region": strp
        },
        ["resource_type"]
    ),

    spec(
        "check_budget_status",
        "Check account AWS Budgets and cost protection threshold guardrails.",
        {"region": strp}
    ),

    spec(
        "troubleshoot_instance",
        "Analyze and troubleshoot an EC2 instance state, hardware status checks, and security group reachability.",
        {
            "instance_id": strp,
            "region": strp
        },
        ["instance_id"]
    ),

    spec(
        "generate_architecture_plan",
        "Generate a structured, multi-tier AWS infrastructure architecture plan and deployment blueprint.",
        {
            "workload_type": strp,
            "tier": strp,
            "high_availability": boolp,
            "region": strp
        }
    )
]


# ============================================================
# JSON NORMALIZATION
# ============================================================

def normalize_result(result: Any) -> dict:

    """
    Bedrock toolResult JSON must contain a JSON object.
    Convert list results into an object and normalize
    datetime and other non-JSON values.
    """

    if isinstance(result, dict):
        data = result

    elif isinstance(result, list):
        data = {
            "items": result,
            "count": len(result)
        }

    else:
        data = {
            "result": result
        }

    return json.loads(
        json.dumps(data, default=str, allow_nan=False)
    )


# ============================================================
# TOOL DISPATCH
# ============================================================

def dispatch(name, args):

    region = args.get("region", REGION)

    if region != "ap-south-1":
        raise ValueError(
            "This MVP is restricted to ap-south-1."
        )

    reads = {
        "list_ec2": aws_tools.list_ec2,
        "list_vpcs": aws_tools.list_vpcs,
        "list_subnets": aws_tools.list_subnets,
        "list_sgs": aws_tools.list_sgs,
        "list_s3": aws_tools.list_s3,
        "list_rds": aws_tools.list_rds,
        "list_lambda": aws_tools.list_lambda,
        "list_alarms": aws_tools.list_alarms,
        "list_iam_roles": aws_tools.list_iam_roles
    }

    if name in reads:
        return reads[name](region)

    if name == "audit_sg":
        return aws_tools.audit_sg(
            args["group_id"],
            region
        )

    if name == "list_s3_objects":
        return aws_tools.list_s3_objects(
            bucket_name=args["bucket_name"],
            prefix=args.get("prefix", ""),
            region=region
        )

    if name == "get_s3_object_url":
        return aws_tools.get_s3_object_url(
            bucket_name=args["bucket_name"],
            key=args["key"],
            region=region
        )

    if name == "estimate_resource_cost":
        return aws_tools.estimate_resource_cost(
            resource_type=args["resource_type"],
            instance_type=args.get("instance_type", "t3.micro"),
            storage_gb=args.get("storage_gb", 20),
            count=args.get("count", 1),
            region=region
        )

    if name == "check_budget_status":
        return aws_tools.check_budget_status(region=region)

    if name == "troubleshoot_instance":
        return aws_tools.troubleshoot_instance(
            instance_id=args["instance_id"],
            region=region
        )

    if name == "generate_architecture_plan":
        return aws_tools.generate_architecture_plan(
            workload_type=args.get("workload_type", "web_application"),
            tier=args.get("tier", "standard"),
            high_availability=args.get("high_availability", False),
            region=region
        )

    mapping = {

        "prepare_create_sg": lambda: (
            "create_sg",
            {
                "name": args["name"],
                "description": args.get(
                    "description",
                    "CloudPilot managed"
                ),
                "vpc_id": args["vpc_id"],
                "region": region
            }
        ),

        "prepare_create_s3": lambda: (
            "create_s3",
            {
                "bucket_name": args["bucket_name"],
                "region": region
            }
        ),

        "prepare_upload_s3_object": lambda: (
            "upload_s3_object",
            {
                "bucket_name": args["bucket_name"],
                "key": args["key"],
                "content": args["content"],
                "region": region
            }
        ),

        "prepare_delete_s3_object": lambda: (
            "delete_s3_object",
            {
                "bucket_name": args["bucket_name"],
                "key": args["key"],
                "region": region
            }
        ),

        "prepare_create_vpc": lambda: (
            "create_vpc",
            {
                "cidr": args["cidr"],
                "name": args["name"],
                "region": region
            }
        ),

        "prepare_create_subnet": lambda: (
            "create_subnet",
            {
                "vpc_id": args["vpc_id"],
                "cidr": args["cidr"],
                "az": args["az"],
                "name": args["name"],
                "region": region
            }
        ),

        "prepare_launch_ec2": lambda: (
            "launch_ec2",
            {
                "name": args.get(
                    "name",
                    "CloudPilot-Instance"
                ),
                "ami_id": args["ami_id"],
                "instance_type": args["instance_type"],
                "subnet_id": args["subnet_id"],
                "sg_id": args["sg_id"],
                "key_name": args["key_name"],
                "associate_public_ip": args.get("associate_public_ip", True),
                "region": region
            }
        ),

        "prepare_start_ec2": lambda: (
            "start_ec2",
            {
                "instance_id": args["instance_id"],
                "region": region
            }
        ),

        "prepare_stop_ec2": lambda: (
            "stop_ec2",
            {
                "instance_id": args["instance_id"],
                "region": region
            }
        ),

        "prepare_reboot_ec2": lambda: (
            "reboot_ec2",
            {
                "instance_id": args["instance_id"],
                "region": region
            }
        ),

        "prepare_terminate_ec2": lambda: (
            "terminate_ec2",
            {
                "instance_id": args["instance_id"],
                "region": region
            }
        ),

        "prepare_add_sg_rule": lambda: (
            "add_sg_rule",
            {
                "group_id": args["group_id"],
                "protocol": args["protocol"],
                "from_port": args["from_port"],
                "to_port": args["to_port"],
                "cidr_ip": args.get("cidr_ip", "0.0.0.0/0"),
                "description": args.get("description", "Added by CloudPilot"),
                "region": region
            }
        ),

        "prepare_remove_sg_rule": lambda: (
            "remove_sg_rule",
            {
                "group_id": args["group_id"],
                "protocol": args["protocol"],
                "from_port": args["from_port"],
                "to_port": args["to_port"],
                "cidr_ip": args.get("cidr_ip", "0.0.0.0/0"),
                "region": region
            }
        ),

        "prepare_create_rds": lambda: (
            "create_rds",
            {
                "db_identifier": args["db_identifier"],
                "engine": args.get("engine", "postgres"),
                "db_class": args.get("db_class", "db.t3.micro"),
                "allocated_storage": args.get("allocated_storage", 20),
                "master_username": args.get("master_username", "cloudpilotadmin"),
                "region": region
            }
        ),

        "prepare_delete_rds": lambda: (
            "delete_rds",
            {
                "db_identifier": args["db_identifier"],
                "skip_final_snapshot": args.get("skip_final_snapshot", True),
                "region": region
            }
        ),

        "prepare_create_lambda": lambda: (
            "create_lambda",
            {
                "function_name": args["function_name"],
                "role_arn": args["role_arn"],
                "handler": args.get("handler", "index.handler"),
                "runtime": args.get("runtime", "python3.11"),
                "inline_code": args.get("inline_code"),
                "s3_bucket": args.get("s3_bucket"),
                "s3_key": args.get("s3_key"),
                "region": region
            }
        ),

        "prepare_delete_lambda": lambda: (
            "delete_lambda",
            {
                "function_name": args["function_name"],
                "region": region
            }
        ),

        "prepare_create_iam_role": lambda: (
            "create_iam_role",
            {
                "role_name": args["role_name"],
                "service_principal": args.get("service_principal", "lambda.amazonaws.com"),
                "description": args.get("description", "CloudPilot managed IAM role"),
                "attach_policy_arn": args.get("attach_policy_arn"),
                "region": region
            }
        ),

        "prepare_delete_iam_role": lambda: (
            "delete_iam_role",
            {
                "role_name": args["role_name"],
                "region": region
            }
        )
    }

    if name not in mapping:
        raise ValueError("Tool is not allowlisted")

    action, action_args = mapping[name]()
    token = str(uuid.uuid4())

    PENDING[token] = {
        "action": action,
        "args": action_args,
        "expires": time.time() + TTL
    }

    warning_msg = "AWS charges/resources may be affected."
    if action == "terminate_ec2":
        warning_msg = "⚠️ CRITICAL: Terminating this EC2 instance will permanently delete it and its attached root volume!"
    elif action == "delete_rds":
        warning_msg = "⚠️ CRITICAL: Deleting this RDS instance will erase database data!"
    elif action == "delete_iam_role":
        warning_msg = "⚠️ Deleting this IAM role will detach policies and revoke access permissions for dependent resources!"
    elif action == "create_iam_role":
        warning_msg = "Creating an IAM role with attached policies granting AWS permissions."
    elif action == "delete_lambda":
        warning_msg = "⚠️ Deleting this Lambda function is permanent."
    elif action == "delete_s3_object":
        warning_msg = "⚠️ Deleting this object from S3 is irreversible."
    elif action == "upload_s3_object":
        warning_msg = "Uploading this object will store data in S3 (will overwrite if key exists)."
    elif action == "add_sg_rule":
        warning_msg = "Adding inbound rule modifies network access control. Ensure ports are restricted appropriately."
    elif action == "remove_sg_rule":
        warning_msg = "Removing inbound rule will block incoming traffic on this port range."
    elif action == "create_rds":
        warning_msg = "Creating an RDS instance will incur ongoing AWS relational database hourly charges."
    elif action == "stop_ec2":
        warning_msg = "Stopping this EC2 instance will stop running services and erase in-memory data."
    elif action == "reboot_ec2":
        warning_msg = "Rebooting this EC2 instance will temporarily disconnect any active connections."
    elif action == "start_ec2":
        warning_msg = "Starting this EC2 instance will resume compute charges."
    elif action == "create_s3":
        warning_msg = "Creating a private S3 bucket in ap-south-1 with Public Access Block enabled."

    return {
        "requires_approval": True,
        "approval_id": token,
        "expires_seconds": TTL,
        "preview": {
            "action": action,
            "parameters": action_args,
            "warning": warning_msg
        }
    }


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM = """
You are CloudPilot AI for AWS Mumbai (ap-south-1).
You are an expert Cloud & DevOps Infrastructure Assistant.

CORE GUIDELINES:
1. Use only available tools for AWS facts. Never invent resource IDs or state.
2. For write/create/delete requests, always call the appropriate prepare_* tool first. This generates a safe preview card for the user. Never claim a resource is created before tool confirmation.
3. For multi-step infrastructure provisioning requests (e.g. 3-tier web app, full VPC + Subnets + EC2 + RDS setup):
   - Use `generate_architecture_plan` to formulate the complete blueprint.
   - Present the multi-step deployment roadmap clearly.
   - For each step, create approval previews sequentially or guide the user step-by-step.
4. For cost and budget inquiries:
   - Use `estimate_resource_cost` to provide transparent monthly price breakdowns.
   - Use `check_budget_status` to report budget limits and safety thresholds.
5. For issue diagnosis and debugging:
   - Use `troubleshoot_instance` and `audit_sg` to identify hardware impairments, status check failures, or open security gaps.
6. Public IP is enabled for EC2 by default when requested.
7. Always advise the user on cost efficiency and best security practices.
8. Be clear, professional, and beginner friendly.
"""


# ============================================================
# BEDROCK CONVERSE
# ============================================================

def converse(message, history):

    msgs = []

    for item in history[-10:]:

        if (
            item.get("role") in ("user", "assistant")
            and isinstance(item.get("content"), str)
        ):

            msgs.append({
                "role": item["role"],
                "content": [
                    {"text": item["content"][:3000]}
                ]
            })

    msgs.append({
        "role": "user",
        "content": [{"text": message}]
    })

    client = boto3.client(
        "bedrock-runtime",
        region_name=REGION
    )

    activity = []

    for _ in range(10):

        response = client.converse(
            modelId=MODEL,
            system=[{"text": SYSTEM}],
            messages=msgs,
            toolConfig={
                "tools": TOOLS,
                "toolChoice": {"auto": {}}
            },
            inferenceConfig={
                "maxTokens": 1500,
                "temperature": 0.2
            }
        )

        assistant_message = response["output"]["message"]

        msgs.append(assistant_message)

        if response.get("stopReason") != "tool_use":

            answer = "\n".join(
                block.get("text", "")
                for block in assistant_message.get("content", [])
                if "text" in block
            )

            return {
                "answer": answer,
                "activity": activity
            }

        results = []

        for block in assistant_message.get("content", []):

            if "toolUse" not in block:
                continue

            tool = block["toolUse"]

            try:

                raw_result = dispatch(
                    tool["name"],
                    tool.get("input", {})
                )

                result = normalize_result(raw_result)

                status = "success"

            except Exception as error:

                result = {
                    "error": str(error),
                    "error_type": type(error).__name__
                }

                status = "error"

            activity.append({
                "tool": tool["name"],
                "result": result
            })

            results.append({
                "toolResult": {
                    "toolUseId": tool["toolUseId"],
                    "content": [
                        {"json": result}
                    ],
                    "status": status
                }
            })

        if not results:
            raise RuntimeError(
                "Bedrock requested tool use but no tool result was produced."
            )

        msgs.append({
            "role": "user",
            "content": results
        })

    return {
        "answer": "Tool call limit reached; narrow the request.",
        "activity": activity
    }


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def home():

    return FileResponse(
        ROOT / "static" / "index.html"
    )


@app.get("/health")
def health():

    return {
        "status": "healthy",
        "region": REGION,
        "api_auth_enabled": bool(API_KEY),
        "audit_logging": True
    }


@app.post("/api/login")
def login(req: LoginIn, request: Request):
    ADMIN_USER = os.getenv("CLOUDPILOT_USER", "admin")
    ADMIN_PASS = os.getenv("CLOUDPILOT_PASS", "cloudpilot123")
    client_ip = request.client.host if request.client else "127.0.0.1"

    if req.username == ADMIN_USER and req.password == ADMIN_PASS:
        token = str(uuid.uuid4())
        log_audit("user_login_success", {"username": req.username}, client_ip=client_ip)
        return {
            "status": "success",
            "token": token,
            "user": {
                "username": req.username,
                "role": "Cloud Architect / Administrator",
                "region": REGION
            }
        }

    log_audit("user_login_failed", {"username": req.username}, client_ip=client_ip)
    raise HTTPException(
        status_code=401,
        detail="Invalid credentials. Default is admin / cloudpilot123"
    )


@app.post("/api/chat")
def chat(req: ChatIn, request: Request):

    authenticate_request(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:

        res = converse(
            req.message,
            req.history
        )

        log_audit(
            event_type="chat_interaction",
            details={
                "prompt": req.message,
                "tools_executed": [a["tool"] for a in res.get("activity", [])]
            },
            client_ip=client_ip
        )

        return res

    except Exception as error:

        log_audit(
            event_type="chat_error",
            details={"prompt": req.message, "error": str(error)},
            client_ip=client_ip
        )

        raise HTTPException(
            status_code=500,
            detail=f"{type(error).__name__}: {error}"
        )


# ============================================================
# APPROVAL ROUTE
# ============================================================

@app.post("/api/approve")
def approve(req: ApprovalIn, request: Request):

    authenticate_request(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    item = PENDING.pop(req.approval_id, None)

    if not item:
        raise HTTPException(
            404,
            "Approval missing or already used"
        )

    if time.time() > item["expires"]:
        raise HTTPException(
            410,
            "Approval expired; request a new preview"
        )

    actions = {
        "create_sg": aws_tools.create_sg,
        "add_sg_rule": aws_tools.add_sg_rule,
        "remove_sg_rule": aws_tools.remove_sg_rule,
        "create_s3": aws_tools.create_s3,
        "upload_s3_object": aws_tools.upload_s3_object,
        "delete_s3_object": aws_tools.delete_s3_object,
        "create_vpc": aws_tools.create_vpc,
        "create_subnet": aws_tools.create_subnet,
        "launch_ec2": aws_tools.launch_ec2,
        "start_ec2": aws_tools.start_ec2,
        "stop_ec2": aws_tools.stop_ec2,
        "reboot_ec2": aws_tools.reboot_ec2,
        "terminate_ec2": aws_tools.terminate_ec2,
        "create_rds": aws_tools.create_rds,
        "delete_rds": aws_tools.delete_rds,
        "create_lambda": aws_tools.create_lambda,
        "delete_lambda": aws_tools.delete_lambda,
        "create_iam_role": aws_tools.create_iam_role,
        "delete_iam_role": aws_tools.delete_iam_role
    }

    try:

        result = actions[item["action"]](
            **item["args"]
        )

        log_audit(
            event_type="action_executed",
            details={
                "action": item["action"],
                "args": {k: v for k, v in item["args"].items() if "password" not in k.lower()},
                "status": "success"
            },
            client_ip=client_ip
        )

        return {
            "status": "success",
            "result": result
        }

    except Exception as error:

        log_audit(
            event_type="action_failed",
            details={
                "action": item["action"],
                "error": str(error)
            },
            client_ip=client_ip
        )

        raise HTTPException(
            500,
            detail=f"AWS action failed: {type(error).__name__}: {error}"
        )

