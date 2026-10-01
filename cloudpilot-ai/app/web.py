
import os
import time
import uuid
import json

from pathlib import Path
from typing import Any

import boto3

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import aws_tools


# ============================================================
# CONFIGURATION
# ============================================================

REGION = os.getenv("AWS_REGION", "ap-south-1")

MODEL = os.getenv(
    "BEDROCK_MODEL_ID",
    "global.amazon.nova-2-lite-v1:0"
)

ROOT = Path(__file__).resolve().parent.parent

PENDING = {}
TTL = 300

app = FastAPI(title="CloudPilot AI")

app.mount(
    "/static",
    StaticFiles(directory=ROOT / "static"),
    name="static"
)


# ============================================================
# REQUEST MODELS
# ============================================================

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
            "region": strp
        },
        [
            "ami_id",
            "instance_type",
            "subnet_id",
            "sg_id",
            "key_name"
        ]
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

    return {
        "requires_approval": True,
        "approval_id": token,
        "expires_seconds": TTL,
        "preview": {
            "action": action,
            "parameters": action_args,
            "warning": "AWS charges/resources may be created."
        }
    }


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM = """
You are CloudPilot AI for AWS Mumbai ap-south-1.

Use only available tools for AWS facts.

Never invent IDs or claim success without tool results.

For write requests, collect exact values and call prepare_* only.
This creates a preview, not the resource.

User must click Confirm in UI.

Do not guess AMI, VPC, subnet, security group or key IDs.
List inventory or ask the user.

Do not request passwords in chat.

Do not open public ingress or create public exposure.

Warn that AWS charges may apply.

Be beginner friendly.
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
                "maxTokens": 1200,
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
        "region": REGION
    }


@app.post("/api/chat")
def chat(req: ChatIn):

    try:

        return converse(
            req.message,
            req.history
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"{type(error).__name__}: {error}"
        )


# ============================================================
# APPROVAL ROUTE
# ============================================================

@app.post("/api/approve")
def approve(req: ApprovalIn):

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
        "create_s3": aws_tools.create_s3,
        "create_vpc": aws_tools.create_vpc,
        "create_subnet": aws_tools.create_subnet,
        "launch_ec2": aws_tools.launch_ec2
    }

    try:

        result = actions[item["action"]](
            **item["args"]
        )

        return {
            "status": "success",
            "result": result
        }

    except Exception as error:

        raise HTTPException(
            500,
            detail=f"AWS action failed: {type(error).__name__}: {error}"
        )

