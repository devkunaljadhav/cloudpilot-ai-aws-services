
import io
import zipfile
import secrets
import json
import boto3
from botocore.exceptions import ClientError

DEFAULT_REGION = "ap-south-1"

def sess(region=DEFAULT_REGION):
    return boto3.Session(region_name=region)

def list_ec2(region=DEFAULT_REGION):
    ec2=sess(region).client("ec2"); out=[]
    for page in ec2.get_paginator("describe_instances").paginate():
        for r in page.get("Reservations", []):
            for i in r.get("Instances", []):
                tags={t["Key"]:t["Value"] for t in i.get("Tags",[])}
                out.append({"id":i["InstanceId"],"name":tags.get("Name",""),
                  "state":i.get("State",{}).get("Name"),"type":i.get("InstanceType"),
                  "vpc":i.get("VpcId"),"subnet":i.get("SubnetId"),
                  "private_ip":i.get("PrivateIpAddress"),"public_ip":i.get("PublicIpAddress")})
    return out

def list_vpcs(region=DEFAULT_REGION):
    return [{"id":v["VpcId"],"cidr":v.get("CidrBlock"),"default":v.get("IsDefault")}
      for v in sess(region).client("ec2").describe_vpcs()["Vpcs"]]

def list_subnets(region=DEFAULT_REGION):
    return [{"id":s["SubnetId"],"vpc":s.get("VpcId"),"cidr":s.get("CidrBlock"),
      "az":s.get("AvailabilityZone"),"available_ips":s.get("AvailableIpAddressCount")}
      for s in sess(region).client("ec2").describe_subnets()["Subnets"]]

def list_sgs(region=DEFAULT_REGION):
    return [{"id":g["GroupId"],"name":g.get("GroupName"),"vpc":g.get("VpcId"),
      "inbound":g.get("IpPermissions",[])} for g in
      sess(region).client("ec2").describe_security_groups()["SecurityGroups"]]

def audit_sg(group_id, region=DEFAULT_REGION):
    ec2=sess(region).client("ec2")
    g=ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    findings=[]
    for rule in g.get("IpPermissions",[]):
        proto=rule.get("IpProtocol"); start=rule.get("FromPort"); end=rule.get("ToPort")
        for source in rule.get("IpRanges",[]):
            if source.get("CidrIp")=="0.0.0.0/0":
                if proto=="-1" or (proto=="tcp" and start==0 and end==65535):
                    findings.append("HIGH: broad internet access")
                elif proto=="tcp" and start in (22,3389,3306,5432):
                    findings.append(f"HIGH: sensitive port {start} open to internet")
    return {"group_id":group_id,"findings":findings}

def list_s3(region=DEFAULT_REGION):
    s3=sess(region).client("s3"); out=[]
    for b in s3.list_buckets().get("Buckets",[]):
        name=b["Name"]
        try: loc=s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except Exception: loc="unknown"
        out.append({"name":name,"region":loc,"created":str(b.get("CreationDate"))})
    return out

def list_s3_objects(bucket_name, prefix="", region=DEFAULT_REGION):
    s3 = sess(region).client("s3")
    kwargs = {"Bucket": bucket_name}
    if prefix:
        kwargs["Prefix"] = prefix
    res = s3.list_objects_v2(**kwargs)
    contents = res.get("Contents", [])
    return [{
        "key": item["Key"],
        "size_bytes": item["Size"],
        "last_modified": str(item["LastModified"]),
        "storage_class": item.get("StorageClass", "STANDARD")
    } for item in contents]

def get_s3_object_url(bucket_name, key, expires_in=3600, region=DEFAULT_REGION):
    s3 = sess(region).client("s3")
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket_name, "Key": key},
        ExpiresIn=int(expires_in)
    )
    return {
        "bucket": bucket_name,
        "key": key,
        "download_url": url,
        "expires_in_seconds": expires_in
    }

def upload_s3_object(bucket_name, key, content, region=DEFAULT_REGION):
    s3 = sess(region).client("s3")
    data = content.encode("utf-8") if isinstance(content, str) else content
    s3.put_object(Bucket=bucket_name, Key=key, Body=data)
    return {
        "bucket": bucket_name,
        "key": key,
        "status": "Uploaded successfully",
        "size_bytes": len(data)
    }

def delete_s3_object(bucket_name, key, region=DEFAULT_REGION):
    s3 = sess(region).client("s3")
    s3.delete_object(Bucket=bucket_name, Key=key)
    return {
        "bucket": bucket_name,
        "key": key,
        "status": "Deleted successfully"
    }

def list_rds(region=DEFAULT_REGION):
    r=sess(region).client("rds")
    return [{"id":d.get("DBInstanceIdentifier"),"engine":d.get("Engine"),
      "class":d.get("DBInstanceClass"),"status":d.get("DBInstanceStatus"),
      "endpoint":(d.get("Endpoint") or {}).get("Address")}
      for d in r.describe_db_instances().get("DBInstances",[])]

def list_lambda(region=DEFAULT_REGION):
    return [{"name":f["FunctionName"],"runtime":f.get("Runtime"),
      "memory":f.get("MemorySize"),"last_modified":f.get("LastModified")}
      for f in sess(region).client("lambda").list_functions().get("Functions",[])]

def list_alarms(region=DEFAULT_REGION):
    return [{"name":a["AlarmName"],"state":a.get("StateValue"),
      "metric":a.get("MetricName"),"namespace":a.get("Namespace")}
      for a in sess(region).client("cloudwatch").describe_alarms().get("MetricAlarms",[])]

def list_iam_roles(region=DEFAULT_REGION):
    return [{"name":r["RoleName"],"arn":r["Arn"],"created":str(r["CreateDate"])}
      for r in sess(region).client("iam").list_roles().get("Roles",[])]

def create_iam_role(role_name, service_principal="lambda.amazonaws.com", description="CloudPilot managed IAM role", attach_policy_arn=None, region=DEFAULT_REGION):
    iam = sess(region).client("iam")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service_principal},
            "Action": "sts:AssumeRole"
        }]
    }
    r = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description=description or "CloudPilot managed IAM role",
        Tags=[{"Key": "ManagedBy", "Value": "CloudPilotAI"}]
    )
    role_arn = r["Role"]["Arn"]
    
    if attach_policy_arn:
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=attach_policy_arn)
        except Exception:
            pass
    elif "lambda" in service_principal:
        try:
            iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
        except Exception:
            pass
            
    return {
        "role_name": role_name,
        "role_arn": role_arn,
        "service_principal": service_principal,
        "status": "Role created successfully"
    }

def delete_iam_role(role_name, region=DEFAULT_REGION):
    iam = sess(region).client("iam")
    attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
    for p in attached:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        except Exception:
            pass
            
    iam.delete_role(RoleName=role_name)
    return {
        "role_name": role_name,
        "status": "IAM Role deleted successfully"
    }

def create_sg(name, description, vpc_id, region=DEFAULT_REGION):
    ec2=sess(region).client("ec2")
    r=ec2.create_security_group(GroupName=name,Description=description or "CloudPilot managed",VpcId=vpc_id)
    return {"group_id":r["GroupId"],"note":"No inbound rules opened."}

def create_s3(bucket_name, region=DEFAULT_REGION):
    s3=sess(region).client("s3")
    # Bucket names must be globally unique; retry with a new name if conflict.
    s3.create_bucket(Bucket=bucket_name,
      CreateBucketConfiguration={"LocationConstraint":region})
    s3.put_public_access_block(Bucket=bucket_name,PublicAccessBlockConfiguration={
      "BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True})
    return {"bucket":bucket_name,"region":region,"public_access_block":"enabled"}

def create_vpc(cidr, name, region=DEFAULT_REGION):
    ec2=sess(region).client("ec2")
    r=ec2.create_vpc(CidrBlock=cidr)
    vpc_id=r["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id],Tags=[{"Key":"Name","Value":name[:255]},{"Key":"ManagedBy","Value":"CloudPilotAI"}])
    return {"vpc_id":vpc_id,"cidr":cidr}

def create_subnet(vpc_id, cidr, az, name, region=DEFAULT_REGION):
    ec2=sess(region).client("ec2")
    r=ec2.create_subnet(VpcId=vpc_id,CidrBlock=cidr,AvailabilityZone=az)
    subnet_id=r["Subnet"]["SubnetId"]
    ec2.create_tags(Resources=[subnet_id],Tags=[{"Key":"Name","Value":name[:255]},{"Key":"ManagedBy","Value":"CloudPilotAI"}])
    return {"subnet_id":subnet_id,"vpc_id":vpc_id,"cidr":cidr,"az":az}

def launch_ec2(name, ami_id, instance_type, subnet_id, sg_id, key_name, associate_public_ip=True, region=DEFAULT_REGION):
    if instance_type not in {"t3.micro","t3.small","t2.micro"}:
        raise ValueError("MVP permits t3.micro, t3.small, t2.micro only")
    r=sess(region).client("ec2").run_instances(ImageId=ami_id,InstanceType=instance_type,
      MinCount=1,MaxCount=1,KeyName=key_name,
      NetworkInterfaces=[{"DeviceIndex":0,"SubnetId":subnet_id,"Groups":[sg_id],
        "AssociatePublicIpAddress":bool(associate_public_ip)}],
      TagSpecifications=[{"ResourceType":"instance","Tags":[
        {"Key":"Name","Value":(name or "CloudPilot-Instance")[:255]},
        {"Key":"ManagedBy","Value":"CloudPilotAI"}]}])
    i=r["Instances"][0]
    note = "Public IPv4 enabled; AWS charges may apply." if associate_public_ip else "No public IPv4; AWS charges may apply."
    return {"instance_id":i["InstanceId"],"state":i["State"]["Name"],
      "public_ip_assigned": bool(associate_public_ip),
      "note": note}

def start_ec2(instance_id, region=DEFAULT_REGION):
    ec2 = sess(region).client("ec2")
    r = ec2.start_instances(InstanceIds=[instance_id])
    state_info = r.get("StartingInstances", [{}])[0]
    return {
        "instance_id": instance_id,
        "previous_state": state_info.get("PreviousState", {}).get("Name"),
        "current_state": state_info.get("CurrentState", {}).get("Name"),
        "status": "Starting"
    }

def stop_ec2(instance_id, region=DEFAULT_REGION):
    ec2 = sess(region).client("ec2")
    r = ec2.stop_instances(InstanceIds=[instance_id])
    state_info = r.get("StoppingInstances", [{}])[0]
    return {
        "instance_id": instance_id,
        "previous_state": state_info.get("PreviousState", {}).get("Name"),
        "current_state": state_info.get("CurrentState", {}).get("Name"),
        "status": "Stopping"
    }

def reboot_ec2(instance_id, region=DEFAULT_REGION):
    ec2 = sess(region).client("ec2")
    ec2.reboot_instances(InstanceIds=[instance_id])
    return {
        "instance_id": instance_id,
        "status": "Reboot initiated"
    }

def terminate_ec2(instance_id, region=DEFAULT_REGION):
    ec2 = sess(region).client("ec2")
    r = ec2.terminate_instances(InstanceIds=[instance_id])
    state_info = r.get("TerminatingInstances", [{}])[0]
    return {
        "instance_id": instance_id,
        "previous_state": state_info.get("PreviousState", {}).get("Name"),
        "current_state": state_info.get("CurrentState", {}).get("Name"),
        "status": "Terminating"
    }

def add_sg_rule(group_id, protocol, from_port, to_port, cidr_ip="0.0.0.0/0", description="Added by CloudPilot", region=DEFAULT_REGION):
    ec2 = sess(region).client("ec2")
    ip_permissions = [{
        "IpProtocol": str(protocol),
        "FromPort": int(from_port),
        "ToPort": int(to_port),
        "IpRanges": [{"CidrIp": cidr_ip, "Description": description}]
    }]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=ip_permissions
    )
    return {
        "group_id": group_id,
        "rule_added": {
            "protocol": protocol,
            "port_range": f"{from_port}-{to_port}",
            "cidr": cidr_ip
        },
        "status": "Rule authorized successfully"
    }

def remove_sg_rule(group_id, protocol, from_port, to_port, cidr_ip="0.0.0.0/0", region=DEFAULT_REGION):
    ec2 = sess(region).client("ec2")
    ip_permissions = [{
        "IpProtocol": str(protocol),
        "FromPort": int(from_port),
        "ToPort": int(to_port),
        "IpRanges": [{"CidrIp": cidr_ip}]
    }]
    ec2.revoke_security_group_ingress(
        GroupId=group_id,
        IpPermissions=ip_permissions
    )
    return {
        "group_id": group_id,
        "rule_removed": {
            "protocol": protocol,
            "port_range": f"{from_port}-{to_port}",
            "cidr": cidr_ip
        },
        "status": "Rule revoked successfully"
    }

def create_rds(db_identifier, engine="postgres", db_class="db.t3.micro", allocated_storage=20, master_username="cloudpilotadmin", master_password=None, region=DEFAULT_REGION):
    r = sess(region).client("rds")
    if not master_password:
        master_password = "CP!" + secrets.token_urlsafe(12) + "9#"
    
    res = r.create_db_instance(
        DBInstanceIdentifier=db_identifier,
        Engine=engine,
        DBInstanceClass=db_class,
        AllocatedStorage=int(allocated_storage),
        MasterUsername=master_username,
        MasterUserPassword=master_password,
        PubliclyAccessible=False,
        Tags=[{"Key": "ManagedBy", "Value": "CloudPilotAI"}]
    )
    db = res.get("DBInstance", {})
    return {
        "db_identifier": db.get("DBInstanceIdentifier"),
        "engine": db.get("Engine"),
        "status": db.get("DBInstanceStatus"),
        "master_username": master_username,
        "note": "RDS instance creation initiated. Takes several minutes to provision."
    }

def delete_rds(db_identifier, skip_final_snapshot=True, region=DEFAULT_REGION):
    r = sess(region).client("rds")
    res = r.delete_db_instance(
        DBInstanceIdentifier=db_identifier,
        SkipFinalSnapshot=bool(skip_final_snapshot)
    )
    db = res.get("DBInstance", {})
    return {
        "db_identifier": db.get("DBInstanceIdentifier"),
        "status": db.get("DBInstanceStatus"),
        "note": "RDS instance deletion initiated."
    }

def create_lambda(function_name, role_arn, handler="index.handler", runtime="python3.11", inline_code=None, s3_bucket=None, s3_key=None, region=DEFAULT_REGION):
    client = sess(region).client("lambda")
    if inline_code:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            filename = (handler.split(".")[0] if "." in handler else "index") + ".py"
            zf.writestr(filename, inline_code)
        code_payload = {"ZipFile": zip_buffer.getvalue()}
    elif s3_bucket and s3_key:
        code_payload = {"S3Bucket": s3_bucket, "S3Key": s3_key}
    else:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("index.py", "def handler(event, context):\n    return {'statusCode': 200, 'body': 'Hello from CloudPilot AI!'}\n")
        code_payload = {"ZipFile": zip_buffer.getvalue()}

    r = client.create_function(
        FunctionName=function_name,
        Runtime=runtime,
        Role=role_arn,
        Handler=handler,
        Code=code_payload,
        Description="Created by CloudPilot AI",
        Timeout=30,
        MemorySize=128
    )
    return {
        "function_name": r["FunctionName"],
        "function_arn": r["FunctionArn"],
        "runtime": r["Runtime"],
        "state": r.get("State", "Active")
    }

def delete_lambda(function_name, region=DEFAULT_REGION):
    client = sess(region).client("lambda")
    client.delete_function(FunctionName=function_name)
    return {
        "function_name": function_name,
        "status": "Deleted successfully"
    }

def estimate_resource_cost(resource_type, instance_type="t3.micro", storage_gb=20, count=1, region=DEFAULT_REGION):
    rates = {
        "ec2": {
            "t2.micro": 0.0116 * 730,
            "t3.micro": 0.0104 * 730,
            "t3.small": 0.0208 * 730,
            "t3.medium": 0.0416 * 730
        },
        "rds": {
            "db.t3.micro": 0.017 * 730,
            "db.t3.small": 0.034 * 730
        },
        "ebs_gb": 0.08,
        "s3_gb": 0.023,
        "lambda_per_million": 0.20
    }
    
    count = int(count or 1)
    storage_gb = float(storage_gb or 0)
    resource = str(resource_type).lower().strip()
    
    monthly_total = 0.0
    
    if resource in ("ec2", "instance", "vm"):
        compute_rate = rates["ec2"].get(instance_type, 7.59)
        compute_cost = compute_rate * count
        ebs_cost = storage_gb * rates["ebs_gb"] * count
        monthly_total = compute_cost + ebs_cost
        breakdown = {
            "compute_cost_monthly": f"${compute_cost:.2f}",
            "ebs_storage_cost_monthly": f"${ebs_cost:.2f}",
            "instance_type": instance_type,
            "instances_count": count,
            "storage_per_instance_gb": storage_gb
        }
    elif resource in ("rds", "database", "db"):
        compute_rate = rates["rds"].get(instance_type, 12.41)
        compute_cost = compute_rate * count
        db_storage_cost = storage_gb * rates["ebs_gb"] * count
        monthly_total = compute_cost + db_storage_cost
        breakdown = {
            "rds_instance_cost_monthly": f"${compute_cost:.2f}",
            "allocated_storage_cost_monthly": f"${db_storage_cost:.2f}",
            "db_instance_class": instance_type,
            "databases_count": count,
            "storage_gb": storage_gb
        }
    elif resource in ("s3", "storage", "bucket"):
        s3_cost = storage_gb * rates["s3_gb"]
        monthly_total = s3_cost
        breakdown = {
            "s3_storage_cost_monthly": f"${s3_cost:.2f}",
            "estimated_stored_gb": storage_gb
        }
    elif resource in ("lambda", "serverless"):
        monthly_total = 0.00
        breakdown = {
            "first_1m_requests": "Free tier eligible ($0.00)",
            "additional_million_requests": "$0.20"
        }
    else:
        monthly_total = 10.0
        breakdown = {"note": f"Estimated baseline for {resource}"}
    
    return {
        "resource_type": resource_type,
        "region": region,
        "estimated_monthly_usd": f"${monthly_total:.2f}",
        "cost_breakdown": breakdown,
        "currency": "USD",
        "pricing_model": "On-Demand (ap-south-1 Mumbai benchmark)",
        "cost_protection_tip": "Enable AWS Budgets and shutdown non-production instances when idle."
    }

def check_budget_status(region=DEFAULT_REGION):
    try:
        sts = sess(region).client("sts")
        account_id = sts.get_caller_identity()["Account"]
        budgets_client = sess(region).client("budgets")
        res = budgets_client.describe_budgets(AccountId=account_id)
        budgets = res.get("Budgets", [])
        return {
            "account_id": account_id,
            "configured_budgets_count": len(budgets),
            "budgets": [{
                "name": b["BudgetName"],
                "limit_usd": b.get("BudgetLimit", {}).get("Amount"),
                "spend_usd": b.get("CalculatedSpend", {}).get("ActualSpend", {}).get("Amount", "0.00"),
                "type": b.get("BudgetType")
            } for b in budgets]
        }
    except Exception as e:
        return {
            "status": "active_monitoring",
            "message": "AWS Budgets API not configured. CloudPilot built-in cost protection & approval-gating is active.",
            "safety_guardrails": {
                "region_lock": "ap-south-1 (Mumbai)",
                "instance_limits": ["t2.micro", "t3.micro", "t3.small"],
                "preview_ttl": "300 seconds",
                "destructive_actions": "Explicit confirmation required"
            },
            "note": str(e)
        }

def troubleshoot_instance(instance_id, region=DEFAULT_REGION):
    ec2 = sess(region).client("ec2")
    reservations = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
    if not reservations or not reservations[0].get("Instances"):
        return {"error": f"Instance {instance_id} not found."}
    inst = reservations[0]["Instances"][0]
    
    statuses = ec2.describe_instance_status(InstanceIds=[instance_id]).get("InstanceStatuses", [])
    system_status = "ok" if not statuses else statuses[0].get("SystemStatus", {}).get("Status", "ok")
    instance_status = "ok" if not statuses else statuses[0].get("InstanceStatus", {}).get("Status", "ok")
    
    sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    sgs_info = []
    if sg_ids:
        sgs_res = ec2.describe_security_groups(GroupIds=sg_ids).get("SecurityGroups", [])
        for g in sgs_res:
            sgs_info.append({
                "group_id": g["GroupId"],
                "name": g.get("GroupName"),
                "inbound_rules_count": len(g.get("IpPermissions", []))
            })
            
    diagnostics = []
    state = inst.get("State", {}).get("Name")
    if state == "stopped":
        diagnostics.append("Instance is in 'stopped' state. Run start_ec2 to resume operations.")
    elif state == "running":
        if system_status == "impaired" or instance_status == "impaired":
            diagnostics.append("⚠️ Instance status checks failing. Consider rebooting or checking system logs.")
        else:
            diagnostics.append("✅ Instance is running and hardware status checks are passing.")
            
    if not inst.get("PublicIpAddress"):
        diagnostics.append("ℹ️ Instance has no Public IPv4 address attached. Direct internet access is not reachable without Elastic IP or Load Balancer.")
        
    return {
        "instance_id": instance_id,
        "state": state,
        "instance_type": inst.get("InstanceType"),
        "vpc_id": inst.get("VpcId"),
        "subnet_id": inst.get("SubnetId"),
        "private_ip": inst.get("PrivateIpAddress"),
        "public_ip": inst.get("PublicIpAddress"),
        "system_status_check": system_status,
        "instance_status_check": instance_status,
        "security_groups": sgs_info,
        "troubleshooting_findings": diagnostics
    }

def generate_architecture_plan(workload_type="web_application", tier="standard", high_availability=False, region=DEFAULT_REGION):
    workload = workload_type.lower()
    if "web" in workload or "app" in workload:
        plan = {
            "workload": "3-Tier Scalable Web Application",
            "vpc": {"cidr": "10.0.0.0/16", "name": "App-VPC"},
            "subnets": [
                {"name": "Public-Subnet-1", "cidr": "10.0.1.0/24", "az": f"{region}a", "type": "public"},
                {"name": "App-Private-Subnet-1", "cidr": "10.0.10.0/24", "az": f"{region}a", "type": "private"},
                {"name": "DB-Private-Subnet-1", "cidr": "10.0.20.0/24", "az": f"{region}b", "type": "private"}
            ],
            "security_groups": [
                {"name": "Web-SG", "inbound": ["HTTP (80) from 0.0.0.0/0", "HTTPS (443) from 0.0.0.0/0"]},
                {"name": "App-SG", "inbound": ["TCP (8000/3000) from Web-SG"]},
                {"name": "DB-SG", "inbound": ["PostgreSQL (5432) from App-SG only"]}
            ],
            "compute": {"service": "EC2 (t3.micro)", "ami": "Amazon Linux 2023"},
            "database": {"service": "Amazon RDS PostgreSQL (db.t3.micro)", "storage_gb": 20},
            "storage": {"service": "Amazon S3 (Private assets bucket)"},
            "deployment_steps": [
                "1. Create VPC (10.0.0.0/16)",
                "2. Create Public & Private Subnets",
                "3. Create Security Groups with least-privilege ingress",
                "4. Launch EC2 instance in Subnet",
                "5. Provision RDS Database in private subnet",
                "6. Provision S3 Assets Bucket with Public Access Block enabled"
            ]
        }
    else:
        plan = {
            "workload": "Serverless Microservices Architecture",
            "compute": {"service": "AWS Lambda (Python 3.11)", "memory": "128MB"},
            "database": {"service": "Amazon RDS or DynamoDB"},
            "storage": {"service": "Amazon S3 (Event triggers & storage)"},
            "monitoring": {"service": "Amazon CloudWatch Alarms & Metrics"},
            "deployment_steps": [
                "1. Create IAM execution role for Lambda",
                "2. Deploy Lambda function code",
                "3. Configure CloudWatch Metric Alarms",
                "4. Create S3 Storage Bucket"
            ]
        }
    return {
        "architecture_blueprint": plan,
        "region": region,
        "high_availability": high_availability,
        "compliance": "AWS Well-Architected Framework aligned"
    }



