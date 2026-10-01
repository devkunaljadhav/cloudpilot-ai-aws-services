
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
    # IAM is global; boto3 accepts a region endpoint for IAM.
    return [{"name":r["RoleName"],"arn":r["Arn"],"created":str(r["CreateDate"])}
      for r in sess(region).client("iam").list_roles().get("Roles",[])]

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

def launch_ec2(name, ami_id, instance_type, subnet_id, sg_id, key_name, region=DEFAULT_REGION):
    if instance_type not in {"t3.micro","t3.small","t2.micro"}:
        raise ValueError("MVP permits t3.micro, t3.small, t2.micro only")
    r=sess(region).client("ec2").run_instances(ImageId=ami_id,InstanceType=instance_type,
      MinCount=1,MaxCount=1,KeyName=key_name,
      NetworkInterfaces=[{"DeviceIndex":0,"SubnetId":subnet_id,"Groups":[sg_id],
        "AssociatePublicIpAddress":False}],
      TagSpecifications=[{"ResourceType":"instance","Tags":[
        {"Key":"Name","Value":(name or "CloudPilot-Instance")[:255]},
        {"Key":"ManagedBy","Value":"CloudPilotAI"}]}])
    i=r["Instances"][0]
    return {"instance_id":i["InstanceId"],"state":i["State"]["Name"],
      "note":"No public IPv4; AWS charges may apply."}


