#!/usr/bin/env python3
"""seed_lab.py — Seed LocalStack with vulnerable AWS resources"""
import boto3
from botocore.exceptions import ClientError

ENDPOINT = "http://127.0.0.1:4566"
REGION = "us-east-1"

def client(svc):
    return boto3.client(svc, endpoint_url=ENDPOINT, region_name=REGION,
                        aws_access_key_id="test", aws_secret_access_key="test")

def main():
    print("[*] Seeding LocalStack...")

    # --- S3 public bucket ---
    s3 = client("s3")
    try:
        s3.create_bucket(Bucket="company-backup")
        print("  [+] S3 bucket 'company-backup' created")
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" not in str(e):
            print(f"  [~] S3 bucket: {e}")

    s3.put_object(Bucket="company-backup", Key="secret.txt",
                  Body=b"FLAG{public_bucket_data_exposed}\nDB_PASSWORD=admin123\n")

    try:
        s3.delete_public_access_block(Bucket="company-backup")
    except ClientError:
        pass

    policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::company-backup/*"}]}'
    s3.put_bucket_policy(Bucket="company-backup", Policy=policy)
    print("  [+] S3 bucket 'company-backup' is PUBLIC")

    # --- IAM user with wildcard ---
    iam = client("iam")
    try:
        iam.create_user(UserName="dev-user")
        print("  [+] IAM user 'dev-user' created")
    except ClientError:
        pass

    iam.put_user_policy(
        UserName="dev-user",
        PolicyName="FullAccess",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    )
    print("  [+] IAM user 'dev-user' has Action:* Resource:*")

    # --- IAM role with admin ---
    try:
        iam.create_role(
            RoleName="lambda-role",
            AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        )
        iam.attach_role_policy(RoleName="lambda-role",
                               PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        print("  [+] IAM role 'lambda-role' created (AdministratorAccess)")
    except ClientError:
        pass

    # --- EC2 open security group ---
    ec2 = client("ec2")
    try:
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        ec2.create_security_group(
            GroupName="open-ssh", Description="Open SSH to world", VpcId=vpc_id
        )
        ec2.authorize_security_group_ingress(
            GroupName="open-ssh",
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )
        print("  [+] EC2 security group 'open-ssh' (0.0.0.0/0:22)")
    except ClientError as e:
        print(f"  [~] EC2 SG: {str(e)[:80]}")

    print("\n[✓] Lab seeded. Run the toolkit next.")

if __name__ == "__main__":
    main()
