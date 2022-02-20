import os
import sys
import json
from turtle import back
import pulumi
from pulumi import automation as auto
import pulumi_aws as aws
from dotenv import dotenv_values
import click

def check_for_aws_credentials():
    """Check for AWS Credentials before doing anything"""
    key = os.environ.get('AWS_ACCESS_KEY_ID')
    if key is not None:
        return True
    return False


def check_for_values_in_config(config):
    """Check if the correct values are in the config file"""
    if 'STATE_BUCKET' and 'KMS_KEY' in config:
        print("STATE_BUCKET and KMS_KEY found")
        return True
    else:
        click.echo(click.style("STATE_BUCKET or KMS_KEY not found", fg='yellow'))
        return False

def check_for_config():
    """Check for config file"""
    config = dotenv_values(".env")
    if config:
        if check_for_values_in_config(config):
            return config
        else:
            click.echo(click.style("You need to set the correct values in the config file", fg='red'))
            sys.exit(1)
    else:
        click.echo(click.style("Make sure your .env file is in the same directory as this script", fg='red'))
        sys.exit(1)

def manage(project_name, environment, action, pulumi_program):
    """Pulumi up"""
    if check_for_aws_credentials() is False:
        print("You need to set your AWS credentials before running this command")
        sys.exit(1)
    config = check_for_config()
    backend_bucket = config['STATE_BUCKET']
    aws_region = os.getenv('AWS_REGION')
    kms_alias_name = config['KMS_KEY']
    stack_name = f"{project_name}-{environment}"
    secrets_provider = f"awskms://alias/{kms_alias_name}"
    backend_url = f"s3://{backend_bucket}"
    if action == 'destroy':
        print(f"Destroying infra: {project_name}")
    elif action == 'preview':
        print(f"Previewing infra: {project_name}")
    else:
        print(f"Deploying infra: {project_name}")

    project_settings=auto.ProjectSettings(
        name=project_name,
        runtime="python",
        backend={"url": backend_url}
    )

    stack_settings=auto.StackSettings(
        secrets_provider=secrets_provider)

    workspace_opts = auto.LocalWorkspaceOptions(project_settings=project_settings,
                                                  secrets_provider=secrets_provider,
                                                  stack_settings={stack_name: stack_settings})

    stack = auto.create_or_select_stack(stack_name=stack_name,
                                        project_name=project_name,
                                        program=pulumi_program,
                                        opts=workspace_opts)


    print("successfully initialized stack")

    # for inline programs, we must manage plugins ourselves
    print("installing plugins...")
    stack.workspace.install_plugin("aws", "v4.20.0")
    stack.workspace.install_plugin("github", "v4.4.0")
    stack.workspace.install_plugin("docker", "v3.1.0")
    print("plugins installed")

    # set stack configuration environment config and/or secrets
    print("setting up config")
    stack.set_config("aws_region", auto.ConfigValue(value=aws_region))
    stack.set_config("environment", auto.ConfigValue(value=environment))
    stack.set_config("project_name", auto.ConfigValue(value=project_name))
    print("config set")

    print("refreshing stack...")
    stack.refresh(on_output=print)
    print("refresh complete")

    if action == 'destroy':
        stack.destroy(on_output=print)
        print("stack destroy complete")
        sys.exit()

    if action == 'preview':
        stack.preview(on_output=print)
        print("stack preview complete")
        sys.exit()

    print("updating stack...")
    up_res = stack.up(on_output=print)
    print(f"update summary: \n{json.dumps(up_res.summary.resource_changes, indent=4)}")
    return up_res

def pulumi_s3():
    """Create an S3 Bucket"""
    aws.s3.Bucket(
        "provtest",
        acl="private",
        tags={
            "Environment": 'dev',
            "Managed By": "Pulumi",
            "Name": "provtest",
        }
    )

def pulumi_ecr():
    """Create an ECR Repository"""
    aws.s3.Bucket(
        "provtest",
        acl="private",
        tags={
            "Environment": 'dev',
            "Managed By": "Pulumi",
            "Name": "provtest",
        }
    )

def pulumi_pipeline():
    """Create an ECR Repository"""
    aws.s3.Bucket(
        "provtest",
        acl="private",
        tags={
            "Environment": 'dev',
            "Managed By": "Pulumi",
            "Name": "provtest",
        }
    )

def pulumi_cloudtrail():
    """Create a CloudTrail trail"""
    aws.s3.Bucket(
        "provtest",
        acl="private",
        tags={
            "Environment": 'dev',
            "Managed By": "Pulumi",
            "Name": "provtest",
        }
    )

def pulumi_rds():
    """Create am RDS database"""
    aws.s3.Bucket(
        "provtest",
        acl="private",
        tags={
            "Environment": 'dev',
            "Managed By": "Pulumi",
            "Name": "provtest",
        }
    )

def pulumi_secrets():
    """Create secrets"""
    aws.s3.Bucket(
        "provtest",
        acl="private",
        tags={
            "Environment": 'dev',
            "Managed By": "Pulumi",
            "Name": "provtest",
        }
    )

def generate_kube_config(eks_cluster):
    """Generate kube config"""
    kubeconfig = pulumi.Output.all(eks_cluster.endpoint, eks_cluster.certificate_authority.apply(lambda v: v.data), eks_cluster.name).apply(lambda args: json.dumps({
        "apiVersion": "v1",
        "clusters": [{
            "cluster": {
                "server": args[0],
                "certificate-authority-data": args[1]
            },
            "name": "kubernetes",
        }],
        "contexts": [{
            "context": {
                "cluster": "kubernetes",
                "user": "aws",
            },
            "name": "aws",
        }],
        "current-context": "aws",
        "kind": "Config",
        "users": [{
            "name": "aws",
            "user": {
                "exec": {
                    "apiVersion": "client.authentication.k8s.io/v1alpha1",
                    "command": "aws-iam-authenticator",
                    "args": [
                        "token",
                        "-i",
                        args[2],
                    ],
                },
            },
        }],
    }))
    return kubeconfig


def pulumi_eks():
    """Provision an EKS cluster"""
    config = pulumi.Config()
    environment = config.require('environment')
    project_name = config.require('project_name')
    tags={
        "Function": "eks",
        "Environment": environment,
        "Project": project_name,
        "Managed By": "Pulumi",
    }
    vpc = aws.ec2.Vpc(
        "eks-vpc",
        cidr_block="10.0.0.0/16",
        tags=tags)
    aws.ec2.Tag("vpc-name",
        resource_id=vpc.id,
        key="Name",
        value=f"eks-{project_name}-{environment}")
    private_subnet = aws.ec2.Subnet(
        "private",
        vpc_id=vpc.id,
        cidr_block="10.0.1.0/24",
        availability_zone="us-east-1a",
        tags=tags)
    aws.ec2.Tag("private-subnet-name",
        resource_id=private_subnet.id,
        key="Name",
        value="eks-private")
    public_subnet = aws.ec2.Subnet(
        "public",
        vpc_id=vpc.id,
        cidr_block="10.0.2.0/24",
        availability_zone="us-east-1b",
        tags=tags)
    aws.ec2.Tag("public-subnet-name",
        resource_id=public_subnet.id,
        key="Name",
        value="eks-public") 
    cluster_iam_role = aws.iam.Role("eks-cluster-iam-role", assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
            }
        ]
        }
        """)
    attach_cluster_policy = aws.iam.RolePolicyAttachment("example-AmazonEKSClusterPolicy",
        policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
        role=cluster_iam_role.name)
    attach_controller_policy = aws.iam.RolePolicyAttachment("example-AmazonEKSVPCResourceController",
        policy_arn="arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
        role=cluster_iam_role.name)
    cluster = aws.eks.Cluster("eks-cluster",
        role_arn=cluster_iam_role.arn,
        vpc_config=aws.eks.ClusterVpcConfigArgs(
            subnet_ids=[
                private_subnet.id,
                public_subnet.id,
            ],
        ),
        opts=pulumi.ResourceOptions(depends_on=[
            attach_cluster_policy,
            attach_controller_policy,
        ]),
        tags=tags)
    aws.ec2.Tag("eks-cluster-name",
        resource_id=cluster.id,
        key="Name",
        value=f"eks-{project_name}-{environment}")
    pulumi.export("endpoint", cluster.endpoint)
    pulumi.export("kubeconfig-certificate-authority-data", cluster.certificate_authority.data)
