import os
import sys
import json
from turtle import back
import pulumi
from pulumi import ResourceOptions, CustomTimeouts
from pulumi_kubernetes import Provider
from pulumi_kubernetes.apps.v1 import Deployment, DeploymentSpecArgs
from pulumi_kubernetes.core.v1 import ContainerArgs, PodSpecArgs, PodTemplateSpecArgs, Service, ServicePortArgs, ServiceSpecArgs
from pulumi_kubernetes.meta.v1 import LabelSelectorArgs, ObjectMetaArgs
from pulumi import automation as auto
from pulumi_aws import eks, iam, ec2, get_availability_zones, route53, elb
from dotenv import dotenv_values
from cprov.utils import generate_kube_config, AutoTag
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

def status(project_name, environment):
    """Get a Pulumi Stack Status"""
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

def manage(project_name, environment, action, pulumi_program, addtl_configs=None):
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
    #stack.set_config("aws:defaultTags", auto.ConfigValue(value={"Environment": environment, "Managed By": "Pulumi"}))

    if addtl_configs is not None:
        for k, v in addtl_configs.items():
            stack.set_config(k, auto.ConfigValue(value=v))
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

def pulumi_eks():
    """Provision an EKS cluster"""
    eks_security_group, subnet_ids = pulumi_eks_vpc()
    eks_role, ec2_role = pulumi_eks_iam()
    eks_cluster = eks.Cluster(
        'eks-cluster',
        role_arn=eks_role.arn,
        tags={
            'Name': 'pulumi-eks-cluster',
        },
        vpc_config=eks.ClusterVpcConfigArgs(
            public_access_cidrs=['0.0.0.0/0'],
            security_group_ids=[eks_security_group.id],
            subnet_ids=subnet_ids,
        ),
    )

    eks_node_group = eks.NodeGroup(
        'eks-node-group',
        cluster_name=eks_cluster.name,
        node_group_name='pulumi-eks-nodegroup',
        node_role_arn=ec2_role.arn,
        subnet_ids=subnet_ids,
        tags={
            'Name': 'pulumi-cluster-nodeGroup',
        },
        scaling_config=eks.NodeGroupScalingConfigArgs(
            desired_size=2,
            max_size=2,
            min_size=1,
        ),
    )

    pulumi.export('cluster-name', eks_cluster.name)
    pulumi.export('kubeconfig', generate_kube_config(eks_cluster))

def pulumi_eks_vpc():
    """Provision a VPC for EKS"""
    vpc = ec2.Vpc(
        'eks-vpc',
        cidr_block='10.100.0.0/16',
        instance_tenancy='default',
        enable_dns_hostnames=True,
        enable_dns_support=True,
        tags={
            'Name': 'pulumi-eks-vpc',
        },
    )

    igw = ec2.InternetGateway(
        'vpc-ig',
        vpc_id=vpc.id,
        tags={
            'Name': 'pulumi-vpc-ig',
        },
    )

    eks_route_table = ec2.RouteTable(
        'vpc-route-table',
        vpc_id=vpc.id,
        routes=[ec2.RouteTableRouteArgs(
            cidr_block='0.0.0.0/0',
            gateway_id=igw.id,
        )],
        tags={
            'Name': 'pulumi-vpc-rt',
        },
    )

    ## Subnets, one for each AZ in a region

    zones = get_availability_zones()
    subnet_ids = []

    for zone in zones.names:
        if zone  != 'us-east-1e' and zone != 'us-east-1f':
            vpc_subnet = ec2.Subnet(
                f'vpc-subnet-{zone}',
                assign_ipv6_address_on_creation=False,
                vpc_id=vpc.id,
                map_public_ip_on_launch=True,
                cidr_block=f'10.100.{len(subnet_ids)}.0/24',
                availability_zone=zone,
                tags={
                    'Name': f'pulumi-sn-{zone}',
                },
            )
            ec2.RouteTableAssociation(
                f'vpc-route-table-assoc-{zone}',
                route_table_id=eks_route_table.id,
                subnet_id=vpc_subnet.id,
            )
            subnet_ids.append(vpc_subnet.id)

    ## Security Group

    eks_security_group = ec2.SecurityGroup(
        'eks-cluster-sg',
        vpc_id=vpc.id,
        description='Allow all HTTP(s) traffic to EKS Cluster',
        tags={
            'Name': 'pulumi-cluster-sg',
        },
        ingress=[
            ec2.SecurityGroupIngressArgs(
                cidr_blocks=['0.0.0.0/0'],
                from_port=443,
                to_port=443,
                protocol='tcp',
                description='Allow pods to communicate with the cluster API Server.'
            ),
            ec2.SecurityGroupIngressArgs(
                cidr_blocks=['0.0.0.0/0'],
                from_port=80,
                to_port=80,
                protocol='tcp',
                description='Allow internet access to pods'
            ),
        ],
    )

    return eks_security_group, subnet_ids

def pulumi_eks_iam():
    """EKS Cluster Role"""
    eks_role = iam.Role(
        'eks-iam-role',
        assume_role_policy=json.dumps({
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                        'Service': 'eks.amazonaws.com'
                    },
                    'Effect': 'Allow',
                    'Sid': ''
                }
            ],
        }),
    )

    iam.RolePolicyAttachment(
        'eks-service-policy-attachment',
        role=eks_role.id,
        policy_arn='arn:aws:iam::aws:policy/AmazonEKSServicePolicy',
    )


    iam.RolePolicyAttachment(
        'eks-cluster-policy-attachment',
        role=eks_role.id,
        policy_arn='arn:aws:iam::aws:policy/AmazonEKSClusterPolicy',
    )

    ## Ec2 NodeGroup Role

    ec2_role = iam.Role(
        'ec2-nodegroup-iam-role',
        assume_role_policy=json.dumps({
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                        'Service': 'ec2.amazonaws.com'
                    },
                    'Effect': 'Allow',
                    'Sid': ''
                }
            ],
        }),
    )

    iam.RolePolicyAttachment(
        'eks-workernode-policy-attachment',
        role=ec2_role.id,
        policy_arn='arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
    )


    iam.RolePolicyAttachment(
        'eks-cni-policy-attachment',
        role=ec2_role.id,
        policy_arn='arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
    )

    iam.RolePolicyAttachment(
        'ec2-container-ro-policy-attachment',
        role=ec2_role.id,
        policy_arn='arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly',
    )

    return eks_role, ec2_role

def pulumi_eks_app():
    """Provision an app on an EKS cluster"""
    config = pulumi.Config()
    environment = config.require('environment')
    project_name = config.require('project_name')
    # Get kubeconfig
    eks_cluster_reference = pulumi.StackReference(f"eks-cluster-{environment}")
    kubeconfig = eks_cluster_reference.get_output("kubeconfig")
    k8s_provider = Provider("k8s-provider",
        kubeconfig=kubeconfig)
    # Deploy app
    app_labels = { "app": "app-nginx", "project_name": project_name, "environment": environment }
    app = Deployment(
        "eks-app",
        spec=DeploymentSpecArgs(
            selector=LabelSelectorArgs(match_labels=app_labels),
            replicas=1,
            template=PodTemplateSpecArgs(
                metadata=ObjectMetaArgs(labels=app_labels),
                spec=PodSpecArgs(containers=[ContainerArgs(name='nginx', image='nginx')]),
            ),
        ), opts=ResourceOptions(provider=k8s_provider))
    ingress = Service(
        'eks-app-svc',
        spec=ServiceSpecArgs(
            type='LoadBalancer',
            selector=app_labels,
            ports=[ServicePortArgs(port=80)],
        ), opts=ResourceOptions(provider=k8s_provider, custom_timeouts=CustomTimeouts(create="15m", delete="15m")))

    ingress_hostname = ingress.status.apply(lambda s: s.load_balancer.ingress[0].hostname)
    pulumi.export('ingress_hostname', ingress_hostname)

def pulumi_eks_app_route_53():
    """Create a Route53 Record for the app"""
    config = pulumi.Config()
    environment = config.require('environment')
    project_name = config.require('project_name')
    hosted_zone_name = config.require('hosted_zone_name')
    # Get Load Balancer IP
    eks_app_reference = pulumi.StackReference(f"eks-app-{environment}")
    ingress_hostname = eks_app_reference.get_output("ingress_hostname")
    # Create Route53 Record
    elb_hosted_zone = elb.get_hosted_zone_id()
    selected = route53.get_zone(name=f"{hosted_zone_name}.")
    eksapp = route53.Record("eks-app-record",
        zone_id=selected.id,
        name=f"eks-app.{selected.name}",
        type="A",
        aliases=[route53.RecordAliasArgs(
            name=ingress_hostname,
            zone_id=elb_hosted_zone.id,
            evaluate_target_health=False,
        )])