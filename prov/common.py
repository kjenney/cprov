import os
import sys
import json
from turtle import back
import pulumi
from pulumi import automation as auto
from pulumi_aws import eks, iam, ec2, get_availability_zones
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
    #stack.set_config("aws:defaultTags", auto.ConfigValue(value={"Environment": environment, "Managed By": "Pulumi"}))
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

def pulumi_eks2():
    """Provision an EKS cluster"""
    config = pulumi.Config()
    environment = config.require('environment')
    project_name = config.require('project_name')
    #AutoTag(environment) # Autotag every taggable resource
    vpc = aws.ec2.Vpc(
        "eks-vpc",
        cidr_block="10.0.0.0/16")
    aws.ec2.Tag("vpc-name",
        resource_id=vpc.id,
        key="Name",
        value=f"eks-{project_name}-{environment}")
    private_subnet = aws.ec2.Subnet(
        "private",
        vpc_id=vpc.id,
        cidr_block="10.0.1.0/24",
        availability_zone="us-east-1a")
    aws.ec2.Tag("private-subnet-name",
        resource_id=private_subnet.id,
        key="Name",
        value="eks-private")
    public_subnet = aws.ec2.Subnet(
        "public",
        vpc_id=vpc.id,
        cidr_block="10.0.2.0/24",
        availability_zone="us-east-1b")
    aws.ec2.Tag("public-subnet-name",
        resource_id=public_subnet.id,
        key="Name",
        value="eks-public") 
    cluster = eks.Cluster('eks-cluster',
                          vpc_id=vpc.id,
                          public_subnet_ids=[public_subnet.id],
                          private_subnet_ids=[private_subnet.id],
                          public_access_cidrs=['0.0.0.0/0'],
                          desired_capacity=2,
                          min_size=2,
                          max_size=2,
                          name=f"{project_name}-{environment}",
                          instance_type='t3.micro',
                          storage_classes={"gp2": eks.StorageClassArgs(
                              type='gp2', allow_volume_expansion=True, default=True, encrypted=True,)},
                          enabled_cluster_log_types=[
                              "api",
                              "audit",
                              "authenticator",
                          ],)
    pulumi.export("kubeconfig", cluster.kubeconfig)

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
    # Get S3 buckets
    eks_cluster_reference = pulumi.StackReference(f"eks-{environment}")
    codepipeline_source_bucket = eks_cluster_reference.get_output("codepipeline_source_bucket")
    buckets = {}
    roles = {}
    buckets["codepipeline_bucket_id"] = s3_reference.get_output("codepipeline_bucket_id")
    # Set the CodePipeline role
    roles['codepipeline_role_arn'] = iam_reference.get_output("codepipeline_role_arn")

class AutoTag:
    """Set tags for a stack"""
    def __init__(self, environment):
        self.tags = {
            'user:Project': pulumi.get_project(),
            'user:Stack': pulumi.get_stack(),
            'user:environment': environment,
            "Managed By": 'Pulumi',
        }
        self.register_auto_tags()
            # taggable_resource_types is a list of known AWS type tokens that are taggable.
        self.taggable_resource_types = [
            'aws:accessanalyzer/analyzer:Analyzer',
            'aws:acm/certificate:Certificate',
            'aws:acmpca/certificateAuthority:CertificateAuthority',
            'aws:alb/loadBalancer:LoadBalancer',
            'aws:alb/targetGroup:TargetGroup',
            'aws:apigateway/apiKey:ApiKey',
            'aws:apigateway/clientCertificate:ClientCertificate',
            'aws:apigateway/domainName:DomainName',
            'aws:apigateway/restApi:RestApi',
            'aws:apigateway/stage:Stage',
            'aws:apigateway/usagePlan:UsagePlan',
            'aws:apigateway/vpcLink:VpcLink',
            'aws:applicationloadbalancing/loadBalancer:LoadBalancer',
            'aws:applicationloadbalancing/targetGroup:TargetGroup',
            'aws:appmesh/mesh:Mesh',
            'aws:appmesh/route:Route',
            'aws:appmesh/virtualNode:VirtualNode',
            'aws:appmesh/virtualRouter:VirtualRouter',
            'aws:appmesh/virtualService:VirtualService',
            'aws:appsync/graphQLApi:GraphQLApi',
            'aws:athena/workgroup:Workgroup',
            'aws:autoscaling/group:Group',
            'aws:backup/plan:Plan',
            'aws:backup/vault:Vault',
            'aws:cfg/aggregateAuthorization:AggregateAuthorization',
            'aws:cfg/configurationAggregator:ConfigurationAggregator',
            'aws:cfg/rule:Rule',
            'aws:cloudformation/stack:Stack',
            'aws:cloudformation/stackSet:StackSet',
            'aws:cloudfront/distribution:Distribution',
            'aws:cloudhsmv2/cluster:Cluster',
            'aws:cloudtrail/trail:Trail',
            'aws:cloudwatch/eventRule:EventRule',
            'aws:cloudwatch/logGroup:LogGroup',
            'aws:cloudwatch/metricAlarm:MetricAlarm',
            'aws:codebuild/project:Project',
            'aws:codecommit/repository:Repository',
            'aws:codepipeline/pipeline:Pipeline',
            'aws:codepipeline/webhook:Webhook',
            'aws:codestarnotifications/notificationRule:NotificationRule',
            'aws:cognito/identityPool:IdentityPool',
            'aws:cognito/userPool:UserPool',
            'aws:datapipeline/pipeline:Pipeline',
            'aws:datasync/agent:Agent',
            'aws:datasync/efsLocation:EfsLocation',
            'aws:datasync/locationSmb:LocationSmb',
            'aws:datasync/nfsLocation:NfsLocation',
            'aws:datasync/s3Location:S3Location',
            'aws:datasync/task:Task',
            'aws:dax/cluster:Cluster',
            'aws:directconnect/connection:Connection',
            'aws:directconnect/hostedPrivateVirtualInterfaceAccepter:HostedPrivateVirtualInterfaceAccepter',
            'aws:directconnect/hostedPublicVirtualInterfaceAccepter:HostedPublicVirtualInterfaceAccepter',
            'aws:directconnect/hostedTransitVirtualInterfaceAcceptor:HostedTransitVirtualInterfaceAcceptor',
            'aws:directconnect/linkAggregationGroup:LinkAggregationGroup',
            'aws:directconnect/privateVirtualInterface:PrivateVirtualInterface',
            'aws:directconnect/publicVirtualInterface:PublicVirtualInterface',
            'aws:directconnect/transitVirtualInterface:TransitVirtualInterface',
            'aws:directoryservice/directory:Directory',
            'aws:dlm/lifecyclePolicy:LifecyclePolicy',
            'aws:dms/endpoint:Endpoint',
            'aws:dms/replicationInstance:ReplicationInstance',
            'aws:dms/replicationSubnetGroup:ReplicationSubnetGroup',
            'aws:dms/replicationTask:ReplicationTask',
            'aws:docdb/cluster:Cluster',
            'aws:docdb/clusterInstance:ClusterInstance',
            'aws:docdb/clusterParameterGroup:ClusterParameterGroup',
            'aws:docdb/subnetGroup:SubnetGroup',
            'aws:dynamodb/table:Table',
            'aws:ebs/snapshot:Snapshot',
            'aws:ebs/snapshotCopy:SnapshotCopy',
            'aws:ebs/volume:Volume',
            'aws:ec2/ami:Ami',
            'aws:ec2/amiCopy:AmiCopy',
            'aws:ec2/amiFromInstance:AmiFromInstance',
            'aws:ec2/capacityReservation:CapacityReservation',
            'aws:ec2/customerGateway:CustomerGateway',
            'aws:ec2/defaultNetworkAcl:DefaultNetworkAcl',
            'aws:ec2/defaultRouteTable:DefaultRouteTable',
            'aws:ec2/defaultSecurityGroup:DefaultSecurityGroup',
            'aws:ec2/defaultSubnet:DefaultSubnet',
            'aws:ec2/defaultVpc:DefaultVpc',
            'aws:ec2/defaultVpcDhcpOptions:DefaultVpcDhcpOptions',
            'aws:ec2/eip:Eip',
            'aws:ec2/fleet:Fleet',
            'aws:ec2/instance:Instance',
            'aws:ec2/internetGateway:InternetGateway',
            'aws:ec2/keyPair:KeyPair',
            'aws:ec2/launchTemplate:LaunchTemplate',
            'aws:ec2/natGateway:NatGateway',
            'aws:ec2/networkAcl:NetworkAcl',
            'aws:ec2/networkInterface:NetworkInterface',
            'aws:ec2/placementGroup:PlacementGroup',
            'aws:ec2/routeTable:RouteTable',
            'aws:ec2/securityGroup:SecurityGroup',
            'aws:ec2/spotInstanceRequest:SpotInstanceRequest',
            'aws:ec2/subnet:Subnet',
            'aws:ec2/vpc:Vpc',
            'aws:ec2/vpcDhcpOptions:VpcDhcpOptions',
            'aws:ec2/vpcEndpoint:VpcEndpoint',
            'aws:ec2/vpcEndpointService:VpcEndpointService',
            'aws:ec2/vpcPeeringConnection:VpcPeeringConnection',
            'aws:ec2/vpcPeeringConnectionAccepter:VpcPeeringConnectionAccepter',
            'aws:ec2/vpnConnection:VpnConnection',
            'aws:ec2/vpnGateway:VpnGateway',
            'aws:ec2clientvpn/endpoint:Endpoint',
            'aws:ec2transitgateway/routeTable:RouteTable',
            'aws:ec2transitgateway/transitGateway:TransitGateway',
            'aws:ec2transitgateway/vpcAttachment:VpcAttachment',
            'aws:ec2transitgateway/vpcAttachmentAccepter:VpcAttachmentAccepter',
            'aws:ecr/repository:Repository',
            'aws:ecs/capacityProvider:CapacityProvider',
            'aws:ecs/cluster:Cluster',
            'aws:ecs/service:Service',
            'aws:ecs/taskDefinition:TaskDefinition',
            'aws:efs/fileSystem:FileSystem',
            'aws:eks/cluster:Cluster',
            'aws:eks/fargateProfile:FargateProfile',
            'aws:eks/nodeGroup:NodeGroup',
            'aws:elasticache/cluster:Cluster',
            'aws:elasticache/replicationGroup:ReplicationGroup',
            'aws:elasticbeanstalk/application:Application',
            'aws:elasticbeanstalk/applicationVersion:ApplicationVersion',
            'aws:elasticbeanstalk/environment:Environment',
            'aws:elasticloadbalancing/loadBalancer:LoadBalancer',
            'aws:elasticloadbalancingv2/loadBalancer:LoadBalancer',
            'aws:elasticloadbalancingv2/targetGroup:TargetGroup',
            'aws:elasticsearch/domain:Domain',
            'aws:elb/loadBalancer:LoadBalancer',
            'aws:emr/cluster:Cluster',
            'aws:fsx/lustreFileSystem:LustreFileSystem',
            'aws:fsx/windowsFileSystem:WindowsFileSystem',
            'aws:gamelift/alias:Alias',
            'aws:gamelift/build:Build',
            'aws:gamelift/fleet:Fleet',
            'aws:gamelift/gameSessionQueue:GameSessionQueue',
            'aws:glacier/vault:Vault',
            'aws:glue/crawler:Crawler',
            'aws:glue/job:Job',
            'aws:glue/trigger:Trigger',
            'aws:iam/role:Role',
            'aws:iam/user:User',
            'aws:inspector/resourceGroup:ResourceGroup',
            'aws:kinesis/analyticsApplication:AnalyticsApplication',
            'aws:kinesis/firehoseDeliveryStream:FirehoseDeliveryStream',
            'aws:kinesis/stream:Stream',
            'aws:kms/externalKey:ExternalKey',
            'aws:kms/key:Key',
            'aws:lambda/function:Function',
            'aws:lb/loadBalancer:LoadBalancer',
            'aws:lb/targetGroup:TargetGroup',
            'aws:licensemanager/licenseConfiguration:LicenseConfiguration',
            'aws:lightsail/instance:Instance',
            'aws:mediaconvert/queue:Queue',
            'aws:mediapackage/channel:Channel',
            'aws:mediastore/container:Container',
            'aws:mq/broker:Broker',
            'aws:mq/configuration:Configuration',
            'aws:msk/cluster:Cluster',
            'aws:neptune/cluster:Cluster',
            'aws:neptune/clusterInstance:ClusterInstance',
            'aws:neptune/clusterParameterGroup:ClusterParameterGroup',
            'aws:neptune/eventSubscription:EventSubscription',
            'aws:neptune/parameterGroup:ParameterGroup',
            'aws:neptune/subnetGroup:SubnetGroup',
            'aws:opsworks/stack:Stack',
            'aws:organizations/account:Account',
            'aws:pinpoint/app:App',
            'aws:qldb/ledger:Ledger',
            'aws:ram/resourceShare:ResourceShare',
            'aws:rds/cluster:Cluster',
            'aws:rds/clusterEndpoint:ClusterEndpoint',
            'aws:rds/clusterInstance:ClusterInstance',
            'aws:rds/clusterParameterGroup:ClusterParameterGroup',
            'aws:rds/clusterSnapshot:ClusterSnapshot',
            'aws:rds/eventSubscription:EventSubscription',
            'aws:rds/instance:Instance',
            'aws:rds/optionGroup:OptionGroup',
            'aws:rds/parameterGroup:ParameterGroup',
            'aws:rds/securityGroup:SecurityGroup',
            'aws:rds/snapshot:Snapshot',
            'aws:rds/subnetGroup:SubnetGroup',
            'aws:redshift/cluster:Cluster',
            'aws:redshift/eventSubscription:EventSubscription',
            'aws:redshift/parameterGroup:ParameterGroup',
            'aws:redshift/snapshotCopyGrant:SnapshotCopyGrant',
            'aws:redshift/snapshotSchedule:SnapshotSchedule',
            'aws:redshift/subnetGroup:SubnetGroup',
            'aws:resourcegroups/group:Group',
            'aws:route53/healthCheck:HealthCheck',
            'aws:route53/resolverEndpoint:ResolverEndpoint',
            'aws:route53/resolverRule:ResolverRule',
            'aws:route53/zone:Zone',
            'aws:s3/bucket:Bucket',
            'aws:s3/bucketObject:BucketObject',
            'aws:sagemaker/endpoint:Endpoint',
            'aws:sagemaker/endpointConfiguration:EndpointConfiguration',
            'aws:sagemaker/model:Model',
            'aws:sagemaker/notebookInstance:NotebookInstance',
            'aws:secretsmanager/secret:Secret',
            'aws:servicecatalog/portfolio:Portfolio',
            'aws:sfn/activity:Activity',
            'aws:sfn/stateMachine:StateMachine',
            'aws:sns/topic:Topic',
            'aws:sqs/queue:Queue',
            'aws:ssm/activation:Activation',
            'aws:ssm/document:Document',
            'aws:ssm/maintenanceWindow:MaintenanceWindow',
            'aws:ssm/parameter:Parameter',
            'aws:ssm/patchBaseline:PatchBaseline',
            'aws:storagegateway/cachesIscsiVolume:CachesIscsiVolume',
            'aws:storagegateway/gateway:Gateway',
            'aws:storagegateway/nfsFileShare:NfsFileShare',
            'aws:storagegateway/smbFileShare:SmbFileShare',
            'aws:swf/domain:Domain',
            'aws:transfer/server:Server',
            'aws:transfer/user:User',
            'aws:waf/rateBasedRule:RateBasedRule',
            'aws:waf/rule:Rule',
            'aws:waf/ruleGroup:RuleGroup',
            'aws:waf/webAcl:WebAcl',
            'aws:wafregional/rateBasedRule:RateBasedRule',
            'aws:wafregional/rule:Rule',
            'aws:wafregional/ruleGroup:RuleGroup',
            'aws:wafregional/webAcl:WebAcl',
            'aws:workspaces/directory:Directory',
            'aws:workspaces/ipGroup:IpGroup',
        ]

    def register_auto_tags(self):
        """
        registerAutoTags registers a global stack transformation that merges a set
        of tags with whatever was also explicitly added to the resource definition.
        """
        pulumi.runtime.register_stack_transformation(lambda args: self.auto_tag(args, self.tags))

    def auto_tag(self, args, auto_tags):
        """auto_tag applies the given tags to the resource properties if applicable."""
        if self.is_taggable(args.type_):
            args.props['tags'] = {**(args.props['tags'] or {}), **auto_tags}
            return pulumi.ResourceTransformationResult(args.props, args.opts)

    def is_taggable(self, t):
        """isTaggable returns true if the given resource type is an AWS resource that supports tags."""
        return t in self.taggable_resource_types