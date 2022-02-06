import os
import sys
import json
from turtle import back
from pulumi import automation as auto
import pulumi_aws as aws
from pprint import pprint
from dotenv import dotenv_values

def check_for_aws_credentials():
    """Check for AWS Credentials before doing anything"""
    key = os.environ.get('AWS_ACCESS_KEY_ID')
    if key is not None:
        return True
    else:
        return False

def manage(project_name, environment, action, pulumi_program):
    """Pulumi up"""
    config = dotenv_values(".env")
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

def pulumi_program():
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