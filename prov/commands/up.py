import click

from prov.common import manage, pulumi_program, check_for_aws_credentials

@click.command()
def up():
    """Provision some stuff"""
    project_name = "prov"
    environment = "dev"
    if check_for_aws_credentials():
        manage(project_name, environment, "up", pulumi_program)
    else:
        click.echo(click.style('AWS Credentials not found!', fg='red'))
        exit(1)
