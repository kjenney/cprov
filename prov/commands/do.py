import click
import functools

from prov.common import manage, pulumi_eks

@click.group(chain=True)
@click.option('--action', type=click.Choice(['up', 'destroy', 'preview'], case_sensitive=False), default='up')
@click.option('--project-name', default='prov')
@click.option('--environment', default='dev')
@click.pass_context
def do(ctx, action, project_name, environment):
    """Do some stuff"""
    ctx.ensure_object(dict)
    ctx.obj['ACTION'] = action
    ctx.obj['PROJECT_NAME'] = project_name
    ctx.obj['ENVIRONMENT'] = environment

@do.command()
@click.pass_context
def eks(ctx):
    """Provision an EKS cluster"""
    manage(ctx.obj['PROJECT_NAME'], ctx.obj['ENVIRONMENT'], ctx.obj['ACTION'], pulumi_eks)
