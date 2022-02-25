import click
import functools

from cprov.common import manage, pulumi_eks, pulumi_eks_app, pulumi_eks_app_route_53

@click.group(chain=True)
@click.option('--action', type=click.Choice(['up', 'destroy', 'preview'], case_sensitive=False), default='up')
@click.option('--environment', default='dev')
@click.pass_context
def do(ctx, action, environment):
    """Do some stuff on AWS

    The default action is 'up'. 'preview' and 'destroy' are also supported.

    Deploy an EKS cluster to AWS:

    cprov do --action up --environment dev eks

    Deploy an EKS cluster, an application, and a Route53 record for the application to AWS:

    cprov do --action up --environment dev everything
    """
    ctx.ensure_object(dict)
    ctx.obj['ACTION'] = action
    ctx.obj['ENVIRONMENT'] = environment

@do.command()
@click.pass_context
def eks(ctx):
    """Do some stuff with an EKS cluster"""
    manage('eks-cluster', ctx.obj['ENVIRONMENT'], ctx.obj['ACTION'], pulumi_eks)

@do.command()
@click.pass_context
def app(ctx):
    """Do some stuff with app"""
    manage('eks-app', ctx.obj['ENVIRONMENT'], ctx.obj['ACTION'], pulumi_eks_app)

@do.command()
@click.option('--dns-name', required=True)
@click.pass_context
def dns(ctx, dns_name):
    """Do some stuff with a Route53 record"""
    manage('eks-app-dns', ctx.obj['ENVIRONMENT'], ctx.obj['ACTION'], pulumi_eks_app_route_53, {'hosted_zone_name': dns_name})

@do.command()
@click.pass_context
def everything(ctx):
    """Do some stuff with everything"""
    manage('eks-cluster', ctx.obj['ENVIRONMENT'], ctx.obj['ACTION'], pulumi_eks)
    manage('eks-app', ctx.obj['ENVIRONMENT'], ctx.obj['ACTION'], pulumi_eks_app)
    manage('eks-app-dns', ctx.obj['ENVIRONMENT'], ctx.obj['ACTION'], pulumi_eks_app_route_53)