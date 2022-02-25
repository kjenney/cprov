import click
import functools

from prov.common import manage

@click.command()
def status():
    """Get the status of a Pulumi stack"""
    print('Status')
