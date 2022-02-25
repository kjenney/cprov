import click

from prov.version import VERSION

from prov.commands.do import do
from prov.commands.status import status

@click.group()
def entry():
    pass

@entry.command()
def version():
    """Show the version"""
    print('version: ' + VERSION)

entry.add_command(do)
entry.add_command(status)
entry.add_command(version)