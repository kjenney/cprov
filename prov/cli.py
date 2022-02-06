import click

from prov.version import VERSION

from prov.commands.up import up
from prov.commands.down import down
from prov.commands.preview import preview

@click.group()
def entry():
    pass

@entry.command()
def version():
    """Show the version"""
    print('version: ' + VERSION)

entry.add_command(up)
entry.add_command(down)
entry.add_command(preview)
entry.add_command(version)