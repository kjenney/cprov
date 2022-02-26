import click

from ._version import __version__

from cprov.commands.do import do
from cprov.commands.status import status

@click.group()
def entry():
    pass

@entry.command()
def version():
    """Show the version"""
    print(str(__version__))

entry.add_command(do)
entry.add_command(status)
entry.add_command(version)