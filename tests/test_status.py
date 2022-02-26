from click.testing import CliRunner

from cprov.cli import entry

def test_greet_cli():
    runner = CliRunner()
    result = runner.invoke(entry, ['status'])
    assert result.exit_code == 0
    assert "Status" in result.output

