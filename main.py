from ModSecurity import ModSecurity

import typer

# Subcommands
import evaluate

app = typer.Typer()
app.add_typer(evaluate.app, name="evaluate", help="Evaluate request against loaded rules")

@app.command()
def version():
    modsec = ModSecurity()
    print(modsec.whoAmI())

if __name__ == "__main__":
    app()
