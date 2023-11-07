from ModSecurity import ModSecurity
from ModSecurity import RulesSet
from ModSecurity import Transaction
from ModSecurity import LogProperty

import re
import glob
from urllib.parse import urlparse, urlencode
import typer
from typing import List
from typing_extensions import Annotated
from enum import Enum

app = typer.Typer()

class Severity(Enum):

  def __new__(cls, *args, **kwds):
    value = len(cls.__members__)
    obj = object.__new__(cls)
    obj._value_ = value
    return obj
  def __init__(self, severity_id, score):
    self.id = severity_id
    self.score = score
 
  EMERGENCY = 0, 0 # not used in CRS
  ALERT     = 1, 0 # not used in CRS
  CRITICAL  = 2, 5
  ERROR     = 3, 4
  WARNING   = 4, 3
  NOTICE    = 5, 2
  INFO      = 6, 0 # not used in CRS
  DEBUG     = 7, 0 # not used in CRS

def get_paranoia_level(rule):
    return next((int(tag.split('/')[1]) for tag in rule.m_tags if 'paranoia-level' in tag), 1)

@app.command()
def parameter(payload: str,
            base_uri: Annotated[str, typer.Option(help="Base URI for payload evaluation")] = "http://www.modsecurity.org/test",
            headers: Annotated[List[str], typer.Option('-H', '--header', help="List of headers")] = [],
            paranoia_level: Annotated[int, typer.Option('-PL', '--paranoia-level', help="Paranoia Level")] = 1,
            configs: Annotated[List[str], typer.Option('--config', help="List of additional configuration files (loaded BEFORE rules")] = ['conf/modsecurity.conf', 'conf/crs-setup.conf'],
            rules_path: Annotated[str, typer.Option('--rules', help="Rules location")] = 'coreruleset/rules',
            verbose: Annotated[bool, typer.Option('-v', '--verbose', help="Print matched rules with associated scores")] = False,
            logs: Annotated[bool, typer.Option(help="Print libmodsecurity server logs")] = False):
    modsec = ModSecurity()

    if not logs:
        # disable logs
        modsec.setServerLogCb2(lambda x, y: None, LogProperty.RuleMessageLogProperty)

    encoded_query = urlencode({"q": payload})
    full_url = f"{base_uri}?{encoded_query}"
    parsed_url = urlparse(full_url)

    rules = RulesSet()

    # Load basic conf
    for config in configs:
        rules.loadFromUri(config)

    # Load rules
    for rule_path in glob.glob(f"{rules_path}/*.conf"):
        rules.loadFromUri(rule_path)

    transaction = Transaction(modsec, rules)
    transaction.processURI(full_url, "GET", "2.0")
    
    headers.append(f"Host: {parsed_url.netloc}") # Avoid matching rule 920280
    for header in headers:
        name, value = header.split(':')
        transaction.addRequestHeader(name, value.strip()) # Avoid matching rule 920280
    transaction.processRequestHeaders()
    transaction.processRequestBody()

    # Decorate RuleMessages
    for rule in transaction.m_rulesMessages:
        rule.m_severity = Severity(rule.m_severity).score

    if verbose:
        print("# Matched rules")
        print()
        for rule in transaction.m_rulesMessages:
            print(' + ' if get_paranoia_level(rule) <= paranoia_level else ' - ', end='')
            print(f" {rule.m_ruleId} [+{rule.m_severity}/PL{get_paranoia_level(rule)}] - {rule.m_message}")

    if verbose:
        print("\nTotal Score (from matched rules): ", end="")

    total_score = sum([ rule.m_severity for rule in transaction.m_rulesMessages if get_paranoia_level(rule) <= paranoia_level])
    print(total_score)

if __name__ == "__main__":
    app()
