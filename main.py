from ModSecurity import ModSecurity
from ModSecurity import RulesSet
from ModSecurity import Transaction
from ModSecurity import LogProperty

import re
import glob
from urllib.parse import urlparse, urlencode
import typer
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


@app.command()
def version():
    modsec = ModSecurity()
    print(modsec.whoAmI())

@app.command()
def evaluate(payload: str,
            base_uri: Annotated[str, typer.Option(help="Base URI for payload evaluation")] = "http://www.modsecurity.org/test",
            verbose: Annotated[bool, typer.Option(help="Print matched rules with associated scores")] = False,
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
    # rules.loadFromUri("conf/modsecurity.conf")
    rules.loadFromUri("conf/crs-setup.conf")
    

    # Load CRS
    for rule_path in glob.glob('coreruleset/rules/*.conf'):
        rules.loadFromUri(rule_path)

    transaction = Transaction(modsec, rules)
    transaction.processURI(full_url, "GET", "2.0")
    transaction.addRequestHeader("Host", parsed_url.netloc) # Avoid matching rule 920280
    transaction.processRequestHeaders()
    transaction.processRequestBody()

    matched_rules = { m.m_ruleId:m for m in transaction.m_rulesMessages}
    if verbose:
        print("# Matched rules")
        print()
        print("\n".join([ f" - {rule.m_ruleId} [+{Severity(rule.m_severity).score}]\t- {rule.m_message}" for rule in transaction.m_rulesMessages]))

    # print("Total Score (from rule 949110)", matched_rules[949110].m_message.split(":")[-1].strip(" )"))

    # print(matched_rules)
    if verbose:
        print("\nTotal Score (from matched rules): ", end="")

    total_score = sum([ Severity(rule.m_severity).score for rule in transaction.m_rulesMessages])
    print(total_score)
    return total_score

    # TODO get rules scores based on paranoia level, using tags
    #  - This could be handled via modsecurity configuration
    #  - If we handle it here, we need to match all tags >= the set paranoia level
    # print([tag for r in rules_logger.get_rules() for tag in r.tags])
    # print({ r.rule_id: r.severity for r in rules_logger.get_rules() if 'paranoia-level/2' in r.tags})
    # print(sum(r.severity for r in rules_logger.get_rules() if 'paranoia-level/2' in r.tags))



if __name__ == "__main__":
    app()
