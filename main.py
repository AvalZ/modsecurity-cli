from ModSecurity import ModSecurity
from ModSecurity import RulesSet
from ModSecurity import Transaction
from ModSecurity import LogProperty

import re
import glob
from urllib.parse import urlparse, urlencode
import typer
from typing_extensions import Annotated

app = typer.Typer()

@app.command()
def version():
    modsec = ModSecurity()
    print(modsec.whoAmI())

@app.command()
def evaluate(payload: str,
            verbose: Annotated[bool, typer.Option(help="Print all matched rules")] = False):
    modsec = ModSecurity()

    # FIXME temporary workaround for base URLs
    base_uri = "http://www.modsecurity.org/test"
    encoded_query = urlencode({"q": payload})
    full_url = f"{base_uri}?{encoded_query}"
    parsed_url = urlparse(full_url)

    rules = RulesSet()
    for rule_path in glob.glob('coreruleset/rules/*.conf'):
        rules.loadFromUri(rule_path)

    transaction = Transaction(modsec, rules)
    transaction.processURI(full_url, "GET", "2.0")
    transaction.addRequestHeader("Host", parsed_url.netloc) # Avoid matching rule 920280
    transaction.processRequestHeaders()
    transaction.processRequestBody()

    matched_rules = { m.m_ruleId:m for m in transaction.m_rulesMessages}
    print(transaction.m_rulesMessages)
    print([ rule.m_ruleId for rule in transaction.m_rulesMessages])
    print([ rule.m_severity for rule in transaction.m_rulesMessages])
    print([ rule.m_message for rule in transaction.m_rulesMessages])

    print("Total Score (from rule 949110)", matched_rules[949110].m_message.split(":")[-1].strip(" )"))

    # print(matched_rules)
    print("Total Score (from matched rules)", sum([ rule.m_severity for rule in matched_rules.values()]))
    if verbose:
        print("Matched rules:", list(matched_rules.keys()))

    


    # TODO get rules scores based on paranoia level, using tags
    #  - This could be handled via modsecurity configuration
    #  - If we handle it here, we need to match all tags >= the set paranoia level
    # print([tag for r in rules_logger.get_rules() for tag in r.tags])
    # print({ r.rule_id: r.severity for r in rules_logger.get_rules() if 'paranoia-level/2' in r.tags})
    # print(sum(r.severity for r in rules_logger.get_rules() if 'paranoia-level/2' in r.tags))



if __name__ == "__main__":
    app()
