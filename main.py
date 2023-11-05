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

class MatchedRule:
    def __init__(self, rule_message):
        # TODO add more fields from the RuleMessage class
        self.rule_id = rule_message.m_ruleId
        self.severity = rule_message.m_severity
        self.tags = rule_message.m_tags



class RulesLogger:
    def __init__(self, debug=False):
        self._rules_triggered = []
        self._debug = debug
        self._score = 0

    def __call__(self, data, rule_message):
        if self._debug:
            print("[!] Rule {} matched - Message: {}, Phase: {}, Severity: {}".format(
                rule_message.m_ruleId, rule_message.m_message, rule_message.m_phase,
                rule_message.m_severity))

        if rule_message.m_ruleId == 949110:
            self._score = float(re.findall(r"\(Total Score: (\d+)\)", str(rule_message.m_message))[0])
        if str(rule_message.m_ruleId) not in self._rules_triggered:
            self._rules_triggered.append(MatchedRule(rule_message))

    def get_rules(self):
        return self._rules_triggered

    def get_score(self):
        return self._score


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

    rules_logger = RulesLogger(debug=verbose)
    modsec.setServerLogCb2(rules_logger, LogProperty.RuleMessageLogProperty)

    transaction = Transaction(modsec, rules)
    transaction.processURI(full_url, "GET", "2.0")
    transaction.addRequestHeader("Host", parsed_url.netloc) # Avoid matching rule 920280
    transaction.processRequestHeaders()
    transaction.processRequestBody()

    print("Total Score (from rule 949110)", rules_logger.get_score())

    matched_rules = { r.rule_id: r.severity for r in rules_logger.get_rules()}
    # print(matched_rules)
    print("Total Score (from matched rules)", sum(matched_rules.values()))
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
