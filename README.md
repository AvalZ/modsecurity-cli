# ModSecurity CLI

A CLI wrapper for libmodsecurity to quickly test payloads against Rules in a headless mode, without having to set up a full-fledged web testing environment.

This wrapper is still in development, and some ModSecurity features could be missing.
Most ModSecurity methods are implemented via [pymodsecurity](https://github.com/AvalZ/pymodsecurity) (requires manual building -- [PR](https://github.com/pymodsecurity/pymodsecurity/pull/21) pending on the [official repository](https://github.com/pymodsecurity/pymodsecurity)), 

## Getting started

To run `modsecurity-cli`, you will need a few setup steps.

### Setup

1. [Compile and Install ModSecurity v3.0.10](#compile-modsecurity-v3010)
1. [Install pymodsecurity](#install-pymodsecurity)
1. [Clone the OWASP CoreRuleSet](#clone-the-owasp-coreruleset)
1. [Run the CLI!](#run-the-cli)

Here's the detail for each step.

### Compile ModSecurity v3.0.10 

First of all, you will need to install [ModSecurity v3.0.10](https://github.com/SpiderLabs/ModSecurity/releases/tag/v3.0.10) on your system.
Currently, this is a ~~nightmare~~tricky process, since you will need to [build ModSecurity v3.0.10 from source](https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes-for-v3.x)
(although some distros might have an updated registry with ModSecurity 3.0.10 already available `*coff*arch*coff*`)

### Install pymodsecurity


In `modsecurity-cli` ModSecurity methods are implemented via [pymodsecurity](https://github.com/pymodsecurity/pymodsecurity).
Since development on the official repository stopped on ModSecurity v3.0.3, we opened a [PR](https://github.com/pymodsecurity/pymodsecurity/pull/21).

Current workaround: clone [our fork](https://github.com/AvalZ/pymodsecurity) and [build it from source](https://github.com/AvalZ/pymodsecurity#building-from-source)
 
### Clone the OWASP CoreRuleSet

To detect incoming payloads, you need a Rule Set.
The *de facto* standard is the [OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset), but of course you can choose any Rule Set you want, or customize the OWASP CRS.

To run the recommended settings, just clone the OWASP CRS in the project folder:
```
git clone git@github.com:coreruleset/coreruleset.git
```

### Run the CLI!

Check ModSecurity version

```console
$ python3 main.py --version

```

Evaluate a single parameter

```console
$ python3 main.py "<script>alert(1)</script>"

20
```

If you want to see the breakdown of matched rules, just use `--verbose`

```console
$ python3 main.py "<script>alert(1)</script>" --verbose

GET http://www.modsecurity.org/test?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

# Matched rules

 -  920320 [+2/PL2] - Missing User Agent Header
 -  920273 [+5/PL4] - Invalid character in request (outside of very strict set)
 +  941100 [+5/PL1] - XSS Attack Detected via libinjection
 +  941110 [+5/PL1] - XSS Filter - Category 1: Script Tag Vector
 +  941160 [+5/PL1] - NoScript XSS InjectionChecker: HTML Injection
 +  941390 [+5/PL1] - Javascript method detected
 -  941320 [+5/PL2] - Possible XSS Attack Detected - HTML Tag Handler
 -  942131 [+5/PL2] - SQL Injection Attack: SQL Boolean-based attack detected
 -  942431 [+3/PL3] - Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
 -  942432 [+3/PL4] - Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
 +  949110 [+0/PL1] - Inbound Anomaly Score Exceeded (Total Score: 43)

Total Score (from matched rules): 20
```

`+` rules are the ones that are actually matched, while `-` rules apply to different paranoia levels (`1` by default)

You can set a specific Paranoia Level to calculate the score (the default PL is `1`)

```console
$ python3 main.py "<script>alert(1)</script>" -v -PL 2

GET http://www.modsecurity.org/test?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

# Matched rules

 -  920320 [+2/PL2] - Missing User Agent Header
 -  920273 [+5/PL4] - Invalid character in request (outside of very strict set)
 +  941100 [+5/PL1] - XSS Attack Detected via libinjection
 +  941110 [+5/PL1] - XSS Filter - Category 1: Script Tag Vector
 +  941160 [+5/PL1] - NoScript XSS InjectionChecker: HTML Injection
 +  941390 [+5/PL1] - Javascript method detected
 -  941320 [+5/PL2] - Possible XSS Attack Detected - HTML Tag Handler
 -  942131 [+5/PL2] - SQL Injection Attack: SQL Boolean-based attack detected
 -  942431 [+3/PL3] - Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
 -  942432 [+3/PL4] - Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
 +  949110 [+0/PL1] - Inbound Anomaly Score Exceeded (Total Score: 43)

Total Score (from matched rules): 20
```

WARNING! You can see that it prints two `Total Scores`. One (`20`) is calculated by matched rules (`+`), while the other one (`43`) is the error message from rule `949110` (which is calculated at Paranoia Level 4).

If you don't want this message, you can either increase the Anomaly Score threshold via your `conf/crs-setup.conf`, or by removing rule `949110` file entirely (not advised).

`modsecurity-cli` has many options, check out the `--help` for all details! *(a wiki is coming)*

```console
$ python3 main.py --help
```

## TODOs

This CLI wrapper is still under development, so you might not find some features that are interesting to you just yet.

Here's the list of our current and future steps:

 - [x] ModSecurity from CLI
 - [x] Import all rules in a folder
 - [x] Support GET parameters evaluation
 - [x] Support Request Header evaluation
 - [x] Set default config to avoid matching [rule 901001](https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-901-INITIALIZATION.conf#L54-L63)
 - [x] Score based on Paranoia Level (basic config uses PL/4, then we filter on a given PL - default: 1)
 - [x] Support POST request evaluation
 - [ ] Full URI evaluation
 - [ ] Create Python package
 - [ ] Wiki to fully document every option
 - [ ] Integration with [regrets](https://github.com/AvalZ/regrets)
 - [ ] Response evaluation (currently supports requests only)

If you want to contribute by adding something from the list, PRs are welcome :sunglasses:

## Contributors

 - Andrea Valenza ([AvalZ](https://github.com/avalz)) - avalenza89@gmail.com
 - Luca Demetrio ([zangobot](https://github.com/zangobot)) - luca.demetrio@dibris.unige.it

