# modsecurity-cli
A CLI wrapper for libmodsecurity to test Rules

This wrapper is still in development, and it doesn't support all features from ModSecurity.
Most ModSecurity methods are implemented via [pymodsecurity](https://github.com/AvalZ/pymodsecurity) (requires manual building -- [PR](https://github.com/pymodsecurity/pymodsecurity/pull/21) pending on the [official repository](https://github.com/pymodsecurity/pymodsecurity)), 

## Getting started

To run modsecurity-cli, you will need a few setup steps.

### Setup

1. Compile ModSecurity v3.0.10
1. Install pymodsecurity
1. Clone the [OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset) (or any other rule set)
1. Run the CLI!

Here's the detail for each step.

### Compile ModSecurity v3.0.10 
First of all, you will need to install pymodsecurity on your machine. Currently, this is a ~~nightmare~~tricky process, since you will need to [build ModSecurity v3.0.10 from source](https://github.com/spiderLabs/ModSecurity/#compilation)

### Install pymodsecurity

ModSecurity methods are implemented via [pymodsecurity](https://github.com/pymodsecurity/pymodsecurity).
Since development on the official repository stopped on ModSecurity v3.0.3, we opened a [PR](https://github.com/pymodsecurity/pymodsecurity/pull/21).

Current workaround: clone [our fork](https://github.com/AvalZ/pymodsecurity) and run this (it might take a while):

```
python3 setup.py install
```

### Clone the OWASP CoreRuleSet

Just run a clone in this folder
```
git clone git@github.com:coreruleset/coreruleset.git
```

### Run the CLI!

Check ModSecurity version

```
python3 main.py version
```

Evaluate a single parameter

```
python3 main.py evaluate parameter "<script>alert(1)</script>" -v
```

You can set a specific Paranoia Level for your evaluation (default is `1`)
```
python3 main.py evaluate parameter "<script>alert(1)</script>" -v -PL 2
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
 - [ ] Full URI evaluation
 - [ ] Support POST request evaluation

If you want to contribute by adding something from the list, PRs are welcome :D

## Contributors

 - Andrea Valenza (@AvalZ) -- avalenza89@gmail.com
 - Luca Demetrio (@zangobot) -- luca.demetrio@dibris.unige.it

