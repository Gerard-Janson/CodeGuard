# CodeGuard

A unified security scanner that runs Semgrep, Trivy, and Gitleaks against local codebases or public Git repositories, merging their output into a single prioritized report.

## Requirements
 
- Python 3.9+
- [Semgrep](https://semgrep.dev/), [Trivy](https://trivy.dev/), and [Gitleaks](https://gitleaks.io/) available on `PATH`
- Git 

--
 
## Project structure
 
```
codeguard/
├── cli.py                   
├── scanners/
│   ├── semgrep_runner.py   
│   ├── trivy_runner.py
│   └── gitleaks_runner.py
├── findings/
│   ├── schema.py          
│   ├── adapters.py          
│   └── merge.py             
├── repo/
│   └── clone.py             
└── report/
    └── terminal.py         
```
 
---

## Windows installation
```bash
git clone git@github.com:Gerard-Janson/CodeGuard.git
cd CodeGuard
python -m venv venv

# Activate the environment:
# Command Prompt:
venv\Scripts\activate.bat
# PowerShell:
venv\Scripts\Activate.ps1

pip install -e .
```

## Linux installation
```bash
git clone git@github.com:Gerard-Janson/CodeGuard.git
cd CodeGuard
python -m venv venv

# Activate the environment:
source .venv/bin/activate

pip install -e .
```


## Run
```bash
codeguard
```
If the `codeguard` command isn't found, run it as a module instead:
 
```bash
python -m codeguard.cli
```

## WTC Tracking Code
WTC-6BKNSM38

## License
 
MIT — see [LICENSE](LICENSE).