PYTHON ?= python3
VENV   ?= .venv

.PHONY: setup scan arp test clean

setup: $(VENV)/.deps-installed

$(VENV)/.deps-installed: requirements.txt requirements-dev.txt
	test -x $(VENV)/bin/python || $(PYTHON) -m venv $(VENV)
	$(VENV)/bin/python -m pip install --quiet --upgrade pip
	$(VENV)/bin/python -m pip install --quiet -r requirements-dev.txt
	touch $@

scan: setup            ## ping-sweep scan, no sudo needed
	$(VENV)/bin/python -m netmon scan

arp: setup             ## ARP scan (requires sudo)
	sudo $(VENV)/bin/python -m netmon scan --method arp

test: setup
	$(VENV)/bin/python -m pytest

clean:
	rm -rf $(VENV) .pytest_cache netmon.db reports/*.md
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
