PYTHON ?= python3
APP_NAME ?= syslog-analyzer
ENTRYPOINT := syslog_analyzer/__main__.py
SPEC_FILE := $(APP_NAME).spec
BUILD_VENV := .build-venv

.PHONY: build-exe clean

$(BUILD_VENV)/bin/python:
	$(PYTHON) -m venv $(BUILD_VENV)
	$(BUILD_VENV)/bin/python -m pip install --upgrade pip
	$(BUILD_VENV)/bin/python -m pip install -e '.[build]'

build-exe: $(BUILD_VENV)/bin/python
	$(BUILD_VENV)/bin/python -m PyInstaller --noconfirm --clean --onefile --name $(APP_NAME) $(ENTRYPOINT)

clean:
	rm -rf $(BUILD_VENV) build dist $(SPEC_FILE)
