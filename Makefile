PYTHON ?= python3
APP_NAME ?= syslog-analyzer
ENTRYPOINT := syslog_analyzer/__main__.py
SPEC_FILE := $(APP_NAME).spec

.PHONY: build-exe clean

build-exe:
	$(PYTHON) -m pip install pyinstaller
	$(PYTHON) -m PyInstaller --noconfirm --clean --onefile --name $(APP_NAME) $(ENTRYPOINT)

clean:
	rm -rf build dist $(SPEC_FILE)
