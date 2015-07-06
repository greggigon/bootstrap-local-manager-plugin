.PHONY: release install files test docs prepare publish

all:
	@echo "make release - prepares a release and publishes it"
	@echo "make dev - prepares a development environment"
	@echo "make install - install on local system"
	@echo "make files - update changelog and todo files"
	@echo "make test - run tox"
	@echo "make docs - build docs"
	@echo "prepare - prepare module for release (CURRENTLY IRRELEVANT)"
	@echo "make publish - upload to pypi"

release: test docs publish

clean:
	rm -rf dist/ build/ bootstrap_local_manager_plugin.egg-info

dev:
	pip install -rdev-requirements.txt
	python setup.py develop

install:
	python setup.py install

files:
	grep '# TODO' -rn * --exclude-dir=docs --exclude-dir=build --exclude=TODO.md | sed 's/: \+#/:    # /g;s/:#/:    # /g' | sed -e 's/^/- /' | grep -v Makefile > TODO.md
	git log --oneline --decorate --color > CHANGELOG

test:
	pip install tox
	tox

docs:
	pip install sphinx sphinx-rtd-theme
	cd docs && make html
	pandoc README.md -f markdown -t rst -s -o README.rst

prepare:
	python scripts/make-release.py

publish:
	python setup.py sdist upload

bac:
	CURRENT=`pwd`
	python setup.py sdist --format=zip
	cp -f dist/bootstrap-local-manager-plugin-1.2.zip ~/tmp/
	cp -f plugin.yaml ~/tmp/bootstrap-local-manager-plugin-1.2.yaml
	-pip uninstall bootstrap-local-manager-plugin==1.2 -y
	cd ~/projects/cloudify-manager-blueprints/local && cfy init -r \
		&& cfy local install-plugins -p simple-manager-blueprint.yaml
