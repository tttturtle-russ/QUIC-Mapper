check:
	pylint --rcfile pylintrc config/*py automata/*py automaton2dot.py
	pytest

coverage:
	pytest --no-pylint --cov-report html
