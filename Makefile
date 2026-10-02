.PHONY: install test verify first-demo serve demo clean

install:
	uv pip install --python $$(command -v python3) -r requirements.txt

test:
	python3 -m pytest

verify:
	python3 scripts/verify_live.py

# the first demo path: boots its own node on a free port, clean state, runs the
# whole vector, asserts it (P2.3 7/7) and prints the live contract the jury sees.
first-demo:
	python3 scripts/first_demo_path.py

serve:
	python3 -m warrnt serve --port 8099

demo:
	python3 scripts/demo_client.py http://127.0.0.1:8099

clean:
	rm -rf state .pytest_cache **/__pycache__
