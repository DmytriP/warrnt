.PHONY: install test verify first-demo serve demo console-check console-shot clean

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

# the console screen (IN-6): is it served, does it read the node's fields, does the kill
# button's own request produce a halt the state confirms. 35 checks, non-zero on failure.
console-check:
	python3 scripts/console_check.py

# render the live screen to PNG (Design evidence) - boots its own node, runs the vector.
console-shot:
	python3 scripts/console_shot.py --outdir state/shots

clean:
	rm -rf state .pytest_cache **/__pycache__
