.PHONY: install test verify serve demo clean

install:
	uv pip install --python $$(command -v python3) -r requirements.txt

test:
	python3 -m pytest

verify:
	python3 scripts/verify_live.py

serve:
	python3 -m warrnt serve --port 8099

demo:
	python3 scripts/demo_client.py http://127.0.0.1:8099

clean:
	rm -rf state .pytest_cache **/__pycache__
