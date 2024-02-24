build: ; docker compose build
lint: ; docker compose run --rm escher pycodestyle --ignore=E501 escherauth
test: ; docker compose run --rm escher nose2
