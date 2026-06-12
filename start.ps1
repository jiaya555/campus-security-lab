[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:FLASK_APP = "app"
python -m flask init-db
python -m flask run --host 127.0.0.1 --port 5000
