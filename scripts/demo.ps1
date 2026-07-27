$ErrorActionPreference = "Stop"
.\.venv\Scripts\sentinelueba init
.\.venv\Scripts\sentinelueba generate-demo --seed 42
.\.venv\Scripts\sentinelueba train --seed 42
.\.venv\Scripts\sentinelueba detect
.\.venv\Scripts\sentinelueba status

