# ICS0027 - Secure web applications

Week 4 designs and starter code for a file encryption system and a password manager.

| Assignment | Design document | Starter and planned routes |
| --- | --- | --- |
| File encryption and management | [File manager design](file-manager/docs/DESIGN.md) | [File manager README](file-manager/README.md) |
| Password manager | [Password manager design](password-manager/docs/DESIGN.md) | [Password manager README](password-manager/README.md) |

Each design covers the architecture, OWASP Top 10:2025 threats, encryption and sessions. See [sources](docs/SOURCES.md) and [planned security tests](docs/ACCEPTANCE.md).

## Status

The submitted checkpoint 1 design remains in the repository. A local checkpoint 2 draft now implements the file manager's core flows. See [progress and limitations](file-manager/docs/PROGRESS.md). The password manager remains a starter. Do not use real secrets with either app.

## Run locally

Requires Python 3.12 or 3.13. From this repository directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python file-manager/manage.py migrate
python password-manager/manage.py migrate
python file-manager/manage.py init_file_key
python file-manager/manage.py runserver 127.0.0.1:8000
```

In a second terminal, activate the same environment and run:

```sh
python password-manager/manage.py runserver 127.0.0.1:8001
```

Open <http://127.0.0.1:8000/> and <http://127.0.0.1:8001/>. `/health/` returns JSON. Each app has its own database. Local HTTP is for development only; deployment requires HTTPS.

## Verify

```sh
python file-manager/manage.py check
python file-manager/manage.py test core
python password-manager/manage.py check
python password-manager/manage.py test core
```

Versions are pinned in `requirements.txt`. Direct dependencies are listed in `requirements.in`. Review updates before changing the lock. See [test results](docs/VERIFICATION.md).

## Submission

[submission.txt](submission.txt) records the repository already submitted for checkpoint 1. Checkpoint 2 adds the file manager implementation and tests. Publishing the repository does not submit the Moodle assignment. Lecture materials are cited but not included.
