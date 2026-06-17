"""
secure-ai-pipeline:rule-source — excluded from the built-in scan.

Vendored lists of the most-downloaded / most-typosquatted PyPI and npm package
names. Used by the slopsquatting guard's near-miss (Damerau-Levenshtein) check to
flag an installed package that is 1-2 edits from a hugely popular one — the classic
typosquat shape ('requets' -> 'requests', 'python-dateutil' -> 'pyhton-dateutil').

Names are normalised (lowercase, '-'->'_') to match the guard's comparison. This
is a high-value subset, not exhaustive; extend it freely.

stdlib only (plain data).
"""

# Normalised (lowercase, hyphens->underscores).
POPULAR_PYPI = {
    "requests", "urllib3", "setuptools", "certifi", "charset_normalizer", "idna",
    "six", "python_dateutil", "boto3", "botocore", "s3transfer", "numpy", "pandas",
    "scipy", "pyyaml", "packaging", "wheel", "pip", "cryptography", "jinja2",
    "markupsafe", "click", "flask", "django", "fastapi", "starlette", "pydantic",
    "sqlalchemy", "werkzeug", "itsdangerous", "aiohttp", "httpx", "requests_oauthlib",
    "oauthlib", "pytz", "tzdata", "attrs", "importlib_metadata", "zipp", "wrapt",
    "pillow", "matplotlib", "scikit_learn", "tensorflow", "torch", "transformers",
    "openai", "anthropic", "langchain", "tqdm", "rich", "typer", "colorama",
    "beautifulsoup4", "lxml", "selenium", "pytest", "coverage", "tox", "mypy",
    "black", "flake8", "isort", "pylint", "redis", "celery", "psycopg2", "psycopg2_binary",
    "pymongo", "elasticsearch", "kafka_python", "pika", "grpcio", "protobuf",
    "google_api_python_client", "boto", "awscli", "paramiko", "bcrypt", "passlib",
    "pyjwt", "stripe", "twilio", "sendgrid", "sentry_sdk", "gunicorn", "uvicorn",
    "gevent", "greenlet", "websockets", "python_dotenv", "pyparsing", "more_itertools",
    "cachetools", "tenacity", "filelock", "platformdirs", "virtualenv", "poetry",
    "opencv_python", "scikit_image", "sympy", "networkx", "joblib", "nltk", "spacy",
}

POPULAR_NPM = {
    "react", "react_dom", "lodash", "axios", "express", "chalk", "commander",
    "debug", "request", "moment", "async", "bluebird", "underscore", "webpack",
    "babel_core", "typescript", "eslint", "prettier", "jest", "mocha", "chai",
    "vue", "angular", "next", "nuxt", "vite", "rollup", "esbuild", "tslib",
    "rxjs", "redux", "react_redux", "styled_components", "tailwindcss", "postcss",
    "dotenv", "cors", "body_parser", "cookie_parser", "morgan", "helmet",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "mongoose", "mongodb", "pg",
    "mysql", "mysql2", "sequelize", "knex", "redis", "ioredis", "socket_io",
    "ws", "node_fetch", "got", "superagent", "uuid", "nanoid", "classnames",
    "prop_types", "yargs", "inquirer", "ora", "glob", "rimraf", "fs_extra",
    "minimist", "semver", "chokidar", "nodemon", "ts_node", "dayjs", "date_fns",
    "zod", "yup", "formik", "react_router", "react_router_dom", "graphql", "apollo_client",
    "stripe", "twilio", "aws_sdk", "firebase", "winston", "pino", "joi", "ajv",
}


def popular_for(registry: str) -> set:
    return POPULAR_PYPI if registry == "pypi" else POPULAR_NPM
