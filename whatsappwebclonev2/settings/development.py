from . base import *

# CORS CONFIGURATIONS
CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',
]

CSRF_TRUSTED_ORIGINS = [
    'http://localhost:3000',
]


DATABASES = {
    "default": {
        "ENGINE": config("POSTGRES_ENGINE"),
        "NAME": config("POSTGRES_DB"),
        "USER": config("POSTGRES_USER"),
        "PASSWORD": config("POSTGRES_PASSWORD"),
        "HOST": config("PG_HOST"),
        "PORT": config("PG_PORT"),
    }
}

# CELERY_BROKER_URL = config("CELERY_BROKER")
# CELERY_RESULT_BACKEND = config("CELERY_BACKEND")
# CELERY_TIMEZONE = "Africa/Lagos"