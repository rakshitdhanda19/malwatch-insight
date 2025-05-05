import secrets

# Generate and store secret keys
SECRET_KEY = secrets.token_urlsafe(64)
JWT_SECRET_KEY = secrets.token_urlsafe(64)

# Optionally print or log the keys for development (not recommended for production)
print("SECRET_KEY:", SECRET_KEY)
print("JWT_SECRET_KEY:", JWT_SECRET_KEY)
