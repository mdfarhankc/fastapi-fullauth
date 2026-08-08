# Tortoise registers models under an app label; FullAuth's mixins reference
# "models.User" / "models.Role", so the label MUST be "models".
DATABASE_URL = "sqlite://fullauth_tortoise_demo.db"
MODELS_MODULE = "examples.tortoise_app.models"
