# Point at your MongoDB. The demo uses a local server; any MongoDB URI works,
# including MongoDB Atlas. No replica set is required - refresh-token rotation
# stays atomic via single-document compare-and-swap.
MONGO_URL = "mongodb://localhost:27017"
DATABASE_NAME = "fullauth_beanie_demo"
