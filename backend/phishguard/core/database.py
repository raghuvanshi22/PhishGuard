from motor.motor_asyncio import AsyncIOMotorClient
from phishguard.core.config import settings
from phishguard.core.logger import logger

class Database:
    client: AsyncIOMotorClient = None
    db = None

    def connect(self):
        try:
            self.client = AsyncIOMotorClient(settings.MONGO_URI)
            self.db = self.client[settings.MONGO_DB_NAME]
            logger.info(f"Connected to MongoDB at {settings.MONGO_URI}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise e

    def close(self):
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed.")

db = Database()

async def get_database():
    return db.db
