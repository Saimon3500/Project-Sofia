import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

async def init_records():
    uri = os.getenv("MONGODB_URI")
    db_name = os.getenv("MONGODB_DB", "Sofia_App")
    
    if not uri:
        print("Error: MONGODB_URI not found in environment variables.")
        print("Please ensure you have a .env file with MONGODB_URI set.")
        return

    print(f"Connecting to database: {db_name}")
    client = AsyncIOMotorClient(uri)
    db = client[db_name]
    collection = db["registros"]

    records = [
        {"nombre": "Trazabilidad", "codigo": "PO-PP-33"},
        {"nombre": "Liberacion", "codigo": "PO-PP-33-1"}
    ]

    print("Initializing records...")
    for record in records:
        try:
            result = await collection.update_one(
                {"codigo": record["codigo"]},
                {"$set": record},
                upsert=True
            )
            
            if result.upserted_id:
                print(f"  [+] Inserted: {record['nombre']} ({record['codigo']})")
            elif result.modified_count > 0:
                print(f"  [*] Updated: {record['nombre']} ({record['codigo']})")
            else:
                print(f"  [=] Already exists: {record['nombre']} ({record['codigo']})")
        except Exception as e:
            print(f"  [!] Error processing {record['nombre']}: {e}")

    print("Records initialization complete.")
    client.close()

if __name__ == "__main__":
    asyncio.run(init_records())
