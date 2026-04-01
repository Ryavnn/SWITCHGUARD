from database.db import engine
from sqlalchemy import inspect

inspector = inspect(engine)
results = []
for table_name in inspector.get_table_names():
    results.append(f"Table: {table_name}")
    for column in inspector.get_columns(table_name):
        results.append(f"  - {column['name']}")

print("\n".join(results))
