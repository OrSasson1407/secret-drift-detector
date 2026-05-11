from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
import sqlite3
import json

app = FastAPI(title='Secret Drift Detector API')

# Allow our React frontend to fetch data
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

metrics_app = make_asgi_app()
app.mount('/metrics', metrics_app)

@app.get('/api/v1/history')
def get_history(limit: int = 10):
    try:
        with sqlite3.connect('drift_history.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM runs ORDER BY id DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            
            results = []
            for r in rows:
                row_dict = dict(r)
                row_dict['report_json'] = json.loads(row_dict['report_json'])
                results.append(row_dict)
                
            return results
    except sqlite3.OperationalError:
        return {'error': 'Database not initialized yet.'}
