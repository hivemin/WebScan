"""
tests/vulnerable_test_server.py
Uso:
    python tests/vulnerable_test_server.py
    # sirve en http://127.0.0.1:5000

Endpoint vulnerable:
    GET /product?id=1   -> concatena 'id' directamente en la query SQL
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE products (id INTEGER, name TEXT, secret TEXT)")
    conn.execute("INSERT INTO products VALUES (1, 'Widget', 'top-secret-value')")
    conn.execute("INSERT INTO products VALUES (2, 'Gadget', 'another-secret')")
    conn.commit()
    return conn

@app.route("/product")
def product():
    product_id = request.args.get("id", "1")
    conn = get_db()
    # VULNERABLE A PROPÓSITO: concatenación directa, sin parametrizar.
    query = f"SELECT id, name FROM products WHERE id = {product_id}"
    try:
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        return {"query_used": query, "results": rows}
    except sqlite3.OperationalError as e:
        # Refleja el error de BD en la respuesta (típico de apps mal
        # configuradas) para poder probar la detección error-based.
        return {"error": f"sqlite3.OperationalError: {e}"}, 500

@app.route("/product_safe")
def product_safe():
    # Versión corregida, para comparar: el scanner NO debería marcar esto.
    product_id = request.args.get("id", "1")
    conn = get_db()
    cursor = conn.execute("SELECT id, name FROM products WHERE id = ?", (product_id,))
    rows = cursor.fetchall()
    return {"results": rows}

if __name__ == "__main__":
    app.run(port=5000, debug=False)
