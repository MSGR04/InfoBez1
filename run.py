"""Development entry point: python run.py"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Bind to localhost only; debug mode is never enabled (it allows code execution).
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
