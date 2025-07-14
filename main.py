# JADE ULTIMATE - State-of-the-Art AI Security Platform 2025
# Main application entry point

from app import app
import routes  # Import routes to register them

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
