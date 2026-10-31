"""
PyGuard Web Dashboard – Flask application.

Serves the web dashboard UI and registers the REST API blueprint.
Launch with: python -m pyguard web
"""

from flask import Flask
import logging

from pyguard.web.api import api


def create_app():
    """Create and configure the Flask application."""
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )
    app.config["JSON_SORT_KEYS"] = False

    @app.context_processor
    def inject_current_year():
        from datetime import datetime
        return {"year": datetime.now().year}

    # Register API blueprint
    app.register_blueprint(api)

    # Public product pages
    @app.route("/")
    def home():
        from flask import render_template
        return render_template("home.html")

    @app.route("/about")
    def about():
        from flask import render_template
        return render_template("about.html")

    # Keep the existing dashboard available at a stable, explicit URL.
    @app.route("/dashboard")
    def index():
        from flask import render_template
        return render_template("dashboard.html")

    return app


def run_dashboard(host="0.0.0.0", port=5000, debug=False):
    """Run the web dashboard server."""
    app = create_app()
    print(f"\n  PyGuard Web Dashboard running at http://localhost:{port}\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
