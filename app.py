#!/usr/bin/python3
from bed import create_app, db, bcrypt
app = create_app()


if __name__ == "__main__":
    app.app_context().push()
    db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=5000)
