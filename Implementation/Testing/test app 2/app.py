from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    user_input = ""
    if request.method == "POST":
        user_input = request.form.get("payload", "")

    # Reflecting user input directly without sanitization (XSS vulnerability)
    return render_template_string(f"""
        <!DOCTYPE html>
        <html>
        <head><title>XSS Vulnerability Test</title></head>
        <body>
            <h2>XSS Test Page</h2>
            <form method="post">
                <input type="text" name="payload" placeholder="Enter XSS Payload">
                <button type="submit">Submit</button>
            </form>
            <h3>Reflected Output:</h3>
            <div>{user_input}</div> <!-- Vulnerable reflection -->
        </body>
        </html>
    """)

if __name__ == "__main__":
    app.run(debug=True)
