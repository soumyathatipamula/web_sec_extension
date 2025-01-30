from flask import Flask, request, escape

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    if request.method == "POST":
        name = request.form.get("name", "")  # Get the name from the form
        # Vulnerable code: Directly embedding user input
        message = f"Hello, {name}!"  # Vulnerable to XSS

        # More secure approach (using escape):
        # message = f"Hello, {escape(name)}!" #Escaping using escape() function


    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test Page</title>
    </head>
    <body>
        <h1>XSS Test</h1>

        <form method="POST">
            <label for="name">Enter your name:</label>
            <input type="text" name="name" id="name">
            <input type="submit" value="Submit">
        </form>

        <p>{message}</p>  </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)  # debug=True for easier development