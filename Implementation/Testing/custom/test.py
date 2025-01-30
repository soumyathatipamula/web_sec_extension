from flask import Flask, request, render_template, escape

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    if request.method == "POST":
        # Reflected XSS (Demonstration - DO NOT DO THIS IN PRODUCTION)
        # In a real application, you MUST sanitize user input!
        unsafe_input = request.form.get("user_input", "")
        #message = f"You entered: {unsafe_input}"  # Vulnerable - DO NOT DO THIS
        message = f"You entered: {escape(unsafe_input)}" # Safer - Escaping output

        # Stored XSS (Demonstration - DO NOT DO THIS IN PRODUCTION)
        # In a real application, you MUST sanitize user input before storing it!
        try:
            with open("stored_xss.txt", "a") as f:  # Insecure storage for demo
                f.write(unsafe_input + "\n")
        except Exception as e:
            print(f"Error storing XSS: {e}")


    # Display stored XSS (Demonstration - DO NOT DO THIS IN PRODUCTION)
    stored_messages = []
    try:
        with open("stored_xss.txt", "r") as f:
            stored_messages = f.readlines()
    except FileNotFoundError:
        pass

    return render_template("index.html", message=message, stored_messages=stored_messages)

if __name__ == "__main__":
    app.run(debug=True)