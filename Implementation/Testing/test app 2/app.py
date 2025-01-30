from flask import Flask, request, render_template, escape

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    event_onclick = ""
    event_onmouseover = ""
    event_onerror = ""
    attr_href = ""
    attr_onfocus = ""
    tag_script = ""
    tag_iframe = ""

    if request.method == "POST":
        unsafe_input = request.form.get("user_input", "")

        # Reflected XSS (Unsafe - For Testing ONLY)
        message = unsafe_input

        # Stored XSS (Insecure - For Testing ONLY)
        try:
            with open("stored_xss.txt", "a") as f:
                f.write(unsafe_input + "\n")
        except Exception as e:
            print(f"Error storing XSS: {e}")
        
        # Example event handlers (for demonstration)
        event_onclick = request.form.get("event_onclick", "")
        event_onmouseover = request.form.get("event_onmouseover", "")
        event_onerror = request.form.get("event_onerror", "")
        attr_href = request.form.get("attr_href", "")
        attr_onfocus = request.form.get("attr_onfocus", "")
        tag_script = request.form.get("tag_script", "")
        tag_iframe = request.form.get("tag_iframe", "")

    stored_messages = []
    try:
        with open("stored_xss.txt", "r") as f:
            stored_messages = f.readlines()
    except FileNotFoundError:
        pass

    return render_template("index.html", 
                           message=message, 
                           stored_messages=stored_messages,
                           event_onclick=event_onclick,
                           event_onmouseover=event_onmouseover,
                           event_onerror=event_onerror,
                           attr_href=attr_href,
                           attr_onfocus=attr_onfocus,
                           tag_script=tag_script,
                           tag_iframe=tag_iframe)

if __name__ == "__main__":
    app.run(debug=True)