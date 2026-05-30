from flask import Flask, request, render_template_string, redirect  # type: ignore

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        name = request.form.get("name", "")
        template = "<p>Hello, " + name + "!</p>"
        result = render_template_string(template)
    return render_template_string("""<html><body>
<h2>Greeting App (SSTI)</h2>
<form method="POST">
  Name: <input type="text" name="name" value="">
  <input type="submit" value="Submit">
</form>
{{ result|safe }}
</body></html>""", result=result)

@app.route("/xxe", methods=["GET", "POST"])
def xxe():
    result = ""
    if request.method == "POST":
        content = request.form.get("xmldata", "")
        try:
            from lxml import etree  # type: ignore
            parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
            tree = etree.fromstring(content.encode("utf-8", errors="replace"), parser)
            result = etree.tostring(tree, encoding="unicode")
        except Exception as e:
            result = str(e)
    return render_template_string("""<html><body>
<h2>XML Parser (XXE)</h2>
<form method="POST">
  XML: <textarea name="xmldata" rows="8" cols="60">{{ default_xml }}</textarea><br>
  <input type="submit" value="Parse">
</form>
<pre>{{ result }}</pre>
</body></html>""", result=result,
    default_xml="<?xml version=\"1.0\"?><root><item>test</item></root>")

@app.route("/redirect", methods=["GET", "POST"])
def open_redirect():
    url = request.form.get("url", "") or request.args.get("url", "")
    if url:
        return redirect(url)
    return render_template_string("""<html><body>
<h2>URL Redirect</h2>
<form method="POST">
  URL: <input type="text" name="url" value="">
  <input type="submit" value="Go">
</form>
</body></html>""")

@app.route("/register", methods=["GET", "POST"])
def register():
    # Fallo logico: acepta cualquier valor (edad vacia, negativa o no numerica)
    # sin ninguna validacion y responde siempre con exito.
    msg = ""
    if request.method == "POST":
        msg = "<p>Registro completado con exito. Bienvenido al sistema.</p>"
    return render_template_string("""<html><body>
<h2>Registro de usuario (Logic)</h2>
<form method="POST">
  Edad: <input type="text" name="age" value="">
  <input type="submit" value="Registrar">
</form>
{{ msg|safe }}
<p>Formulario de registro de la aplicacion de prueba.</p>
</body></html>""", msg=msg)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
