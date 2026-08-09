XSS_PAYLOAD_TEMPLATES = [
    # --- Contexto: texto plano en el cuerpo del HTML ---
    {
        "context": "html_body",
        "template": "<script>/*{marker}*/</script>",
        "detect_raw": "<script>/*{marker}*/</script>",
        "explanation": (
            "Si esto se refleja TAL CUAL (con los símbolos < > sin "
            "convertir a &lt; &gt;), el navegador ejecutaría el script."
        ),
    },
    {
        "context": "html_body_img",
        "template": "<img src=x onerror=\"/*{marker}*/\">",
        "detect_raw": "onerror=\"/*{marker}*/\"",
        "explanation": (
            "Vector alternativo sin la palabra 'script', útil cuando el "
            "servidor filtra específicamente la etiqueta <script> pero "
            "no otros vectores de ejecución (onerror, onload, etc.)."
        ),
    },
    # --- Contexto: dentro de un atributo HTML, p.ej. value="AQUI" ---
    {
        "context": "html_attribute",
        "template": "\" onmouseover=\"/*{marker}*/",
        "detect_raw": "onmouseover=\"/*{marker}*/",
        "explanation": (
            "Cierra las comillas del atributo original e inyecta un "
            "nuevo atributo de evento. Si el servidor no escapa las "
            "comillas dobles, esto queda como HTML ejecutable."
        ),
    },
    # --- Contexto: dentro de un bloque <script> ya existente ---
    {
        "context": "js_string",
        "template": "';/*{marker}*/;'",
        "detect_raw": "';/*{marker}*/;'",
        "explanation": (
            "Cierra un string de JavaScript ya abierto (comilla simple) "
            "para poder inyectar código JS adicional."
        ),
    },
]
