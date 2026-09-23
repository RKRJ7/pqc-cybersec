# ===========================================================================
# views.py — single shared HTML shell. VIVA MAP:
#   * page(title, content) wraps every route's body in the same
#     <!DOCTYPE html> + <head> (charset + /public/style.css) + centered
#     .wrapper > .card layout. That is why all pages "look the same".
#   * VIVA: NO crypto here — styling/structure only. The PQC look (headings
#     like "ML-KEM-768", .pqc labels) comes from the `content` strings built
#     in app.py; this file only frames them. Unchanged by the PQC migration.
# ===========================================================================

def page(title: str, content: str) -> str:
    # VIVA: f-string template; {title} goes to <title>, {content} is the
    # per-route card body (forms, message-box divs, inline <script> tags).
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title} - Classmate Hub</title>
  <link rel="stylesheet" href="/public/style.css">
</head>
<body>
  <div class="wrapper">
    <div class="card">
      {content}
    </div>
  </div>
</body>
</html>"""
