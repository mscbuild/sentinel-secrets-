from datetime import datetime
from html import escape

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secret Scanner Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f5f7fa;
            padding: 20px;
        }}
        h1 {{
            color: #c0392b;
        }}
        .meta {{
            margin-bottom: 20px;
            color: #555;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #fff;
        }}
        th, td {{
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #2c3e50;
            color: #fff;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .low {{
            color: #27ae60;
            font-weight: bold;
        }}
    </style>
</head>
<body>

<h1>🚨 Secret Scanner Report</h1>

<div class="meta">
    <p><strong>Date:</strong> {date}</p>
    <p><strong>Total findings:</strong> {count}</p>
</div>

<table>
    <thead>
        <tr>
            <th>File</th>
            <th>Line</th>
            <th>Type</th>
            <th>Risk</th>
        </tr>
    </thead>
    <tbody>
        {rows}
    </tbody>
</table>

</body>
</html>
"""

def risk_level(secret_type):
    if secret_type == "HIGH_ENTROPY":
        return "medium"
    return "high"

def generate_html_report(findings, path="report.html"):
    rows = ""

    for item in findings:
        risk = risk_level(item["type"])
        rows += f"""
        <tr>
            <td>{escape(item['file'])}</td>
            <td>{item['line']}</td>
            <td>{escape(str(item['type']))}</td>
            <td class="{risk}">{risk.upper()}</td>
        </tr>
        """

    html = HTML_TEMPLATE.format(
        date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        count=len(findings),
        rows=rows
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
