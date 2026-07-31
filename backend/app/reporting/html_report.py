import os
from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
# nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
# autoescape is correctly enabled for html and j2 templates via select_autoescape.
_env = Environment(  # nosemgrep
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(
    enabled_extensions=("html", "htm", "xml", "j2"),
    default_for_string=True,
    )
)

def render_html_report(context: dict) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(**context) # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
