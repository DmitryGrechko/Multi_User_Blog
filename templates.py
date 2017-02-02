import webapp2
import cgi


def escape_html(s):
    return cgi.escape(s, quote=True)

form = """
<!DOCTYPE html>
<html>
    <head>
        <title> ROT13 </title>
    </head>
    <body>
        <h2>
          Enter some text to ROT13:
        </h2>
        <form method="post">
            <textarea name="text" style="height: 100px;
            width: 400px;">%(rot)s</textarea>
            <br>
            <input type="submit">
        </form>
    </body>
</html>
"""


import rot13


class MainPage(webapp2.RequestHandler):

    def write_form(self, message):
        self.response.out.write(form % {"rot": escape_html(message)})

    def get(self):
        self.write_form("")

    def post(self):
        textarea_text = self.request.get('text')
        text = rot13.conv(textarea_text)
        self.write_form(text)

app = webapp2.WSGIApplication([('/', MainPage),
                               ],
                              debug=True)

#template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
#                               autoescape=True)
#
#
# class Handler(webapp2.RequestHandler):
#
#    def write(self, *a, **kw):
#        self.response.out.write(*a, **kw)
#
#    def render_str(self, template, **params):
#        t = jinja_env.get_template(template)
#        return t.render(params)
#
#    def render(self, template, **kw):
#        self.write(self.render_str(template, **kw))
#
#
# class MainPage(Handler):
#
#    def post(self):
#        self.render("rot.html", items=items)
#
# app = webapp2.WSGIApplication([('/', MainPage),
#                               ],
#                              debug=True)
