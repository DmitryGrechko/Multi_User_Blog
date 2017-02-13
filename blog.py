import os
import re
from string import letters
import random
import string
import hashlib
import hmac
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Secret for hashing is generated via Python random and string functions

file = open('secret.txt', 'r’)
SECRET = file.read()


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# BlogHandler for Unit 2 & Unit 3


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

        # Handling cookies

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

        # Login & Logout Functions

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# Cookies Count - Substituted it for "Hello, Udacity" page


class MainPage(BlogHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)

        visits += 1

        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header(
            'Set-Cookie', 'visits=%s' % new_cookie_val)

        if visits > 1000:
            self.write("You're the best ever!")
        else:
            self.write("You've been here %s times!" % visits)

# Database for Users


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Blog (Unit 2 & 3)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Database for posts


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty()
    likes = db.IntegerProperty(default=0)

    @property
    def like_count(likes):
        return likes.length

    def render(self):
        comments = Comment.all().filter('post_id =', self).order('-created')
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self, comments=comments)

# Database for comments


class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post_id = db.ReferenceProperty(Post)
    name = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p=self)


class Likes(db.Model):
    name = db.StringProperty(required=True)
    post_id = db.IntegerProperty()
    comment_id = db.IntegerProperty()


class BlogFront(BlogHandler):

    # renders logid-in username and posts into front.html

    def get(self):
        if self.user:
            author = self.user.name
            posts = db.GqlQuery(
                "select * from Post order by created desc limit 10")
            self.render('front.html', posts=posts, author=author)
        else:
            self.redirect("/login")


class PostPage(BlogHandler):

    # Post preview after submission

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post)


class LikePost(BlogHandler):

    # Like functionality

    def post(self, post_id):
        if not self.user:
            return self.redirect("/login")

        name = self.user.name
        q = db.Query(Likes)
        q.filter('post_id =', int(post_id)).filter('name =', name)
        for p in q.run():
            return self.redirect('/blog')

        id = int(post_id)
        l = Likes(name=name, post_id=id)
        l.put()
        key = db.Key.from_path("Post", id, parent=blog_key())
        posts = db.get(key)
        if self.user.name != posts.author:
            if posts is None:
                return self.redirect('/blog')

            if posts.likes is None:
                posts.likes = 1
            else:
                posts.likes += 1
            posts.put()
            self.redirect('/blog')
        else:
            self.redirect('/blog')


class EditPost(BlogHandler):

    # Edit post (checks whether a user loged in, post exists, and permission)

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            if not post:
                self.error(404)
                return
            elif self.user.name == post.author:
                author = post.author
                self.render("editpost.html", post=post, author=author)
            else:
                self.redirect("/editposterror")
        else:
            self.redirect("/login")

    # Updates changed information in the datatbase

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')

        if subject and content:
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')
            post.put()
            self.redirect('/blog')
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error, author=author)


class EditPostError(BlogHandler):

    # Error page for users trying to edit/delete others' content

    def get(self):
        self.render("editposterror.html")


class DeletePost(BlogHandler):

    # Deletes post (checks whether a user loged in, post exists, and
    # permission)

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            if not post:
                self.error(404)
                return
            elif self.user.name == post.author:
                author = post.author
                self.render("deletepost.html", post=post, author=author)
            else:
                self.redirect("/editposterror")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        db.delete(key)
        self.redirect("/blog")


class NewPost(BlogHandler):

    # Creates New Post and Saves the author's name into db

    def get(self):
        if self.user:
            author = self.user.name
            self.render("newpost.html", author=author)
        else:
            self.redirect("/login")

    def post(self):

        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            author = self.user.name
            if subject and content:
                p = Post(parent=blog_key(), subject=subject,
                         content=content, author=author)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject,
                            content=content, error=error, author=author)
        else:
            self.redirect("/login")

    # Comments


class NewComment(BlogHandler):

    # Creates New Comment and Saves the author's name into db

    def get(self, post_id):
        if self.user:
            name = self.user.name
            self.render("newcomment.html", name=name, postId=post_id)
        else:
            self.redirect("/login")

    def post(self, post_id):

        if self.user:
            content = self.request.get('content')
            name = self.user.name
            created = self.request.get('created')

            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            posts = db.get(key)

            if posts is None:
                return self.redirect('/blog')

            if content:
                c = Comment(content=content, name=name, post_id=posts)
                c.put()
                self.redirect('/blog')
            else:
                error = "Write a comment, please!"
                self.render("newcomment.html", content=content, error=error)
        else:
            self.redirect("/login")


class EditComment(BlogHandler):

    # Updates changed Comment information in the datatbase

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id))
            comments = db.get(key)
            if not comments:
                self.error(404)
                return
            elif self.user.name == comments.name:
                name = comments.name
                self.render("editcomment.html", comments=comments, name=name)
            else:
                self.redirect("/editcommenterror")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Comment', int(post_id))
        comments = db.get(key)

        if not self.user:
            self.redirect('/blog')

        content = self.request.get('content')

        if content:
            comments.content = content
            comments.put()
            self.redirect('/blog')
        else:
            error = "You haven't written your comment!!"
            self.render("editcomment.html", content=content,
                        error=error)


class EditCommentError(BlogHandler):

    # Error page for users trying to edit/delete others' content

    def get(self):
        self.render("editcommenterror.html")


class DeleteComment(BlogHandler):

    # Deletes the Comment info from db
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id))
            comments = db.get(key)
            if not comments:
                self.error(404)
                return
            elif self.user.name == comments.name:
                name = comments.name
                self.render("deletecomment.html", comments=comments, name=name)
            else:
                self.redirect("/editcommenterror")
        else:
            self.redirect("/login")

    def post(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comments = db.get(key)
            comments.delete()
            self.redirect('/blog/')

# Unit 2 HomeWork (ROT13)


class Rot13(BlogHandler):

    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)

# Unit 2 Homework (Blog)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):

    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Welcome(BlogHandler):

    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')

# Unit 3 HomeWork (Blog)


class Register(Signup):
    # Checks if the User already exists

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')


class Unit3Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

# Unit 3 HomeWork - User & Security


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt(len=5):
    return ''.join(random.choice(string.letters) for x in xrange(len))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/editposterror', EditPostError),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/newcomment/([0-9]+)', NewComment),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/editcommenterror', EditCommentError),
                               ], debug=True)
