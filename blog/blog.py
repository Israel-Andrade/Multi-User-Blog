import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    """Function will display a specific format for our post"""
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
    """Our Main Page to render """
    def get(self):
        self.render("home-page.html")


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    """Obtain users information and storing them using the datastore """
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    """Information from our post """
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    #Adding the name of the original poster
    author = db.StringProperty()


    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(db.Model):
    """ Information from our comments """
    comment = db.TextProperty(required = True)
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br')
        return render_str('creatComment.html', c = self)

class BlogFront(BlogHandler):
    """Posting our post in the front of the blog """
    def get(self):
        posts = greetings = Post.all().order('-created')
        if posts == None:
            posts = greetings = Post.all().order('-created')

        self.render('front.html', posts = posts)


class AllComments(BlogHandler):
    """ Displaying all the comments from our post """
    def get(self):
        comments = greetings = Comment.all().order('-created')
        self.render('allOfComments.html', comments = comments)


class PostPage(BlogHandler):
    """ Posting a specific post to permalink page """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class PostComment(BlogHandler):
    """ Posting a specific comment """
    def get(self, post_id):
        key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

class NewPost(BlogHandler):
    """ Posting a new post """

    #If the user is loged in we will render a blog form
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")
    #The post method will post to our blog
    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = author)
            p.put()
            a = '/blog/%s' % str(p.key().id())
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    """ sign up for our blog """

    #Rendering the page that will ask the user information needed to create their profile
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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


class Register(Signup):
    """Registration form that inherited from sign up class """
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    """ Login form that will obtain the user information """
    def get(self):
        self.render('login-form.html')
    #The post method will obtain the users user name and password
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


class Logout(BlogHandler):
    """Login out from our blog """
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


class Delete(BlogFront):
    """This class is in charge of deleting a blog post created by the user"""
    def get(self): 
        post = Post.all().get()
        comments = Comment.all()
        #Grabing the instance of our blog
        #Rediring the an HTML page that will be delete a blog post
        #Also passing in the HTML file to render and the instance post to be
        #used in the HTML file
        self.render('delete-post.html', post = post)
        self.redirect('/blog/deleteAllComments')

        

class AddComment(BlogHandler):
    def get(self):
        if self.user:
            self.render("comment.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        comment = self.request.get('comment')
        author = self.user.name

        if comment:
            c = Comment(parent = blog_key(), comment = comment, author = author)
            c.put()
            self.redirect('/blog')
        else:
            error = "Please add a comment"
            self.render("comment.html", author = author, comment = comment, error=error)


class DeleteComment(BlogHandler):
    """This class is in charge of deleting a blog post created by the user"""
    def get(self): 
        #Grabing the instance of our blog
        comment_delete = Comment.all().get()
        #Rediring the an html page that will be delete a blog post
        #Also pasing in the HTML file to render and the instance post to be
        #used in the HTML file
        self.render('delete-comment.html', comment = comment_delete)

class DeleteAllComments(BlogHandler):
    def get(self):
        comments_delete = greetings = Comment.all().order('-created')
        self.render('delete-all-comments.html', comments = comments_delete)

class EditPost(BlogHandler):
    def get(self):
        post_to_edit = Post.all().get()
        self.render('edit-post.html', post = post_to_edit)

    def post(self):
        if not self.user:
            self.redirect('/login')
        post_to_edit = Post.all().get()
        content = self.request.get('content')
        subject = post_to_edit.subject
        author = post_to_edit.author

        if content:
            post_to_edit = Post(parent = blog_key(), subject = subject, content = content, author = author)
            Post.all().get().delete()
            post_to_edit.put()
            self.redirect('/blog')
        else:
            error = "content, please!"
            self.render("edit-post.html", subject = subject, post = post_to_edit, author = author, error=error)

class EditComment(BlogHandler):
    def get(self):
        comment_to_edit = Comment.all().get()
        self.render('edit-comment.html', comment = comment_to_edit)
    def post(self):
        if not self.user:
            self.redirect('/login')
        comment_to_edit = Comment.all().get()
        comment = self.request.get('comment')
        author = comment_to_edit.author
        if comment:
            comment_to_edit = Comment(parent = blog_key(), comment = comment, author = author)
            Comment.all().get().delete()
            comment_to_edit.put()
            self.redirect('/blog')
        else:
            error = "Comment, Please!"
            self.render("edit-comment.html", comment = comment, author = author)
        self.redirect('/blog')

#Our directory for our website
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/delete', Delete),
                               ('/blog/newComment', AddComment),
                               ('/blog/showComments', AllComments),
                               ('/blog/deleteComment', DeleteComment),
                               ('/blog/deleteAllComments', DeleteAllComments),
                               ('/blog/editpost', EditPost),
                               ('/blog/editcomment', EditComment),
                               ],
                              debug=True)