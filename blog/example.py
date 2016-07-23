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




class BlogFront(BlogHandler):
    """Posting our post in the front of the blog """
    def get(self):
        posts = greetings = Post.all().order('-created')

        self.render('front.html', posts = posts)




class PostPage(BlogHandler):
    """ Posting a specific post to permalink page """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)



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
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class Delete(BlogFront):
    """This class is in charge of deleting a blog post created by the user"""


    def get(self): 
       # post = Post.all().get()
        #Grabing the instance of our blog
        #Rediring the an HTML page that will be delete a blog post
        #Also passing in the HTML file to render and the instance post to be
        #used in the HTML file
        """
        key = self.x
        for x in posts:
                if x == key:
                    self.render('delete-post.html', post = x)
                    return
                else:
                    self.render('delete-post.html', post = key)
                    return
                    """
        self.render('delete-post.html', post = key)



class DeleteComment(BlogHandler):
    """This class is in charge of deleting a blog post created by the user"""
    def get(self, post_id): 
        #Grabing the instance of our blog
        comment_delete = Comment.all().get()
        #Rediring the an html page that will be delete a blog post
        #Also pasing in the HTML file to render and the instance post to be
        #used in the HTML file
        self.render('delete-comment.html', comment = comment_delete)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/delete/([0-9]+)', Delete),
                               ('/blog/newComment', AddComment),
                               ('/blog/showComments', AllComments),
                               ('/blog/deleteComment', DeleteComment),
                               ('/blog/editpost', EditPost),
                               ],
                              debug=True)