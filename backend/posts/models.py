from django.db import models
from django.conf import settings


class Post(models.Model):
    """
    Blog/Forum post model
    Demonstrates public/private content patterns
    """
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='posts'
    )
    title = models.CharField(max_length=255, verbose_name="Başlık")
    content = models.TextField(verbose_name="Gövde")
    is_published = models.BooleanField(default=True, verbose_name="Yayınlanmış mı?")
    created_at = models.DateTimeField(auto_now_add=True,verbose_name="Oluşturulma Tarihi")
    updated_at = models.DateTimeField(auto_now=True,verbose_name="Güncellenme Tarihi")

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['author', '-created_at']),
        ]

    def __str__(self):
        return self.title


class Comment(models.Model):
    """
    Comment model for posts
    Optional: Demonstrates nested relationships
    """
    post = models.ForeignKey(
        Post,
        on_delete=models.CASCADE,
        related_name='comments'
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='comments'
    )
    content = models.TextField(verbose_name="Gövde")
    created_at = models.DateTimeField(auto_now_add=True,verbose_name="Oluşturulma Tarihi")
    updated_at = models.DateTimeField(auto_now=True,verbose_name="Güncellenme Tarihi")

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f'Comment by {self.author.username} on {self.post.title}'
