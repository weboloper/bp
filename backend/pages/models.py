from django.db import models
from django.urls import reverse
from django.utils.text import slugify


class Page(models.Model):
    title = models.CharField(max_length=200, verbose_name="Başlık")
    slug = models.SlugField(max_length=200, unique=True, verbose_name="URL/Slug")
    content = models.TextField(verbose_name="Gövde")
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children',
        verbose_name="Üst Sayfa"
    )
    
    # Ek faydalı alanlar
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Oluşturulma Tarihi")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Güncellenme Tarihi")
    is_published = models.BooleanField(default=True, verbose_name="Yayınlanmış mı?")
    order = models.IntegerField(default=0, verbose_name="Sıralama")
    
    class Meta:
        verbose_name = "Sayfa"
        verbose_name_plural = "Sayfalar"
        ordering = ['order', 'title']
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        # Eğer slug yoksa title'dan otomatik oluştur
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)
    
    def get_absolute_url(self):
        return reverse('pages:detail', kwargs={'slug': self.slug})
    
    def get_children(self):
        """Alt sayfaları döndürür"""
        return self.children.filter(is_published=True).order_by('order', 'title')
    
    def get_ancestors(self):
        """Üst sayfaları hierarchik olarak döndürür"""
        ancestors = []
        parent = self.parent
        while parent:
            ancestors.append(parent)
            parent = parent.parent
        return reversed(ancestors)
    
    def get_breadcrumbs(self):
        """Breadcrumb için kullanılabilir"""
        breadcrumbs = list(self.get_ancestors())
        breadcrumbs.append(self)
        return breadcrumbs
