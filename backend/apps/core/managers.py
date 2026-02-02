from django.db import models
from django.utils import timezone


class SoftDeleteQuerySet(models.QuerySet):
    """
    QuerySet for models using SoftDeleteMixin.
    Provides methods for soft delete operations.
    """
    def delete(self):
        """Soft delete - marks records as deleted instead of removing them."""
        return self.update(is_deleted=True, deleted_at=timezone.now())

    def hard_delete(self):
        """Permanently delete records from database."""
        return super().delete()

    def alive(self):
        """Returns only non-deleted records."""
        return self.filter(is_deleted=False)

    def deleted(self):
        """Returns only deleted records."""
        return self.filter(is_deleted=True)


class SoftDeleteManager(models.Manager):
    """
    Manager for models using SoftDeleteMixin.
    By default, only returns non-deleted records.

    Usage:
        class MyModel(SoftDeleteMixin, models.Model):
            objects = SoftDeleteManager()
            all_objects = models.Manager()  # Access all records including deleted
    """
    def get_queryset(self):
        """Default queryset - excludes deleted records."""
        return SoftDeleteQuerySet(self.model, using=self._db).filter(is_deleted=False)

    def all_with_deleted(self):
        """Returns all records including deleted ones."""
        return SoftDeleteQuerySet(self.model, using=self._db)

    def deleted_only(self):
        """Returns only deleted records."""
        return SoftDeleteQuerySet(self.model, using=self._db).filter(is_deleted=True)
