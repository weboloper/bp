from django.db import models
from django.db.models import ProtectedError
from django.utils.translation import gettext_lazy as _


class TimestampMixin(models.Model):
    """
    Mixin to add timestamp fields to models.

    Provides created_at and updated_at fields that are automatically managed.
    This prevents repetition and maintains consistency across all models.

    Usage:
        class MyModel(TimestampMixin, models.Model):
            name = models.CharField(max_length=100)
    """
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At")
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Updated At")
    )

    class Meta:
        abstract = True



class SoftDeleteMixin(models.Model):
    """
    Mixin to add soft delete functionality to models.

    Records are marked as deleted instead of being removed from database.
    This prevents data loss and maintains referential integrity.

    Usage:
        class MyModel(SoftDeleteMixin, models.Model):
            name = models.CharField(max_length=100)

            objects = SoftDeleteManager()
            all_objects = models.Manager()
    """
    is_deleted = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("Is Deleted")
    )
    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Deleted At")
    )
    deleted_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(app_label)s_%(class)s_deleted_set',
        verbose_name=_("Deleted By")
    )

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False, user=None):
        """
        Soft delete - mark as deleted instead of removing from database.

        Args:
            using: Database alias
            keep_parents: Keep parent models (Django standard)
            user: User who is deleting this record (optional)
        """
        from django.utils import timezone
        self.is_deleted = True
        self.deleted_at = timezone.now()
        if user:
            self.deleted_by = user
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by'])

    def hard_delete(self, using=None, keep_parents=False):
        """
        Permanently delete from database.

        WARNING: This cannot be undone!
        """
        return super().delete(using=using, keep_parents=keep_parents)

    def restore(self):
        """
        Restore a soft-deleted record.

        Clears is_deleted, deleted_at, and deleted_by fields.
        """
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by'])