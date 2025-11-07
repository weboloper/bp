from django_filters import rest_framework as filters
from django.db.models import Q
from pages.models import Page


class PageFilter(filters.FilterSet):
    """
    Filter class for Page model.
    Provides filtering capabilities for pages API.

    Query Parameters:
    - parent: Filter by parent ID (e.g., ?parent=1 or ?parent=null for root pages)
    - is_published: Filter by published status (e.g., ?is_published=true)
    - search: Search in title and content (e.g., ?search=hakkımızda)
    """
    # Parent filter - supports null for root pages
    parent = filters.NumberFilter(field_name='parent__id')
    parent_isnull = filters.BooleanFilter(field_name='parent', lookup_expr='isnull')

    # Search in title and content
    search = filters.CharFilter(method='filter_search', label='Search in title/content')

    class Meta:
        model = Page
        fields = {
            'is_published': ['exact'],  # ?is_published=true
        }

    def filter_search(self, queryset, name, value):
        """
        Search in both title and content fields.
        Case-insensitive search.
        """
        if not value:
            return queryset

        return queryset.filter(
            Q(title__icontains=value) | Q(content__icontains=value)
        )
