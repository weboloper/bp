from django_filters import rest_framework as filters
from django.db.models import Q
from posts.models import Post


class PostFilter(filters.FilterSet):
    """
    Filter class for Post model.
    Provides filtering capabilities for posts API.

    Query Parameters:
    - author: Filter by author ID (e.g., ?author=1)
    - is_published: Filter by published status (e.g., ?is_published=true)
    - search: Search in title and content (e.g., ?search=django)
    - created_after: Filter posts created after date (e.g., ?created_after=2024-01-01)
    - created_before: Filter posts created before date (e.g., ?created_before=2024-12-31)
    """
    # Author filter
    author = filters.NumberFilter(field_name='author__id')

    # Search in title and content
    search = filters.CharFilter(method='filter_search', label='Search in title/content')

    # Date range filters
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte', label='Created after')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte', label='Created before')

    class Meta:
        model = Post
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
