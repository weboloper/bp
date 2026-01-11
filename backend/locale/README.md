# locale klasörünü oluştur

python manage.py makemessages -l en
python manage.py makemessages -l tr

# Çevirileri derle

python manage.py compilemessages

# Çeviri Dosyaları (Translation Files)

Bu klasör Django'nun çeviri dosyalarını içerir.

## Kullanım

### 1. Çeviri Dosyalarını Oluşturma

İngilizce çeviri dosyalarını oluşturmak için:

```bash
python manage.py makemessages -l en --ignore=venv --ignore=env
```

Tüm Python ve template dosyalarında `gettext()` veya `_()` ile işaretlenmiş stringler toplanacaktır.

### 2. Çeviri Dosyalarını Derleme

Çeviri dosyalarını (.po) derlenmiş formata (.mo) çevirmek için:

```bash
python manage.py compilemessages
```

### 3. Kodda Çeviri Kullanımı

#### Python Kodunda:

```python
from django.utils.translation import gettext as _

# Basit çeviri
message = _("Merhaba Dünya")

# Parametreli çeviri
message = _("Hoş geldiniz, %(username)s") % {'username': user.username}

# Çoğul formlar
from django.utils.translation import ngettext
message = ngettext(
    '%(count)d öğe bulundu',
    '%(count)d öğe bulundu',
    count
) % {'count': count}
```

#### Template'lerde:

```django
{% load i18n %}

<!-- Basit çeviri -->
<h1>{% trans "Hoş Geldiniz" %}</h1>

<!-- Parametreli çeviri -->
<p>{% blocktrans with name=user.name %}Merhaba {{ name }}{% endblocktrans %}</p>

<!-- Çoğul formlar -->
{% blocktrans count counter=list|length %}
{{ counter }} öğe bulundu
{% plural %}
{{ counter }} öğe bulundu
{% endblocktrans %}
```

#### JavaScript'te:

```javascript
// Django'nun i18n kataloğunu yükleyin
<script src="{% url 'javascript-catalog' %}"></script>;

// Çeviri kullanımı
const message = gettext("Merhaba Dünya");
const interpolated = interpolate(gettext("Hoş geldiniz, %s"), [username]);
```

## Dil Değiştirme

Kullanıcılar dili aşağıdaki yöntemlerle değiştirebilir:

### 1. Form ile (POST isteği)

```html
<form action="{% url 'set_language' %}" method="post">
    {% csrf_token %}
    <input name="next" type="hidden" value="{{ redirect_to }}" />
    <select name="language">
        {% get_current_language as LANGUAGE_CODE %}
        {% get_available_languages as LANGUAGES %}
        {% for lang_code, lang_name in LANGUAGES %}
            <option value="{{ lang_code }}" {% if lang_code == LANGUAGE_CODE %}selected{% endif %}>
                {{ lang_name }}
            </option>
        {% endfor %}
    </select>
    <button type="submit">{% trans "Dili Değiştir" %}</button>
</form>
```

### 2. Query parametresi ile

Dil tercihi session'da saklanır ve kullanıcı oturumu boyunca aktif kalır.

## Desteklenen Diller

Şu anda desteklenen diller:

- Türkçe (tr) - Varsayılan
- English (en)

Yeni dil eklemek için `settings.py` dosyasındaki `LANGUAGES` listesini güncelleyin.

## Notlar

- Çeviri dosyaları `.po` formatındadır (Portable Object)
- Derlenmiş dosyalar `.mo` formatındadır (Machine Object)
- `.mo` dosyaları git'e commit edilmemelidir (otomatik oluşturulur)
- Her dil için `locale/<lang_code>/LC_MESSAGES/` klasörü oluşturulur
- `django.po` dosyası genel çevirileri içerir
- `djangojs.po` dosyası JavaScript çevirilerini içerir
