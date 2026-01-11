from django import forms
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from accounts.models import User, Profile
from accounts.utils import validate_alphanumeric_username


class UserRegistrationForm(forms.ModelForm):
    password1 = forms.CharField(required=True, widget=forms.PasswordInput)
    password2 = forms.CharField(required=True, widget=forms.PasswordInput)
    
    class Meta:
        model = User
        fields = ['username', 'email']
    
    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()

        if not username:
            raise ValidationError(_('Username is required'))

        if len(username) < 3:
            raise ValidationError(_('Username must be at least 3 characters'))

        if len(username) > 30:
            raise ValidationError(_('Username must be at most 30 characters'))

        # Alphanumeric validation
        try:
            validate_alphanumeric_username(username)
        except ValidationError as e:
            raise ValidationError(str(e.message))

        # Check if username exists (ModelForm handles this automatically, but we need custom message)
        if User.objects.filter(username=username).exists():
            raise ValidationError(_('This username is already taken'))

        return username
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        
        if not email:
            raise ValidationError(_('Email is required'))
        
        # Django's built-in email validation (ModelForm handles this, but for custom message)
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError(_('Enter a valid email address'))
        
        # Check if email exists
        if User.objects.filter(email=email).exists():
            raise ValidationError(_('This email address is already registered'))
        
        return email
    
    def clean_password1(self):
        password1 = self.cleaned_data.get('password1', '')
        
        if not password1:
            raise ValidationError(_('Password is required'))
        
        # Create a temporary user instance for validation (not saved)
        temp_user = User(
            username=self.cleaned_data.get('username', ''),
            email=self.cleaned_data.get('email', '')
        )
        
        # Django's built-in password validation with user context
        try:
            validate_password(password1, temp_user)
        except ValidationError as e:
            raise ValidationError(' '.join(e.messages))
        
        return password1
    
    def clean_password2(self):
        password2 = self.cleaned_data.get('password2', '')
        
        if not password2:
            raise ValidationError(_('Password confirmation is required'))
        
        return password2
    
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        if password1 and password2:
            if password1 != password2:
                raise ValidationError({'password2': _('Passwords do not match')})
        
        return cleaned_data
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class PasswordResetForm(forms.Form):
    email = forms.EmailField(required=True)
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        
        if not email:
            raise ValidationError(_('Email address is required'))
        
        # Django's built-in email validation
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError(_('Enter a valid email address'))
        
        return email
    
    def get_user(self):
        """Email ile kullanıcıyı getir, yoksa None döndür"""
        email = self.cleaned_data.get('email')
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None


class PasswordResetConfirmForm(forms.Form):
    new_password1 = forms.CharField(required=True, widget=forms.PasswordInput)
    new_password2 = forms.CharField(required=True, widget=forms.PasswordInput)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1', '')
        
        if not new_password1:
            raise ValidationError(_('New password is required'))
        
        # Django's built-in password validation
        try:
            validate_password(new_password1, self.user)
        except ValidationError as e:
            raise ValidationError(' '.join(e.messages))
        
        return new_password1
    
    def clean_new_password2(self):
        new_password2 = self.cleaned_data.get('new_password2', '')
        
        if not new_password2:
            raise ValidationError(_('Password confirmation is required'))
        
        return new_password2
    
    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')
        
        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise ValidationError({'new_password2': _('Passwords do not match')})
        
        return cleaned_data
    
    def save(self):
        """Kullanıcının şifresini güncelle"""
        password = self.cleaned_data['new_password1']
        self.user.set_password(password)
        self.user.save()
        return self.user


class EmailVerificationResendForm(forms.Form):
    email = forms.EmailField(required=True)
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        
        if not email:
            raise ValidationError(_('Email address is required'))
        
        # Django's built-in email validation
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError(_('Enter a valid email address'))
        
        return email
    
    def get_user(self):
        """Email ile kullanıcıyı getir, yoksa None döndür"""
        email = self.cleaned_data.get('email')
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None


class PasswordSetForm(forms.Form):
    """
    Password olmayan kullanıcılar için (sosyal medya ile giriş yapanlar)
    Current password gerektirmez
    """
    new_password1 = forms.CharField(required=True, widget=forms.PasswordInput)
    new_password2 = forms.CharField(required=True, widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1', '')

        if not new_password1:
            raise ValidationError(_('New password is required'))

        # Django's built-in password validation with user context
        try:
            validate_password(new_password1, self.user)
        except ValidationError as e:
            raise ValidationError(' '.join(e.messages))

        return new_password1

    def clean_new_password2(self):
        new_password2 = self.cleaned_data.get('new_password2', '')

        if not new_password2:
            raise ValidationError(_('New password confirmation is required'))

        return new_password2

    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')

        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise ValidationError({'new_password2': _('Passwords do not match')})

        return cleaned_data

    def save(self):
        self.user.set_password(self.cleaned_data['new_password1'])
        self.user.save()
        return self.user


class PasswordChangeForm(forms.Form):
    """
    Password olan kullanıcılar için
    Current password gerektirir
    """
    current_password = forms.CharField(required=True, widget=forms.PasswordInput)
    new_password1 = forms.CharField(required=True, widget=forms.PasswordInput)
    new_password2 = forms.CharField(required=True, widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password', '')

        if not current_password:
            raise ValidationError(_('Current password is required'))

        # Check if current password is correct
        if not self.user.check_password(current_password):
            raise ValidationError(_('Current password is incorrect'))

        return current_password

    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1', '')

        if not new_password1:
            raise ValidationError(_('New password is required'))

        # Django's built-in password validation with user context
        try:
            validate_password(new_password1, self.user)
        except ValidationError as e:
            raise ValidationError(' '.join(e.messages))

        return new_password1

    def clean_new_password2(self):
        new_password2 = self.cleaned_data.get('new_password2', '')

        if not new_password2:
            raise ValidationError(_('New password confirmation is required'))

        return new_password2

    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')
        current_password = cleaned_data.get('current_password')

        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise ValidationError({'new_password2': _('New passwords do not match')})

        if current_password and new_password1:
            if current_password == new_password1:
                raise ValidationError({'new_password1': _('New password cannot be the same as current password')})

        return cleaned_data

    def save(self):
        """Kullanıcının şifresini güncelle"""
        new_password = self.cleaned_data['new_password1']
        self.user.set_password(new_password)
        self.user.save()
        return self.user


class EmailChangeForm(forms.Form):
    current_password = forms.CharField(required=True, widget=forms.PasswordInput)
    new_email = forms.EmailField(required=True)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password', '')
        
        if not current_password:
            raise ValidationError(_('Enter your current password'))
        
        # Check if current password is correct
        if not self.user.check_password(current_password):
            raise ValidationError(_('Current password is incorrect'))
        
        return current_password
    
    def clean_new_email(self):
        new_email = self.cleaned_data.get('new_email', '').strip().lower()
        
        if not new_email:
            raise ValidationError(_('New email address is required'))
        
        # Check if same as current email
        if new_email == self.user.email.lower():
            raise ValidationError(_('New email address cannot be the same as current email'))
        
        # Django's built-in email validation
        try:
            validate_email(new_email)
        except ValidationError:
            raise ValidationError(_('Enter a valid email address'))
        
        # Check if email already exists
        if User.objects.filter(email__iexact=new_email).exists():
            raise ValidationError(_('This email address is already in use'))
        
        return new_email


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['first_name', 'last_name', 'birth_date', 'bio', 'avatar']
        widgets = {
            'birth_date': forms.DateInput(attrs={'type': 'date'}),
            'bio': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Kendiniz hakkında kısa bilgi...'}),
        }

    def __init__(self, user, *args, **kwargs):
        self.user = user
        # Get or create profile (signal should have created it, but use get_or_create to be safe)
        profile, created = Profile.objects.get_or_create(user=user)
        super().__init__(instance=profile, *args, **kwargs)

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name', '').strip()

        if len(first_name) > 30:
            raise ValidationError(_('First name must be at most 30 characters'))

        return first_name

    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name', '').strip()

        if len(last_name) > 30:
            raise ValidationError(_('Last name must be at most 30 characters'))

        return last_name

    def clean_bio(self):
        bio = self.cleaned_data.get('bio', '').strip()

        if len(bio) > 500:
            raise ValidationError(_('Bio must be at most 500 characters'))

        return bio

    def save(self, commit=True):
        # Update profile fields
        profile = super().save(commit=commit)
        return profile


class UsernameChangeForm(forms.Form):
    current_password = forms.CharField(required=True, widget=forms.PasswordInput)
    new_username = forms.CharField(required=True, max_length=30)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password', '')
        
        if not current_password:
            raise ValidationError(_('Enter your current password'))
        
        # Check if current password is correct
        if not self.user.check_password(current_password):
            raise ValidationError(_('Current password is incorrect'))
        
        return current_password
    
    def clean_new_username(self):
        new_username = self.cleaned_data.get('new_username', '').strip()
        
        if not new_username:
            raise ValidationError(_('New username is required'))
        
        if len(new_username) < 3:
            raise ValidationError('Kullanıcı adı en az 3 karakter olmalı')
        
        if len(new_username) > 30:
            raise ValidationError('Kullanıcı adı en fazla 30 karakter olabilir')
        
        # Check if same as current username
        if new_username.lower() == self.user.username.lower():
            raise ValidationError(_('New username cannot be the same as current username'))
        
        # Alphanumeric validation
        try:
            validate_alphanumeric_username(new_username)
        except ValidationError as e:
            raise ValidationError(str(e.message))
        
        # Check if username exists
        if User.objects.filter(username__iexact=new_username).exists():
            raise ValidationError('Bu kullanıcı adı zaten alınmış')
        
        return new_username
    
    def save(self):
        """Kullanıcının username'ini güncelle"""
        new_username = self.cleaned_data['new_username']
        self.user.username = new_username
        self.user.save()
        return self.user
