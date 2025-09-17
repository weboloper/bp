from django import forms
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from accounts.models import User
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
            raise ValidationError('Kullanıcı adı gerekli')
        
        if len(username) < 3:
            raise ValidationError('Kullanıcı adı en az 3 karakter olmalı')
        
        if len(username) > 30:
            raise ValidationError('Kullanıcı adı en fazla 30 karakter olabilir')
        
        # Alphanumeric validation
        try:
            validate_alphanumeric_username(username)
        except ValidationError as e:
            raise ValidationError(str(e.message))
        
        # Check if username exists (ModelForm handles this automatically, but we need custom message)
        if User.objects.filter(username=username).exists():
            raise ValidationError('Bu kullanıcı adı zaten alınmış')
        
        return username
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        
        if not email:
            raise ValidationError('Email gerekli')
        
        # Django's built-in email validation (ModelForm handles this, but for custom message)
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError('Geçerli bir email adresi giriniz')
        
        # Check if email exists
        if User.objects.filter(email=email).exists():
            raise ValidationError('Bu email adresi zaten kayıtlı')
        
        return email
    
    def clean_password1(self):
        password1 = self.cleaned_data.get('password1', '')
        
        if not password1:
            raise ValidationError('Şifre gerekli')
        
        # Create a temporary user instance for validation (not saved)
        temp_user = User(
            username=self.cleaned_data.get('username', ''),
            email=self.cleaned_data.get('email', ''),
            first_name=self.cleaned_data.get('first_name', ''),
            last_name=self.cleaned_data.get('last_name', '')
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
            raise ValidationError('Şifre tekrarı gerekli')
        
        return password2
    
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        if password1 and password2:
            if password1 != password2:
                raise ValidationError({'password2': 'Şifreler eşleşmiyor'})
        
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
            raise ValidationError('Email adresi gerekli')
        
        # Django's built-in email validation
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError('Geçerli bir email adresi giriniz')
        
        return email
    
    def get_user(self):
        """Email ile kullanıcıyı getir, yoksa None döndür"""
        email = self.cleaned_data.get('email')
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None


class PasswordResetConfirmForm(forms.Form):
    password1 = forms.CharField(required=True, widget=forms.PasswordInput)
    password2 = forms.CharField(required=True, widget=forms.PasswordInput)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_password1(self):
        password1 = self.cleaned_data.get('password1', '')
        
        if not password1:
            raise ValidationError('Yeni şifre gerekli')
        
        # Django's built-in password validation
        try:
            validate_password(password1, self.user)
        except ValidationError as e:
            raise ValidationError(' '.join(e.messages))
        
        return password1
    
    def clean_password2(self):
        password2 = self.cleaned_data.get('password2', '')
        
        if not password2:
            raise ValidationError('Şifre tekrarı gerekli')
        
        return password2
    
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        if password1 and password2:
            if password1 != password2:
                raise ValidationError({'password2': 'Şifreler eşleşmiyor'})
        
        return cleaned_data
    
    def save(self):
        """Kullanıcının şifresini güncelle"""
        password = self.cleaned_data['password1']
        self.user.set_password(password)
        self.user.save()
        return self.user


class EmailVerificationResendForm(forms.Form):
    email = forms.EmailField(required=True)
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        
        if not email:
            raise ValidationError('Email adresi gerekli')
        
        # Django's built-in email validation
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError('Geçerli bir email adresi giriniz')
        
        return email
    
    def get_user(self):
        """Email ile kullanıcıyı getir, yoksa None döndür"""
        email = self.cleaned_data.get('email')
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None


class PasswordChangeForm(forms.Form):
    current_password = forms.CharField(required=True, widget=forms.PasswordInput)
    new_password1 = forms.CharField(required=True, widget=forms.PasswordInput)
    new_password2 = forms.CharField(required=True, widget=forms.PasswordInput)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password', '')
        
        if not current_password:
            raise ValidationError('Mevcut şifre gerekli')
        
        # Check if current password is correct
        if not self.user.check_password(current_password):
            raise ValidationError('Mevcut şifre yanlış')
        
        return current_password
    
    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1', '')
        
        if not new_password1:
            raise ValidationError('Yeni şifre gerekli')
        
        # Django's built-in password validation with user context
        try:
            validate_password(new_password1, self.user)
        except ValidationError as e:
            raise ValidationError(' '.join(e.messages))
        
        return new_password1
    
    def clean_new_password2(self):
        new_password2 = self.cleaned_data.get('new_password2', '')
        
        if not new_password2:
            raise ValidationError('Yeni şifre tekrarı gerekli')
        
        return new_password2
    
    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')
        current_password = cleaned_data.get('current_password')
        
        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise ValidationError({'new_password2': 'Yeni şifreler eşleşmiyor'})
        
        if current_password and new_password1:
            if current_password == new_password1:
                raise ValidationError({'new_password1': 'Yeni şifre mevcut şifre ile aynı olamaz'})
        
        return cleaned_data
    
    def save(self):
        """Kullanıcının şifresini güncelle"""
        new_password = self.cleaned_data['new_password1']
        self.user.set_password(new_password)
        self.user.save()
        return self.user
