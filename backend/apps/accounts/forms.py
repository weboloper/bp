from django import forms
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
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
    new_password1 = forms.CharField(required=True, widget=forms.PasswordInput)
    new_password2 = forms.CharField(required=True, widget=forms.PasswordInput)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1', '')
        
        if not new_password1:
            raise ValidationError('Yeni şifre gerekli')
        
        # Django's built-in password validation
        try:
            validate_password(new_password1, self.user)
        except ValidationError as e:
            raise ValidationError(' '.join(e.messages))
        
        return new_password1
    
    def clean_new_password2(self):
        new_password2 = self.cleaned_data.get('new_password2', '')
        
        if not new_password2:
            raise ValidationError('Şifre tekrarı gerekli')
        
        return new_password2
    
    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')
        
        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise ValidationError({'new_password2': 'Şifreler eşleşmiyor'})
        
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


class EmailChangeForm(forms.Form):
    current_password = forms.CharField(required=True, widget=forms.PasswordInput)
    new_email = forms.EmailField(required=True)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password', '')
        
        if not current_password:
            raise ValidationError('Mevcut şifrenizi girin')
        
        # Check if current password is correct
        if not self.user.check_password(current_password):
            raise ValidationError('Mevcut şifre yanlış')
        
        return current_password
    
    def clean_new_email(self):
        new_email = self.cleaned_data.get('new_email', '').strip().lower()
        
        if not new_email:
            raise ValidationError('Yeni email adresi gerekli')
        
        # Check if same as current email
        if new_email == self.user.email.lower():
            raise ValidationError('Yeni email adresi mevcut email ile aynı olamaz')
        
        # Django's built-in email validation
        try:
            validate_email(new_email)
        except ValidationError:
            raise ValidationError('Geçerli bir email adresi giriniz')
        
        # Check if email already exists
        if User.objects.filter(email__iexact=new_email).exists():
            raise ValidationError('Bu email adresi zaten kullanılıyor')
        
        return new_email


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name']
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        
        # Set initial data for user fields
        if not kwargs.get('data'):
            self.initial['first_name'] = user.first_name
            self.initial['last_name'] = user.last_name
    
    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name', '').strip()
        
        if len(first_name) > 30:
            raise ValidationError('Ad en fazla 30 karakter olabilir')
        
        return first_name
    
    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name', '').strip()
        
        if len(last_name) > 30:
            raise ValidationError('Soyad en fazla 30 karakter olabilir')
        
        return last_name
    
    def save(self, commit=True):
        # Update user fields
        self.user.first_name = self.cleaned_data['first_name']
        self.user.last_name = self.cleaned_data['last_name']
        
        if commit:
            self.user.save()
        
        return self.user


class ProfileDetailsForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['birth_date', 'bio', 'avatar']
        widgets = {
            'birth_date': forms.DateInput(attrs={'type': 'date'}),
            'bio': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Kendiniz hakkında kısa bilgi...'}),
        }
    
    def clean_bio(self):
        bio = self.cleaned_data.get('bio', '').strip()
        
        if len(bio) > 500:
            raise ValidationError('Bio en fazla 500 karakter olabilir')
        
        return bio


class UsernameChangeForm(forms.Form):
    current_password = forms.CharField(required=True, widget=forms.PasswordInput)
    new_username = forms.CharField(required=True, max_length=30)
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password', '')
        
        if not current_password:
            raise ValidationError('Mevcut şifrenizi girin')
        
        # Check if current password is correct
        if not self.user.check_password(current_password):
            raise ValidationError('Mevcut şifre yanlış')
        
        return current_password
    
    def clean_new_username(self):
        new_username = self.cleaned_data.get('new_username', '').strip()
        
        if not new_username:
            raise ValidationError('Yeni kullanıcı adı gerekli')
        
        if len(new_username) < 3:
            raise ValidationError('Kullanıcı adı en az 3 karakter olmalı')
        
        if len(new_username) > 30:
            raise ValidationError('Kullanıcı adı en fazla 30 karakter olabilir')
        
        # Check if same as current username
        if new_username.lower() == self.user.username.lower():
            raise ValidationError('Yeni kullanıcı adı mevcut kullanıcı adı ile aynı olamaz')
        
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
