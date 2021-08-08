from django.urls import path
from .views import RegisterView , VerifyEmail , LoginAPIView , PasswordTokenCheckAPI ,RequestPasswordResetEmail,SetNewPassword
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework_simplejwt.views import TokenRefreshView , TokenObtainPairView

schema_view = get_schema_view(
   openapi.Info(
      title="Login Logout",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.ourapp.com/policies/terms/",
      contact=openapi.Contact(email="contact@LB.local"),
      license=openapi.License(name="Test License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
   path('register/' , RegisterView.as_view(),name='register'),
   path('login/' , LoginAPIView.as_view(),name='login'),
   path('verify-email/' , VerifyEmail.as_view(),name='Email-Verification') ,
   path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path('^redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
   path('api/token/refresh/' , TokenRefreshView.as_view() , name='token_refresh'),
   path('request-reset-password/' , RequestPasswordResetEmail.as_view(),name='request-reset-password') ,
   path('password-reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view() , name='password-reset-confirm'),
   path('password-reset-complete',SetNewPassword.as_view(),name='password-reset-complete'),
]

