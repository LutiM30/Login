import jwt
from django.shortcuts import render
from rest_framework import generics , status , views
from .serializers import RegisterSerializer,EmailVerificationSerializer , LoginSerializer ,RequestPasswordResetEmailSerializer , SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken ,Token
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from core import settings as set
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode , urlsafe_base64_decode
from django.utils.encoding import smart_str,force_str, smart_bytes , DjangoUnicodeDecodeError
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util

class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('Email-Verification')
        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi '+user.username + \
            ' Use the link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify your email'}

        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)
    
class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    renderer_classes = (UserRenderer,)

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        
        try:
            print("Hi I'm Here in TRY")
            payload = jwt.decode(token, set.SECRET_KEY,algorithms=['HS256'])
            # token = RefreshToken(token , verify = True)

            user = User.objects.get(id=payload['user_id'])
        
            if not user.is_verified:
                user.is_verified = True
                user.save()
        
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError as identifier:
            print('LOL')
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        
        except jwt.exceptions.DecodeError as identifier:
            print(identifier)
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    renderer_classes = (UserRenderer,)
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data,status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = RequestPasswordResetEmailSerializer

    def post(self , request):
        serializer=self.serializer_class(data=request.data)

        email = request.data['email']

        if User.objects.filter(email=email).exists() :
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
            absurl = 'http://'+current_site+relativeLink
            email_body = 'Hello , \nUse the link below to Reset Your Password \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
            'email_subject': 'Password Reset Request'}

            Util.send_email(data)

        return Response({'success':'If the Email is associated with account We Have Sent the link to reset your password'},status=status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView) :
    serializer_class = SetNewPasswordSerializer
    def get(self, request , uidb64,token):
        try :
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            

            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({"ERROR" : "The Link is Used Now Please Let us Send New One"},status=status.HTTP_403_FORBIDDEN)
            
            return Response({"SUCCESS" : True , "Message" : 'Credentials Valid' , 'uidb64' : uidb64 , 'token' : token} , status=status.HTTP_200_OK)


        except DjangoUnicodeDecodeError as identifier : 
            return Response({"ERROR" : "It is not as we send to you"})

class SetNewPassword(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({"success" : True , "message": "Yeah You Changed Your Password Now Memorize it so You don't have to come here again"},status=status.HTTP_200_OK)