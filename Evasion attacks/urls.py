"""credit_card_fraud URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from application import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # Main navigation views
    path('', views.home, name='home'),
    path('register', views.register, name='register'),
    path('login', views.login_view, name='login'),
    path('about', views.about, name='about'),
    path('logout', views.logout_view, name='logout'),

    
    # Staff-only model pipeline views
    path('upload', views.Upload_data, name='upload'),
    path('preprocessing', views.preprocess, name='preprocessing'),
    
    path('alg1', views.train_logreg_view, name='alg1'),
    path('alg2', views.train_random_forest_view, name='alg2'),
    path('alg3', views.train_decision_tree_view, name='alg3'),
    path('alg4', views.train_proposed_mlp_view, name='alg4'),
    path('evaluation', views.performance_summary_view, name='evaluation'),

    # Final prediction page (for uploading test set and predicting)
    path('prediction', views.predict_view, name='predict'),

] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

