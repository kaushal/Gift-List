import os

class Config(object):
    DEBUG = True
    TESTING = False
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
    FBAPI_APP_ID = os.environ.get('FACEBOOK_APP_ID')
    FBAPI_APP_SECRET = os.environ.get('FACEBOOK_SECRET')
    FBAPI_SCOPE = ['user_photos', 'user_likes', 'friends_likes', 'user_birthday', 'friends_birthday', 'friends_interests']
