# -*- coding: utf-8 -*-

import base64
import os
import os.path
import urllib
import hmac
import json
import operator
import hashlib
import datetime
from collections import defaultdict
from base64 import urlsafe_b64decode, urlsafe_b64encode

import requests
from flask import Flask, request, redirect, render_template, url_for

from xml.dom.minidom import parseString

import bottlenose

ACCESS_KEY = "AKIAJQ3F2XC5FIIJQ5OA"
SECRET_KEY = "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"
TAG = 'aztag-20'

amazon = bottlenose.Amazon(ACCESS_KEY, SECRET_KEY, TAG)

#FB_APP_ID = os.environ.get('FACEBOOK_APP_ID')
FB_APP_ID = 161906967278002
requests = requests.session()

app_url = 'https://graph.facebook.com/{0}'.format(FB_APP_ID)
FB_APP_NAME = json.loads(requests.get(app_url).content).get('name')
#FB_APP_SECRET = os.environ.get('FACEBOOK_SECRET')
FB_APP_SECRET = "4c5315f7ff39378fe9a0348ca1c89ca3"


app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_object('conf.Config')


@app.route('/recommendations/<fid>', methods=['GET', 'POST'])
def recommendations(fid):
    access_token = get_token()
    channel_url = url_for('get_channel', _external=True)
    channel_url = channel_url.replace('http:', '').replace('https:', '')

    if access_token:
        likes = fb_call('%s/likes' % fid,
                            args={'access_token': access_token, 'limit': 20})
        titles = []
        for like in likes['data']:
            titles.append(like['name'])
        dictionary = {}
        images = {}
        for title in titles:
            response = amazon.ItemSearch(Keywords=title, SearchIndex="All", ItemPage=1)
            #print response
            dom = parseString(response)
            xmlTag = dom.getElementsByTagName('TotalResults')[0].toxml()
            result_size = xmlTag.replace('<TotalResults>','').replace('</TotalResults>','')
            if int(result_size) > 0:
                xmlTag = dom.getElementsByTagName('ASIN')[0].toxml()
                ASIN = xmlTag.replace('<ASIN>','').replace('</ASIN>','')
                image_service = amazon.ItemLookup(ItemId=ASIN, ResponseGroup="Images")
                img_xml = parseString(image_service)
                xmlTag = dom.getElementsByTagName('DetailPageURL')[0].toxml()
                url = xmlTag.replace('<DetailPageURL>','').replace('</DetailPageURL>','')
                image = None
                try:
                    xmlTag = img_xml.getElementsByTagName('URL')[0].toxml()
                    image = xmlTag.replace('<URL>','').replace('</URL>','')
                except IndexError:
                    image = "/static/images/404_error_4.jpg"
                xmlTag = dom.getElementsByTagName('Title')[0].toxml()
                title = xmlTag.replace('<Title>','').replace('</Title>','')
                dictionary[title] = url
                images[title] = image
        empty = False
        if len(dictionary) == 0:
            empty = True
        friend = fb_call(fid, args={'access_token': access_token})
        return render_template(
                'recommendations.html', token=access_token, dictionary=dictionary, 
                images=images, fid=friend, flag=empty)
    
   
def oauth_login_url(preserve_path=True, next_url=None):
    fb_login_uri = ("https://www.facebook.com/dialog/oauth"
                    "?client_id=%s&redirect_uri=%s" %
                    (app.config['FB_APP_ID'], get_home()))

    if app.config['FBAPI_SCOPE']:
        fb_login_uri += "&scope=%s" % ",".join(app.config['FBAPI_SCOPE'])
        print "URI:" + fb_login_uri
    return fb_login_uri


def simple_dict_serialisation(params):
    return "&".join(map(lambda k: "%s=%s" % (k, params[k]), params.keys()))


def base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip('=')


def fbapi_get_string(path,
    domain=u'graph', params=None, access_token=None,
    encode_func=urllib.urlencode):
    """Make an API call"""

    if not params:
        params = {}
    params[u'method'] = u'GET'
    if access_token:
        params[u'access_token'] = access_token

    for k, v in params.iteritems():
        if hasattr(v, 'encode'):
            params[k] = v.encode('utf-8')

    url = u'https://' + domain + u'.facebook.com' + path
    params_encoded = encode_func(params)
    url = url + params_encoded
    result = requests.get(url).content

    return result


def fbapi_auth(code):
    params = {'client_id': app.config['FB_APP_ID'],
              'redirect_uri': get_home(),
              'client_secret': app.config['FB_APP_SECRET'],
              'code': code}

    result = fbapi_get_string(path=u"/oauth/access_token?", params=params,
                              encode_func=simple_dict_serialisation)
    pairs = result.split("&", 1)
    result_dict = {}
    for pair in pairs:
        (key, value) = pair.split("=")
        result_dict[key] = value
    return (result_dict["access_token"], result_dict["expires"])


def fbapi_get_application_access_token(id):
    token = fbapi_get_string(
        path=u"/oauth/access_token",
        params=dict(grant_type=u'client_credentials', client_id=id,
                    client_secret=app.config['FB_APP_SECRET']),
        domain=u'graph')

    token = token.split('=')[-1]
    if not str(id) in token:
        print 'Token mismatch: %s not in %s' % (id, token)
    return token


def fql(fql, token, args=None):
    if not args:
        args = {}

    args["query"], args["format"], args["access_token"] = fql, "json", token

    url = "https://api.facebook.com/method/fql.query"

    r = requests.get(url, params=args)
    return json.loads(r.content)


def fb_call(call, args=None):
    url = "https://graph.facebook.com/{0}".format(call)
    r = requests.get(url, params=args)
    return json.loads(r.content)

 

def get_home():
    return 'https://' + request.host + '/'


def get_token():

    if request.args.get('code', None):
        return fbapi_auth(request.args.get('code'))[0]

    cookie_key = 'fbsr_{0}'.format(FB_APP_ID)

    if cookie_key in request.cookies:

        c = request.cookies.get(cookie_key)
        encoded_data = c.split('.', 2)


        #encoded_data[0] += "=" * ((4 - len(encoded_data[0]) % 4) % 4) 
        xd = "=" * ((4 - len(encoded_data[1]) % 4) % 4) 

        data = json.loads(urlsafe_b64decode(str(encoded_data[1] + xd)))

        sig = encoded_data[0]

        if not data['algorithm'].upper() == 'HMAC-SHA256':
            raise ValueError('unknown algorithm {0}'.format(data['algorithm']))

        h = hmac.new(FB_APP_SECRET, digestmod=hashlib.sha256)
        h.update(encoded_data[1])
        expected_sig = urlsafe_b64encode(h.digest()).replace('=', '')

        if sig != expected_sig:
            raise ValueError('bad signature')

        code =  data['code']

        params = {
            'client_id': FB_APP_ID,
            'client_secret': FB_APP_SECRET,
            'redirect_uri': '',
            'code': data['code']
        }

        from urlparse import parse_qs
        r = requests.get('https://graph.facebook.com/oauth/access_token', params=params)
        token = parse_qs(r.content).get('access_token')


        return token


@app.route('/', methods=['GET', 'POST'])
def index():
    # print get_home()


    access_token = get_token()
    channel_url = url_for('get_channel', _external=True)
    channel_url = channel_url.replace('http:', '').replace('https:', '')

    if access_token:

        me = fb_call('me', args={'access_token': access_token})
        fb_app = fb_call(FB_APP_ID, args={'access_token': access_token})
        likes = fb_call('me/likes',
                        args={'access_token': access_token, 'limit': 1})
        friends = fb_call('me/friends',
                          args={'access_token': access_token, 'limit': 125})
        photos = fb_call('me/photos',
                         args={'access_token': access_token, 'limit': 2})
  
        redir = get_home() + 'close/'
        POST_TO_WALL = ("https://www.facebook.com/dialog/feed?redirect_uri=%s&"
                        "display=popup&app_id=%s" % (redir, FB_APP_ID))

        app_friends = {}

        SEND_TO = None

        birthday = {}
        today = datetime.date.today()
        

        for friend in friends['data']:
            profile = fb_call(friend['id'],
                          args={'access_token': access_token})
            if 'birthday' in profile:
                dp = profile['birthday'].split("/")
                friend_bday = datetime.date(today.year, int(dp[0]), int(dp[1]))
                if friend_bday > today:
                    diff = friend_bday - today
                    if diff.days < 30:
                        birthday[friend['id']] = (friend_bday.strftime("%A, %B %d"), profile['name'], friend['id'], diff.days)

        sorted_friend = sorted(birthday.items(), key=lambda x: x[1][3])

        url = request.url

        return render_template(
            'index.html', app_id=FB_APP_ID, token=access_token, likes=likes,
            friends=friends, photos=photos, app_friends=app_friends, app=fb_app,
            me=me, POST_TO_WALL=POST_TO_WALL, SEND_TO=SEND_TO, url=url,
            channel_url=channel_url, name=FB_APP_NAME, sorted_friend=sorted_friend)
    else:
        return render_template('login.html', app_id=FB_APP_ID, token=access_token, url=request.url, channel_url=channel_url, name=FB_APP_NAME)

@app.route('/channel.html', methods=['GET', 'POST'])
def get_channel():
    return render_template('channel.html')


@app.route('/close/', methods=['GET', 'POST'])
def close():
    return render_template('close.html')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    if app.config.get('FB_APP_ID') and app.config.get('FB_APP_SECRET'):
        app.run(host='0.0.0.0', port=port)
    else:
        print 'Cannot start application without Facebook App Id and Secret set'
