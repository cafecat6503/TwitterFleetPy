import base64

import requests
from requests_oauthlib import OAuth1

consumer_key = '3nVuSoBZnx6U4vzUxf5w'
consumer_secret = 'Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys'
header_tz = "Asia/Tokyo"
header_language = "ja-JP"
adid = 'a7e8ab7c-22f4-4ec7-9d79-bf6a1fe9dc8d'
device_id = '801d23384cb5451a'
client_uuid = 'a3b9d2dc-f148-4f95-8a0f-36ffaf0879c7'
twitter_app_ver = '9.0.0-release.00'


class TwitterFleetPy:
    def __init__(self, identifier, password):
        self.identifier = identifier
        self.password = password
        self.ck = '3nVuSoBZnx6U4vzUxf5w'
        self.cs = 'Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys'
        self.oauth_token_key = None
        self.oauth_token_secret = None
        self.kdt = None
        self.req_header = {
            'user-agent': 'TwitterAndroid/9.0.0-release.00 (29000000-r-0) Android+SDK+built+for+x86/7.1.1 (Google;Android+SDK+built+for+x86;google;sdk_google_phone_x86;0;;1;2013)',
            'accept-encoding': 'gzip, deflate',
            'x-twitter-client-adid': adid,
            'timezone': header_tz,
            'x-twitter-client-limit-ad-tracking': '0',
            'x-twitter-client': 'TwitterAndroid',
            'x-twitter-client-version': twitter_app_ver,
            'x-twitter-client-language': header_language,
            'x-twitter-client-deviceid': device_id,
            'x-twitter-api-version': '5',
            'optimize-body': 'true',
            'authorization': '',
            'accept': 'application/json',
            'x-b3-traceid': 'f164f5d9a8f19d09',
            'x-twitter-active-user': 'yes'
        }

    def login(self):

        header_auth = self.ck + ':' + self.cs

        header_auth = header_auth.encode()
        header_auth = base64.b64encode(header_auth).decode()

        oauth2_req_header = self.req_header
        s = 'Basic ' + header_auth
        oauth2_req_header['authorization'] = s

        oauth2_endipoint = 'https://api.twitter.com/oauth2/token'
        oauth2_req_param = 'grant_type=client_credentials'
        oauth2_req = requests.post(oauth2_endipoint, headers=oauth2_req_header, params=oauth2_req_param)
        if oauth2_req.status_code != 200:
            raise Exception(oauth2_req.content.decode())
        bearer_token = oauth2_req.json()['access_token']

        activate_endpoint = 'https://api.twitter.com/1.1/guest/activate.json'
        activate_auth_header = 'Bearer ' + bearer_token
        activate_req_header = self.req_header
        activate_req_header['authorization'] = activate_auth_header
        activate_req = requests.post(activate_endpoint, headers=activate_req_header)
        if activate_req.status_code != 200:
            raise Exception(oauth2_req.content.decode())
        guest_token = activate_req.json()['guest_token']

        xauth_endpoint = 'https://api.twitter.com/auth/1/xauth_password.json'
        xauth_req_header = activate_req_header
        xauth_req_header['x-guest-token'] = guest_token
        xauth_data = {
            'x_auth_identifier': self.identifier,
            'x_auth_password': self.password,
            'send_error_codes': 'true',
            'x_auth_login_challenge': '1',
            'x_auth_login_verification': '1',
            'ui_metrics': ''
        }

        xauth_req = requests.post(xauth_endpoint, headers=xauth_req_header, data=xauth_data)
        if xauth_req.status_code != 200:
            raise Exception(xauth_req.content.decode())
        self.oauth_token_key = xauth_req.json()['oauth_token']
        self.oauth_token_secret = xauth_req.json()['oauth_token_secret']
        self.kdt = xauth_req.json()['kdt']

    def get_fleet_by_screenname(self, screenname):

        fleet_endpoint = "https://api.twitter.com/fleets/v1/user_fleets"
        search_endpoint = "https://api.twitter.com/2/users/by/username/"
        params = {
            'user_id': user_id,
        }