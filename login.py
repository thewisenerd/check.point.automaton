#!/usr/bin/env python3

# todo:
#  * keep track of cookies? fs?
#  * inject them into browsers
#  * argparse?
#  * refactor and make nacsid global?

import requests

from http.cookies import SimpleCookie # cookie parsing
import json # json parsing

from rsa import encrypt # rsa encryption
from binascii import hexlify # hexifying stuff -- TODO: workaround later

# disable insecure request warnings.
# thx http://stackoverflow.com/a/28002687
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# EDIT THIS !!!
regno = 'regno'
password = 'password'
# EDIT THIS !!! (end)

PortalMainURL = 'https://192.168.10.3/connect/PortalMain';
RSASettingsURL = 'https://192.168.10.3/connect/RSASettings';
GetStateAndViewURL = 'https://192.168.10.3/connect/GetStateAndView';
LoginURL = 'https://192.168.10.3/connect/Login';

# TODO: jobless? redo with regex or something simpler.
def getCookieNACSID(s):
  cookie = SimpleCookie()
  cookie.load(s)
  if 'NACSID' in cookie.keys():
    return cookie['NACSID'].value
  return False

# for teh rsa encrypt
class c_pubkey:
  def __init__(self, n, e):
    self.n = n;
    self.e = e;

# shitty _encoding_
# original def goes something like this (js):
#
#   if (value.length > 2)
#   {
#     var newPass = "";
#     for (var j=value.length-2; j>=0; j=j-2)
#     {
#         newPass = newPass.concat(value.substr(j,2));
#     }
#     value = newPass;
#   }
#
# TODO: i have NOT checked odd chars or sanity
def revStrEncode(s):
  if (len(s) > 2):
    s = "".join([s[i:i+2] for i in range(len(s)-2, -2, -2)])
  return s

def getNACSID():
  r = requests.get(PortalMainURL, verify=False);

  # assert status code is 200
  assert r.status_code == 200, "status code %d" % r.status_code;

  # # used to use this before using SimpleCookie
  # cookiearg = r.headers['Set-Cookie'].split(';');
  # return cookiearg[0][7:]; # 7 == length("NACSID=")

  return getCookieNACSID(r.headers['Set-Cookie']);

def getRSASettings(nacsid):
  cookies = dict(NACSID=nacsid);
  r = requests.get(RSASettingsURL, cookies=cookies, verify = False);

  # assert status code is 200
  assert r.status_code == 200, "status code %d" % r.status_code;

  # check if nacsid changed
  # todo: refactor this. repeated.
  if 'Set-Cookie' in r.headers.keys():
    _t = getCookieNACSID(r.headers['Set-Cookie'])
    if _t != False:
      if nacsid != _t:
        nacsid = _t

  # TODO: too lazy to write a try catch.
  j = json.loads(r.text);

  return j

def getsnv(nacsid):
  cookies = dict(NACSID=nacsid);
  r = requests.get(GetStateAndViewURL, cookies=cookies, verify = False);

  # assert status code is 200
  assert r.status_code == 200, "status code %d" % r.status_code;

  # check if nacsid changed
  # todo: refactor this. repeated.
  if 'Set-Cookie' in r.headers.keys():
    _t = getCookieNACSID(r.headers['Set-Cookie'])
    if _t != False:
      if nacsid != _t:
        nacsid = _t

  # TODO: too lazy to write a try catch.
  j = json.loads(r.text);

  return j

def doAuth(nacsid, rsa, user, password):

  # maketh pubkey from RSASettings
  n = int("0x" + rsa['m'], 16);
  e = int("0x" + rsa['e'], 16);
  pubkey = c_pubkey(n, e);

  # doeth teh _encryption_
  plaintext = rsa['loginToken'] + password;

  encrypted = encrypt(plaintext.encode('utf-8'), pubkey);
  encryptedhex = hexlify(encrypted);

  encryptedhexEncoded = revStrEncode(encryptedhex.decode("utf-8"));

  # maketh the post
  # TODO: keep track of cookies (!!!)
  # TODO: char count in following lines > 80 (!!!)
  cookies = dict(NACSID=nacsid,cpnacportal_login_type="password",cpnacportal_username=user);
  data = { 'realm': 'passwordRealm', 'username': user, 'password': encryptedhexEncoded };
  r = requests.post(LoginURL, data = data, cookies=cookies, verify = False);

  # check if nacsid changed
  # todo: refactor this. repeated.
  if 'Set-Cookie' in r.headers.keys():
    _t = getCookieNACSID(r.headers['Set-Cookie'])
    if _t != False:
      if nacsid != _t:
        nacsid = _t

  # todo: rework this entire cookies thing, seriously. have global variables?
  # set back cookies. nacsid may have changed.
  cookies = dict(NACSID=nacsid,cpnacportal_login_type="password",cpnacportal_username=user);

  r = requests.get(GetStateAndViewURL, cookies=cookies, verify = False);

  # check if nacsid changed
  # todo: refactor this. repeated.
  # todo: pointless after this?
  if 'Set-Cookie' in r.headers.keys():
    _t = getCookieNACSID(r.headers['Set-Cookie'])
    if _t != False:
      if nacsid != _t:
        nacsid = _t

  # TODO: too lazy to write a try catch.
  j = json.loads(r.text);

  return j

def main():
  global regno, password

  nacsid = getNACSID();

  # make sure we get an nacsid
  assert nacsid != False, "nacsid not got!"

  # get RSA Settings
  rsa = getRSASettings(nacsid);

  # get current state and view
  snv = getsnv(nacsid);

  # assert view in authentication
  assert snv['view'] == 'Authentication', "view [%s] != 'Authentication'" % snv['view']

  # do auth
  r = doAuth(nacsid, rsa, regno, password);

  # assert view in final, else doAuth failure
  assert r['view'] == 'Final', "view [%s] != 'Final'; auth failure" % snv['view']

  print("done.");

if __name__ == "__main__":
  main()
