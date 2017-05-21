import requests
import json

from rsa import encrypt
from binascii import hexlify

# disable insecure request warnings.
# thx http://stackoverflow.com/a/28002687
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class pubkey_t:
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

def login(regno, password):
	BaseURL = 'https://192.168.10.3';
	PortalMainURL = BaseURL + '/connect/PortalMain';
	RSASettingsURL = BaseURL + '/connect/RSASettings';
	GetStateAndViewURL = BaseURL + '/connect/GetStateAndView';
	LoginURL = BaseURL + '/connect/Login';

	s = requests.Session()
	rsa = None
	snv = None

	## get initial nacsid
	# optional
	# r = s.get(PortalMainURL, verify=False);
	# assert r.status_code == 200, "status code %d" % r.status_code;

	## get rsasettings
	r = s.get(RSASettingsURL, verify=False);
	assert r.status_code == 200, "status code %d" % r.status_code;
	try:
		rsa = r.json()
	except ValueError:
		return "RSASettings decode error"

	## make sure we're at auth?
	r = s.get(GetStateAndViewURL, verify=False);
	try:
		snv = r.json()
	except ValueError:
		return "StateAndView decode error"
	# assert auth?
	# optional
	#assert snv['view'] == 'Authentication', "view [%s] != 'Authentication'" % snv['view']

	## auth
	# maketh pubkey from RSASettings
	n = int("0x" + rsa['m'], 16);
	e = int("0x" + rsa['e'], 16);
	pubkey = pubkey_t(n, e);

	# doeth teh _encryption_
	plaintext = rsa['loginToken'] + password;
	encrypted = encrypt(plaintext.encode('utf-8'), pubkey);
	encryptedhex = hexlify(encrypted);
	encryptedhexEncoded = revStrEncode(encryptedhex.decode('utf-8'))

	payload = {
		'realm': 'passwordRealm',
		'username': regno,
		'password': encryptedhexEncoded
	};

	# meh.
	r = s.post(LoginURL, data=payload, verify=False);

	# validate snv
	r = s.get(GetStateAndViewURL, verify=False);
	try:
		snv = r.json()
	except ValueError:
		return "StateAndView decode error"

	assert snv['view'] == 'Final', "view [%s] != 'Final'; auth failure" % snv['view']
	return "ok"
