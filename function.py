from urllib.parse import quote_plus, unquote_plus, urlparse, urlunparse, parse_qsl, urlencode
from time import strftime, time
from datetime import datetime
import base64
import html
import json
# Must package the following modules separately
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import bcrypt

# Extract public key for Apache/mod_ucam_webauth like "openssl rsa -in mykey.pem -RSAPublicKey_out > mykey.pub"
privkey = '-----BEGIN RSA PRIVATE KEY-----\n'\
	+ 'MIIEowIBAAKCAQEArtOutogZyCIZaAO+bTLZ5EzdprWL6QrU7Qsf9yhNk0EeV/6l\n'\
	+ 'hji0qJr8HwgfGgTF7FLy2uuX0GnOQAjTsPvX0dfuF61W4Mck35vkJnk/qngy0LCp\n'\
	+ 'x9BkVIAshzEehHL5zd7y5UsaZZYNzCXGpHwfZEmnCoWcbPu0ZKmhA/ZxO960Yp4E\n'\
	+ '1f/odftR6p/2i7hCLNASJYejK1pv/IA03vw+fQos79rqJMhCQS0NcsR30flHWId+\n'\
	+ 'wn0EcbeIP1GhEN6/7KiIIjRSTV/0Ami1YqdF8e4ORGTsV3F3N0kpf1iaRuJa2cpw\n'\
	+ 'QT8biJ1ebjSFtbA411jTpmrbFR0e5JaTRLw6JwIDAQABAoIBAQCuUJB2nXOfciiE\n'\
	+ '5p67gKVzFhU3QPM0tMEjbSE9LalTtu0LbfMaxnWTW50hT9a6+aFjBj3xfFCN1MF6\n'\
	+ 'ZZK1eBZzu+pBH2ttigLBFk3A8spBLcH1BQD0I1u2SWqcjaRRCdb7p13mtCCow5oU\n'\
	+ 'QGI05THjq/Bq9FfI7puqdtv9+H5k4vx3x7idAknGSIsdg/fO7OhDkUa8s2bW1fqZ\n'\
	+ 'YQjAwkgROMjkyLnhQKCrCdBE7UfAJMsNOs1EnZypjq6oL9nYFzQhgyNsFhCxp4YY\n'\
	+ 'nwKaTYRa0dzxi/Za8rV5yHGn5vbKu+4lOmHQTmc4iaanAkojRHBGwFKfQUtwmfcK\n'\
	+ 'nhWY1xtZAoGBAL/1wP1G6gdSELdOTgrXRXic1l7ISoDYHdiGda1TTvFslTttkeMn\n'\
	+ 'bjLwtpDMs8eaJ+YwXVkU/futh20SDBoENmie1RLXxtijcJxB2jnCzNAonkkBV8Cg\n'\
	+ 'XsOaHfVNZTVQh8M0OlsKkQIESv7La+pKMEiCtfFNv3A1TkzfNJ09s4ZjAoGBAOkm\n'\
	+ 'r3sunwGqnMgmPLyTZGilMP1PbrHDBCvudLynggf0ZCbdhnstDyWAWbvjgfsRPQ1L\n'\
	+ 'krYx5vEDS9ioxin+SZJgLuKRvDCctkJpfWqq45Ltt7cNCfdsJbxkOcylWN76sRtQ\n'\
	+ 'pDItmhwTSitTGDWqBgLRPUAlEwF3RGseBjhdmpZtAoGAJJznFmf0Mzk/3vachAzT\n'\
	+ 'P1IKwUFKlJCkAKyEvW5qXDntrMwVS1I1/plS+QNSNvv8KDeJVnheiSZr8i3DCSNM\n'\
	+ 'jV/eHB3z21YxIFyfFu1Ey18z8ZDEAAWWjZBTrnn4l9aoTl8j0kGNrujKtRZvmtxT\n'\
	+ 'oUDtGv1NSkWgjaD1FBi0qSkCgYBqBL5dDEkfr95VIRYTRg6tixhox3r1eFFoTKlm\n'\
	+ 's+DsDxSPm8IwNsAhdGjZiE2txhv19LyE/tIeHDqcDbr2k3wPBI+tVUm27TvvnRp7\n'\
	+ 'q7OKN3CH23UBvnq2XPjvduyfkG2Clzvi2VuvkpHye3mRxXuwQkdQ6MroqrxA3UlE\n'\
	+ 'zkOiTQKBgFl4gCm+pp5zJfs/u+leDNx90hsmK8o5iAkltX+tpC5AD94FjtA8jFYT\n'\
	+ 'GgqyvQDnnbgbiLCMt7NumVFOR2lVRmMidP70U1yD51vyCARtNv8yk4NOx5WWSrYJ\n'\
	+ 'Ucn+5N/AnJC4k0n9t1tooBmeMoMkRxJ/YOjrqSvX+Sx1205tcrQp\n'\
	+ '-----END RSA PRIVATE KEY-----'

def wls_tstamp():
	d = datetime.now()
	return d.strftime('%Y%m%dT%H%M%SZ') # Ucam-Webauth specific modified RFC3339
	
def wls_sign(str):
    RSAkey = RSA.importKey(privkey)
    digest = SHA.new()
    digest.update(str.encode('utf-8'))
    sig = PKCS1_v1_5.new(RSAkey).sign(digest)
    sig = base64.b64encode(sig).decode('utf-8')
    trans = sig.maketrans('+/=', '-._') # Ucam-Webauth specific URL-safe encoding
    sig = sig.translate(trans)
    return sig
	
def checkpwd(username, password):
    # Test credentials are 'admin'/'admin', you should choose a bigger cost parameter for production (but be aware of lambda timeout)
    admin = '$2b$04$62c0LmreheTA6xmvOoABeun.o.60OMr7Hmq4UtM7In4uei80uNi5K'.encode('utf-8')
    if ((username == 'admin') and (bcrypt.checkpw(password.encode('utf-8'), admin))):
        return True
    else:
        return False

def login_page(action, hidden_params):
    html = '<!DOCTYPE HTML>'\
            + '<HTML>'\
            + '<HEAD>'\
            + '<TITLE>Login</TITLE>'\
            + '</HEAD>'\
            + '<DIV style="text-align: center; vertical-align: middle; margin: 48px;">'\
            + '<IMG style="margin: 48px" src="data:image/png;base64,'\
            + 'R0lGODlhZABjAMIAAAAAAGZmZjMzM8zMzJmZmf///////////yH5BAEKAAcALAAAAABkAGMAAAP+'\
            + 'eLrc/jDKKQcRIAsyqP9gKCpDkJ2nEHRj677Phc6aYAccrO+SSf+0DYtHhPmAyNmqyBQRklAaoUmd'\
            + 'DDDRbCZQ7TqeWqhN5S0fruEgIWduH45pwMZNL8VPS7q5hI0LhnpdBHB3gIFNMncoXIdUiYooU41F'\
            + 'aJA0hpMudpZBmTuPnIueRqFAmKMem6UzAqgjoKsnkq4fYLGXtKmEtxmzuRGVvDOnvyS2wpHFD6rI'\
            + 'KH/KCxZ9zTO+udLUSM/FsNlKxcHeptfH4j+MruHmP8SBzOvnrt3ww6Pq9DToje/4+e1lfPol2eZu'\
            + 'nsAU/6pYOCgmYRN+DJU4JIItYhJrXgZNs/j+A+NDjRyjTHxxYWPIH3MyAjEZcmSLdyrWsLToskWA'\
            + 'mzhYGOQ0UwvBOrssbWAzAGJDdz5i9hyIowCwpaxq6rAT0+i5NUVBWBWlpwSOM0FRsnERVlamilDy'\
            + '7Cjr0c3ORVKthI27415HuhQCztgHVQVerViw/IVxrI8QOk9aPdFX5waBAia+usugwERboINhYFhg'\
            + 'IjM0EBhYXPn5uUvoaDY8l+4BoMFi1asfdHYNQG1sihkMDdAA+5cFnDdtpAgwhlXO2x9237IxFsbJ'\
            + '59CjS48IvLr169iza9/Ovbt3xsjDi6dQcox55iHWuD4/xtru8wfYy7/xhj34A+XNo115uUH+agbd'\
            + '/MfZNK1AhUd933yx0TbBSBLMfQ0oh5FyWwDTCwMULlHUIBWSUE0EkRlyxBANTuDDfba0AsF7ER5I'\
            + 'mz64xAAARkfQpsEEfWBC4YwQPOGei/7BKBxvMtJ4Qos3RnDMfUdAaIMDGS7jixxLFulAjf4dCaJh'\
            + 'OqLQJXhRRuiAHPhxBSCPDWAZTQoWPuJRH+DNhmRtEarIAJlvJHOmkZSdeWGPirH5BUIYkgElkJXZ'\
            + 'uQCewfzk45UnkIioA2TsqGMfvjx66BZF/YbnnXY2OoSmDDSJ0xb97cZCk7IJqsCTyww0pqI7okMq'\
            + 'Z3jAkRBxCxzTZaQetpVhB0VFNquNf97xWhmwKbbzHg5r6Jmmi3JuSidq4H2KK7NolqplfGb1KEcK'\
            + 'zsgIrKGxdjjgsXUipGyefZYJ7AOwojZvlr28u6a6xrDbrgbvqgkuv2vGOakCKdab7rUTaOvnFt1u'\
            + '21qvXkKKia/W/rniwZUN4fDDGkuMr8Ms0hvutPcufN9us3zs7ckSA7Jjpgyj7HKYFhJ8xmkKuGxv'\
            + 'yK+mDK8comEgrLQMYNHfGYRG48OdAPxTySxeOSMZ08MRp8FxJGi9iDVgSACSGPgt2RyGGg+CHYDc'\
            + 'jZpdnf0R190U2LWj7yS9aZL3eBR85/ffgAf+3XSEF2744ZAkAAA7'\
            + '" />'\
            + '<FORM style="font-family: monospace; font-size: 24px" method="POST" enctype="application/x-www-form-urlencoded" '\
            + 'action="' + action + '">'\
            + '<LABEL for="username">Username:&nbsp;</LABEL>'\
            + '<INPUT TYPE="text" name="username" /><BR />'\
            + '<LABEL for="password">Password:&nbsp;</LABEL>'\
            + '<INPUT TYPE="password" name="password" /><BR />'\
            + hidden_params\
            + '<BR />'\
            + '<INPUT TYPE="submit" name="submit" value="Login" />'\
            + '<INPUT TYPE="submit" name="cancel" value="Cancel" />'\
            + '</FORM>'\
            + '</DIV>'\
            + '</HTML>'
    return html

def error_page(msg):
    html = '<!DOCTYPE HTML>'\
            + '<HTML>'\
            + '<HEAD>'\
            + '<TITLE>Login</TITLE>'\
            + '</HEAD>'\
            + '<DIV style="text-align: center; vertical-align: middle; margin: 48px;">'\
            + '<IMG style="margin: 48px" src="data:image/png;base64,'\
            + 'R0lGODlhZABjAIABAAAAAP///yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAAEALAAAAABkAGMA'\
            + 'AAL+jI+py+0Po5y02ouz3rz7D4YRQALiiQblaqbuxrLvbMUxjUO2nffKvvMJgUBhjxg00pBF5YuZ'\
            + 'dKKgTWmISrResVEth5v1fsFd8YUcNtfQafWE3Xbr4HF5g163//B5/YHf5weI5LdHZQhViHB4l6io'\
            + '4ujAWDjZyKRYKRkphyXRafc5t2nG5RlKeqqZqQVmmmrVOlIqRub6aoRme+vDJhrrBOf7i9v7EKxE'\
            + 'Jzycg6e8vJRsHM3MJz0N3Wx5/QSomj0z6L09Fa79TV7OMEjiss6uvp7i/o6YvuUOjy8yT5/A3/Lh'\
            + 'H0B//0AIzDcv4MEFAgdqaIgw4RiIBCk+bIixzJqGjBxlYOgI0uPGkCDPlPxzkkLHiAvfcBTXUhZG'\
            + 'ZxJlWrR201xMmAVx5tTZE2hQnz8XrbQ5k2VRhimNNuX5k6RDpiErkoSa0alUpUchSfX49YbXsGST'\
            + 'lD3LYyxatAbWum3xdm3buGfn0iWL8u5WrXpf1uu70ypgfY8KGz6MOLHixYwbO35soQAAOw=='\
            + '" />'\
            + '<BR />'\
            + '<P style="font-family: monospace; font-size: 24px">'\
            + msg\
            + '</P>'\
            + '</DIV>'\
            + '</HTML>'
    return html

def lambda_handler(event, context):
    if (event['requestContext']['httpMethod'] == 'GET'):
        if (('queryStringParameters' in event.keys()) and (json.dumps(event['queryStringParameters']) != 'null')):
            if (('ver' not in event['queryStringParameters'].keys()) or ('url' not in event['queryStringParameters'].keys())):
                return {
                    'isBase64Encoded': 0,
                    'statusCode': 400,
                    'headers': {'Content-Type': 'text/html; charset=utf-8'},
                    'body': error_page('Error: missing mandatory keys from query string')
                 }
        else:
            return {
                'isBase64Encoded': 0,
                'statusCode': 400,
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': error_page('Error: missing query string')
            }  
        action = '/' + event['requestContext']['stage'] + event['requestContext']['resourcePath']
        params = ''
        try:
            for key, val in event['queryStringParameters'].items(): # Copy initial query params to hidden form inputs
                params += '<INPUT type="hidden" name="' + html.escape(key) + '" value="' + html.escape(val) + '" />'
        except:
            params = ''
        return {
            'isBase64Encoded': 0,
            'statusCode': 200,
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'body': login_page(action, params)
        }
    elif (event['requestContext']['httpMethod'] == 'POST'):
        try:
            params = dict([p.split('=') for p in event['body'].split('&')])
        except:
            params = {}
        if ('cancel' in params.keys()):
            status = '410' # The user cancelled the authentication request
            principal = ''
            auth =''
        elif (checkpwd(params['username'], params['password'])):
            status = '200' # Successfull authentication
            principal = params['username']
            auth = 'pwd'
        else:
            #status = '570' # Authentication declined, Apache/mod_ucam_webauth doesn't like
            #principal = ''
            #auth = ''
            return {
                'isBase64Encoded': 0,
                'statusCode': 400,
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': error_page('Error: bad username and/or password')
            }
        if ('params' in params.keys()):
            echo = unquote_plus(params['params']) # Required because POST is application/x-www-form-urlencoded
            echo = html.unescape(echo)
            echo = echo.replace('%', '%25').replace('!', '%21') # Reflect inbound parameters
        else:
            echo = ''
        url = unquote_plus(params['url']) # Required because POST is application/x-www-form-urlencoded
        url = html.unescape(url)
        url_safe = url.replace('%', '%25').replace('!', '%21')
        response = ''
        response += '3' # params['ver'] # ver [required]
        response += '!' + status # status [required]
        response += '!' # msg [optional]
        response += '!' + wls_tstamp() # issue [required]
        response += '!' + event['requestContext']['requestId'] # id [required]
        response += '!' + url_safe # url [required]
        response += '!' + principal # principal [required, only if status == 200]
        response += '!' + 'current' # ptags [optional]
        response += '!' + auth # auth [required, only if iact]
        response += '!' # sso [required, only if auth == ''] - not implemented
        response += '!' # life [optional] - not implemented (depends on sso, also not implemented)
        response += '!' + echo # params [required, must match inbound params if present]
        response += '!1!' + wls_sign(response) # kid (always 1) + sig
        urlparts = list(urlparse(url))
        query = dict(parse_qsl(urlparts[4]))
        query.update({"WLS-Response": response})
        urlparts[4] = urlencode(query, False, '!')
        redirect = urlunparse(urlparts)
        return {
            'isBase64Encoded': 0,
            'statusCode': 302,
            'headers': {'Content-Type': 'text/html; charset=utf-8', 'Location': redirect},
            'body': ''
        }
    else:
        return {
            'isBase64Encoded': 0,
            'statusCode': 405,
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'body': error_page('Error: unsupported method')
        }
