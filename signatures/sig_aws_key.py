'''
Signature filename must start with 'sig_'
Signature file requires the following dictionary format:

type = regex or match

    Signature dictionary must be name 'Sig'
    Dictonary must include the following:
    Sig = {
        'title': 'Quick title of what signatures file we are using',
        'type': 'Match or Regex.',
		'pattern: 'The regex pattern that you want to search for',
		'caption': 'Description of the pattern you are matching',
        'filters': ['List of false positive regex filters' \],
    }
'''

Sig = {
    'title': 'AWS Keys',
    'types': [
        {
	'type': 'regex',
	'pattern': '((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})',
	'caption': 'REGEX: Potential AWS Token',
	'filters': [
		'\x00'
	],
        },
	{
	'type': 'match',
	'pattern': 'password=',
	'caption': 'Potential password',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '{encrypt}',
	'caption': 'Potential password',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '{encrypt_aes}',
	'caption': 'Potential password',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '\'password\':',
	'caption': 'Potential password',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '\'pass\':',
	'caption': 'Potential password',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '\'secret\':',
	'caption': 'Potential secret',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '\'jwt\':',
	'caption': 'Potential JWT Token',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': 'token:',
	'caption': 'Potential Token',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': 'authorization: basic ',
	'caption': 'Potential Basic Auth Creds',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '_secret',
	'caption': 'Potential secret',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': 'secret_',
	'caption': 'Potential secret',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '_client',
	'caption': 'Potential client id',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': 'client_',
	'caption': 'Potential client id',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '\\bs\\.[a-zA-Z0-9]{24}\\b',
	'caption': 'REGEX: VAULT Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[\\b\']s\\.[a-zA-Z0-9]{24}[\\b\']',
	'caption': 'REGEX: VAULT Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
	'caption': 'REGEX: Slack Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '-----BEGIN RSA PRIVATE KEY-----',
	'caption': 'RSA Private Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '-----BEGIN DSA PRIVATE KEY-----',
	'caption': 'DSA Private Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '-----BEGIN EC PRIVATE KEY-----',
	'caption': 'EC Private Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'match',
	'pattern': '-----BEGIN PGP PRIVATE KEY BLOCK-----',
	'caption': 'PGP Private Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
	'caption': 'REGEX: Amazon MWS Auth Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'da2-[a-z0-9]{26}',
	'caption': 'REGEX: AWS AppSync GraphQL Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'EAACEdEose0cBA[0-9A-Za-z]+',
	'caption': 'REGEX: Facebook Access Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[fF][aA][cC][eE][bB][oO][oO][kK].*[\'|\"][0-9a-f]{32}[\'|\"]',
	'caption': 'REGEX: Facebook OAuth Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[aA][pP][iI]_?[kK][eE][yY].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]',
	'caption': 'REGEX:  Generic API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[sS][eE][cC][rR][eE][tT].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]',
	'caption': 'REGEX: Generic Secret Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'AIza[0-9A-Za-z\\-_]{35}',
	'caption': 'REGEX: Google API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'AIza[0-9A-Za-z\\-_]{35}',
	'caption': 'REGEX: Google Cloud Platform API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
	'caption': 'REGEX: Google Cloud Platform OAuth Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'AIza[0-9A-Za-z\\-_]{35}',
	'caption': 'REGEX:  Google Drive API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
	'caption': 'REGEX: Google Drive OAuth Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '\"type\": \"service_account\"',
	'caption': 'REGEX: Google (GCP) Service-account Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
	'caption': 'REGEX: Google Gmail OAut Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'AIza[0-9A-Za-z\\-_]{35}',
	'caption': 'REGEX: Google Gmail API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'ya29\\.[0-9A-Za-z\\-_]+',
	'caption': 'REGEX: Google OAuth Access Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'AIza[0-9A-Za-z\\-_]{35}',
	'caption': 'REGEX: Google YouTube API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
	'caption': 'REGEX:  Google YouTube OAuth Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
	'caption': 'REGEX:  Heroku API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[0-9a-f]{32}-us[0-9]{1,2}',
	'caption': 'REGEX:  MailChimp API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'key-[0-9a-zA-Z]{32}',
	'caption': 'REGEX:  Mailgun API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"\'\\s]',
	'caption': 'REGEX:  Password in URL Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
	'caption': 'REGEX:  PayPal Braintree Access Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'sk_live_[0-9a-z]{32}',
	'caption': 'REGEX:  Picatic API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
	'caption': 'REGEX:  Slack Webhook Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'sk_live_[0-9a-zA-Z]{24}',
	'caption': 'REGEX:  Stripe API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'rk_live_[0-9a-zA-Z]{24}',
	'caption': 'REGEX:  Stripe Restricted API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'sq0atp-[0-9A-Za-z\\-_]{22}"',
	'caption': 'REGEX:  Square Access Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'q0csp-[0-9A-Za-z\\-_]{43}',
	'caption': 'REGEX:  Square OAuth Secret Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[0-9]+:AA[0-9A-Za-z\\-_]{33}',
	'caption': 'REGEX:  Telegram Bot API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'SK[0-9a-fA-F]{32}',
	'caption': 'REGEX:  Twilio API Key Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
	'caption': 'REGEX:  Twitter Access Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': '[tT][wW][iI][tT][tT][eE][rR].*[\'|\"][0-9a-zA-Z]{35,44}[\'|\"]',
	'caption': 'REGEX:  Twitter OAuth Token Found',
	'filters': [
		'\x00'
	],
	},
	{
	'type': 'regex',
	'pattern': 'GLPAT_[0-9a-zA-Z\\-_]{20}',
	'caption': 'REGEX: Potential password',
	'filters': [
		'\x00'
	],
	}
    ]
}

