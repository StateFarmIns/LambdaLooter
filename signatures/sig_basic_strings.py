"""
Signature filename must start with "sig_"
Signature file requires the following dictionary format:

    Signature dictionary must be name 'Sig'
    Dictonary must include the following:
    Sig = {
        'title': 'Quick title of what signature we are looking for',
        'pattern': 'Formatting the set of strings in the lookupstrings variable',
        'caption': 'Description of the pattern you are matching',
        'filters': ['List of false positive regex filters' \],
    }
"""

lookupstrings = [
    'password',
    'pwd',
    'authoriztion',
    'ejY',
    'username',
    'vault_pw',
    'oauth_token'
]

Sig = {
    'title': 'Basic String Searches',
    'types': [
        {
            'type': 'regex',
            'pattern': '(^.*?({0}).*?$)'.format('|'.join(lookupstrings)),
            'caption': 'REGEX: Basic Strings',
            'filters': [],
        }
    ]
}

