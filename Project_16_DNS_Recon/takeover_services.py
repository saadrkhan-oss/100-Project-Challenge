"""
Subdomain Takeover Service Database
Project #16: DNS Enumeration & Subdomain Takeover Advanced
"""

# Known services vulnerable to subdomain takeover
# Format: {cname_pattern: {'service': name, 'fingerprint': HTTP response pattern}}
TAKEOVER_SERVICES = {
    'github.io': {
        'service': 'GitHub Pages',
        'fingerprint': "There isn't a GitHub Pages site here",
        'severity': 'HIGH'
    },
    'herokuapp.com': {
        'service': 'Heroku',
        'fingerprint': 'No such app',
        'severity': 'HIGH'
    },
    's3.amazonaws.com': {
        'service': 'AWS S3',
        'fingerprint': 'NoSuchBucket',
        'severity': 'HIGH'
    },
    'azurewebsites.net': {
        'service': 'Azure App Service',
        'fingerprint': '404 Web Site not found',
        'severity': 'HIGH'
    },
    'cloudfront.net': {
        'service': 'AWS CloudFront',
        'fingerprint': 'Bad request',
        'severity': 'MEDIUM'
    },
    'readthedocs.io': {
        'service': 'ReadTheDocs',
        'fingerprint': '404',
        'severity': 'MEDIUM'
    },
    'surge.sh': {
        'service': 'Surge.sh',
        'fingerprint': 'project not found',
        'severity': 'MEDIUM'
    },
    'bitbucket.io': {
        'service': 'Bitbucket',
        'fingerprint': 'Repository not found',
        'severity': 'HIGH'
    },
    'netlify.app': {
        'service': 'Netlify',
        'fingerprint': 'Not Found - Request ID',
        'severity': 'MEDIUM'
    },
    'vercel.app': {
        'service': 'Vercel',
        'fingerprint': 'The deployment could not be found',
        'severity': 'MEDIUM'
    },
    'ghost.io': {
        'service': 'Ghost',
        'fingerprint': 'Domain error',
        'severity': 'MEDIUM'
    },
    'zendesk.com': {
        'service': 'Zendesk',
        'fingerprint': 'Help Center Closed',
        'severity': 'MEDIUM'
    },
    'statuspage.io': {
        'service': 'Statuspage',
        'fingerprint': 'Status page not found',
        'severity': 'MEDIUM'
    },
    'fastly.net': {
        'service': 'Fastly',
        'fingerprint': 'Fastly error: unknown domain',
        'severity': 'MEDIUM'
    },
    'pantheonsite.io': {
        'service': 'Pantheon',
        'fingerprint': 'The gods are wise',
        'severity': 'MEDIUM'
    },
    'wordpress.com': {
        'service': 'WordPress.com',
        'fingerprint': 'Do you want to register',
        'severity': 'MEDIUM'
    },
    'tumblr.com': {
        'service': 'Tumblr',
        'fingerprint': "There's nothing here",
        'severity': 'MEDIUM'
    },
    'shopify.com': {
        'service': 'Shopify',
        'fingerprint': 'Sorry, this shop is currently unavailable',
        'severity': 'MEDIUM'
    },
    'wpengine.com': {
        'service': 'WP Engine',
        'fingerprint': 'The site you were looking for couldn\'t be found',
        'severity': 'MEDIUM'
    },
    'desk.com': {
        'service': 'Desk.com',
        'fingerprint': 'This page is reserved for future use',
        'severity': 'MEDIUM'
    },
    'teamwork.com': {
        'service': 'TeamWork',
        'fingerprint': 'Oops - We didn\'t find your site',
        'severity': 'MEDIUM'
    },
    'uservoice.com': {
        'service': 'UserVoice',
        'fingerprint': 'This UserVoice subdomain is currently available',
        'severity': 'MEDIUM'
    },
}

# Mail security record patterns
SPF_PATTERN = r'v=spf1'
DKIM_PATTERN = r'v=DKIM1'
DMARC_PREFIX = '_dmarc'
DMARC_PATTERN = r'v=DMARC1'

# DNSSEC algorithm identifiers
DNSSEC_ALGORITHMS = {
    1: 'RSAMD5',
    3: 'DSA',
    5: 'RSASHA1',
    7: 'RSASHA1-NSEC3-SHA1',
    8: 'RSASHA256',
    10: 'RSASHA512',
    13: 'ECDSAP256SHA256',
    14: 'ECDSAP384SHA384',
    15: 'ED25519',
    16: 'ED448',
}