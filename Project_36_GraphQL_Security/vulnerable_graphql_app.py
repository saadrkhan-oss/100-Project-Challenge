#!/usr/bin/env python3
"""
Vulnerable GraphQL App (Project #36 — LEARNING ONLY)
Deliberately insecure. Never deploy.

Uses Flask + Graphene. Exposes users without auth, allows
introspection, and doesn't sanitize inputs.
"""
from flask import Flask, request, jsonify
import graphene
import json

app = Flask(__name__)

# In-memory database
USERS = {
    1: {'id': 1, 'username': 'admin',  'email': 'admin@example.com',  'password': '5f4dcc3b5aa765d61d8327deb882cf99', 'role': 'admin',  'isAdmin': True},
    2: {'id': 2, 'username': 'alice',  'email': 'alice@example.com',  'password': 'e10adc3949ba59abbe56e057f20f883e', 'role': 'user',   'isAdmin': False},
    3: {'id': 3, 'username': 'bob',    'email': 'bob@example.com',    'password': '25d55ad283aa400af464c76d713c07ad', 'role': 'user',   'isAdmin': False},
}

POSTS = {
    1: {'id': 1, 'title': 'Admin Post',  'content': 'Welcome', 'author_id': 1},
    2: {'id': 2, 'title': 'Alice Post',  'content': 'Hello',   'author_id': 2},
}

# ==================================================================== #
# Graphene schema
# ==================================================================== #
class Post(graphene.ObjectType):
    id = graphene.Int()
    title = graphene.String()
    content = graphene.String()
    author = graphene.Field(lambda: User)

    def resolve_author(self, info):
        return USERS.get(self.__dict__.get('author_id', 0))

class User(graphene.ObjectType):
    id = graphene.Int()
    username = graphene.String()
    email = graphene.String()
    password = graphene.String()      # VULNERABLE: password exposed
    role = graphene.String()
    is_admin = graphene.Boolean()
    posts = graphene.List(Post)

class Query(graphene.ObjectType):
    user = graphene.Field(User, id=graphene.Int(required=True))
    users = graphene.List(User)
    post = graphene.Field(Post, id=graphene.Int(required=True))

    def resolve_user(self, info, id):
        # VULNERABLE: no auth, no authorization
        return USERS.get(id)

    def resolve_users(self, info):
        # VULNERABLE: returns all users
        return list(USERS.values())

    def resolve_post(self, info, id):
        return POSTS.get(id)

class CreateUser(graphene.Mutation):
    class Arguments:
        username = graphene.String(required=True)
        email = graphene.String(required=True)
        password = graphene.String(required=True)
        role = graphene.String(default_value='user')

    user = graphene.Field(User)

    def mutate(self, info, username, email, password, role='user'):
        new_id = max(USERS.keys()) + 1 if USERS else 1
        USERS[new_id] = {
            'id': new_id, 'username': username, 'email': email,
            'password': password, 'role': role,
            'isAdmin': (role == 'admin'),
        }
        return CreateUser(user=USERS[new_id])

class CreatePost(graphene.Mutation):
    class Arguments:
        title = graphene.String(required=True)
        content = graphene.String(required=True)
        author_id = graphene.Int(required=True)

    post = graphene.Field(Post)

    def mutate(self, info, title, content, author_id):
        new_id = max(POSTS.keys()) + 1 if POSTS else 1
        POSTS[new_id] = {
            'id': new_id, 'title': title, 'content': content,
            'author_id': author_id,
        }
        return CreatePost(post=POSTS[new_id])

class Mutation(graphene.ObjectType):
    create_user = CreateUser.Field()
    create_post = CreatePost.Field()

schema = graphene.Schema(query=Query, mutation=Mutation)

# ==================================================================== #
# Flask route
# ==================================================================== #
@app.route('/graphql', methods=['GET', 'POST'])
@app.route('/api/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    if request.method == 'GET':
        # Simple playground / health check
        return '''
        <html><body>
        <h1>Vulnerable GraphQL Endpoint</h1>
        <p>POST JSON to /graphql with {"query": "..."}</p>
        </body></html>
        '''

    try:
        # Array batching support (VULNERABLE)
        data = request.get_json(force=True)
        if isinstance(data, list):
            results = []
            for item in data:
                query = item.get('query', '')
                result = schema.execute(query)
                results.append({'data': result.data, 'errors': [str(e) for e in (result.errors or [])]})
            return jsonify(results)

        query = data.get('query', '')
        result = schema.execute(query)
        response = {}
        if result.data is not None:
            response['data'] = result.data
        if result.errors:
            response['errors'] = [str(e) for e in result.errors]
        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/')
def home():
    return '''<html><body>
    <h1>Vulnerable GraphQL App</h1>
    <p>Endpoint: <a href="/graphql">/graphql</a></p>
    </body></html>'''

if __name__ == '__main__':
    print("[!] Vulnerable GraphQL app starting on http://localhost:5000/graphql")
    print("[!] For local learning only")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)