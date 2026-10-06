#!/bin/bash
# GraphQL PoC
curl -s -X POST "http://localhost:5000/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 2) { id username email password } }"}'
echo ""
