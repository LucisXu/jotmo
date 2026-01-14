#!/bin/bash
TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"xuhuayan","password":"xuhuayan"}' http://localhost:8088/api/login | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "Token: ${TOKEN:0:30}..."
curl -s -X POST http://localhost:8088/api/categories/regenerate-names -H "Authorization: Bearer $TOKEN"
