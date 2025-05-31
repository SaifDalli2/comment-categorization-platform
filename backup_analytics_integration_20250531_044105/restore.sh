#!/bin/bash
echo "Restoring Gateway Service from backup..."
cp -f package.json ../
cp -f server.js ../
cp -f .env ../
[ -d routes ] && cp -r routes ../ 
[ -d services ] && cp -r services ../
[ -d middleware ] && cp -r middleware ../
echo "Backup restored. Run 'npm install' to reinstall dependencies."
