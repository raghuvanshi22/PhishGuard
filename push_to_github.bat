@echo off
echo Initializing Git...
git init

echo Adding files...
git add .

echo Committing...
git commit -m "Initial commit: PhishGuard 2.0"

echo Renaming branch to main...
git branch -M main

echo Adding remote...
git remote remove origin
git remote add origin https://github.com/raghuvanshi22/PhishGuard

echo Pushing to GitHub (forcing local version)...
git push -u origin main --force

echo Done!
pause
