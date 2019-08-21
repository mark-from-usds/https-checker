# https-checker
Check HSTS on all of a site's possible IP addresses

## setup and usage
```
https-checker$ pipenv install
https-checker$ pipenv run python -m unittest discover -s test
https-checker$ pipenv run python https_checker.py the-most-american-web-site.gov
```

The `package-lambda` shell script will build a ZIP file suitable for upload to AWS Lambda.
