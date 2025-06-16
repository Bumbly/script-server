$response = Invoke-WebRequest -Uri "http://localhost:5555/auth/config" -UseBasicParsing
Write-Host "Config Response:"
$response.Content | ConvertFrom-Json | Format-List

Write-Host "`nTesting redirect (check browser):"
Start-Process "http://localhost:5555/auth/okta"