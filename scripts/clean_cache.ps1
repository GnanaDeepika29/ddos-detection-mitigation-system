# Windows Script to deeply clean pycache and caches to save memory
Write-Host "Cleaning __pycache__ folders..."
Get-ChildItem -Path "D:\ddos-detection-mitigation-system" -Directory -Filter "__pycache__" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse

Write-Host "Cleaning .pytest_cache folders..."
Get-ChildItem -Path "D:\ddos-detection-mitigation-system" -Directory -Filter ".pytest_cache" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse

Write-Host "Cleaning up dangling docker images to save space..."
docker system prune -f

Write-Host "Cache cleanup complete!"
