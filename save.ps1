param([string]$m = "lab progress")
Set-Location $HOME\Documents\soc-detection-lab
git add .
git commit -m $m
git push
