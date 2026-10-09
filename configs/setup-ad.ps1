# setup-ad.ps1
# Builds the Himal Traders structure in lab.local: OUs, groups and users.
# Run on DC01 AFTER it has been promoted to a domain controller, as LAB\Administrator.
# LAB ONLY: every user gets the same starting password. Real companies never do this.

Import-Module ActiveDirectory

$domainDN = (Get-ADDomain).DistinguishedName      # DC=lab,DC=local
$company  = "HimalTraders"
$companyDN = "OU=$company,$domainDN"

# ---- 1. Organizational Units (folders for AD objects) ----
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$company'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $company -Path $domainDN
}
foreach ($ou in "Staff", "Admins", "Groups", "Servers", "ServiceAccounts") {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -SearchBase $companyDN -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $companyDN
    }
}

# ---- 2. Department groups ----
foreach ($group in "Finance", "Sales", "IT") {
    if (-not (Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $group -GroupScope Global -GroupCategory Security -Path "OU=Groups,$companyDN"
    }
}

# ---- 3. Starting password for all lab users ----
$password = Read-Host "Enter a starting password for all lab users" -AsSecureString

# ---- 4. Staff (normal accounts) ----
$staff = @(
    @{ First = "Ram";   Last = "Sharma"; Sam = "ram.sharma";  Dept = "Finance" },
    @{ First = "Sita";  Last = "Thapa";  Sam = "sita.thapa";  Dept = "Sales"   },
    @{ First = "Hari";  Last = "Karki";  Sam = "hari.karki";  Dept = "IT"      },
    @{ First = "Gita";  Last = "Rai";    Sam = "gita.rai";    Dept = "Finance" },
    @{ First = "Bikash";Last = "Gurung"; Sam = "bikash.gurung"; Dept = "Sales" }
)

foreach ($u in $staff) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "$($u.First) $($u.Last)" `
            -GivenName $u.First -Surname $u.Last `
            -SamAccountName $u.Sam -UserPrincipalName "$($u.Sam)@lab.local" `
            -Department $u.Dept -Path "OU=Staff,$companyDN" `
            -AccountPassword $password -Enabled $true
    }
    Add-ADGroupMember -Identity $u.Dept -Members $u.Sam
}

# ---- 5. Separate admin account for the IT person (best practice) ----
if (-not (Get-ADUser -Filter "SamAccountName -eq 'hari.admin'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name "Hari Karki (Admin)" -SamAccountName "hari.admin" `
        -UserPrincipalName "hari.admin@lab.local" -Path "OU=Admins,$companyDN" `
        -AccountPassword $password -Enabled $true
}
Add-ADGroupMember -Identity "Domain Admins" -Members "hari.admin"

# ---- 6. Show the result ----
Write-Host "`nUsers in Himal Traders:" -ForegroundColor Green
Get-ADUser -Filter * -SearchBase $companyDN -Properties Department |
    Select-Object Name, SamAccountName, Department, Enabled | Format-Table -AutoSize

Write-Host "Domain Admins:" -ForegroundColor Green
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName | Format-Table -AutoSize
