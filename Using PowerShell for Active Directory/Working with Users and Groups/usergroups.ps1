#Working with users and groups

#Creating new users
Get-Command -Syntax New-ADUser

#By itself
New-ADUser David
Get-User David
$user = Get-User David
$user | gm
$user = Get-User David -Properties *
$user = Set-ADObject -Description "Regular person"

#New Accounts are disabled b default
Enable-ADAccount David

#Set password & enable account
$pw = Read-Host "What is the password?" -AsSecureString
Set-ADAccountPassword David -NewPassword $pw
Enable-ADAccount David

#New user, set password and enable
New-ADUser David -Enabled $True -AccountPassword $(ConvertTo-SecureString "Password" -AsPlainText -Force)

#View Users from CSV
Import-CSV ".\users.csv" | Out-GridView

#Import users from CSV
Import-CSV ".\users.csv" | New-ADUser

#Import users from CSV, set password, enable
Import-CSV ".\users.csv" | 
    New-ADUser ` 
        -Enabled $True `
        -AccountPassword $(ConvertTo-SecureString "Password" -AsPlainText -Force)

#Import users from CSV, set destination OU
Import-CSV ".\users.csv" | 
    New-ADUser ` 
        -Enabled $True `
        -AccountPassword $(ConvertTo-SecureString "Password" -AsPlainText -Force) `
        -Company 'My company' `
        -Path 'OU=NewUsers,DC=company,DC=com'

#Import users from CSV when the columns do not match
New-ADOrganizationalUnit NewUsers

Import-Csv ".\users.csv" | ogv

Get-ADUser -Filter 'Office -eq "MVA"' | ogv
#################################################################################################3
#Groups

$rootDN = (Get-ADDomain).DistinguishedName
New-ADGroup -Path "OU=HR,$rootDN" -Name "DL-HR" -GroupScope DomainLocal -GroupCategory Distribution

New-ADGroup -SamAccountName 'G_Purchasing' -GroupScope Global -GroupCategory Security
Get-ADGroup G_Purchasing | Add-ADGroupMember David

Add-ADGroupMember -Identity G_Purchasing -Members (Get-ADUser David)

New-ADOrganizationalUnit Engineering

###################################################################################################
#Updating
#Find some odd user properties
(Get-ADObject -Filter 'objectclass  -eq "classSchema" -and name -eq "user"' -SearchBase(Get-ADRootDSE))

#Other attributes for properties not available as parameters
New-ADUser David -Description "I'm a test account" -OtherAttributes @{carLicense="ASDASD"}

Set-ADUser David -Replace @{carLicense='LOL'}
Get-ADUser David -Properties carLicense

Set-ADUser David -Add @{carLicense='A111'}
Set-ADUser David -Clear carLicense


Get-ADComputer CVCOMPUTER1 -Properties ServicePrincipalName | Select-Object -ExcludeProperty ServicePrincipalNames
Set-ADComputer CVCOMPUTER1 -ServicePrincipalNames @{Add='HTTP/myapp.cvmember1.cohovineyard.con:8080'}

<#
Set-ADAccountControl
Set-ADAccountExpiration
Set-ADAccountPassword
#>

Set-ADAccountControl David -PasswordNeverExpires $True
Set-ADAccountControl David -PasswordNeverExpires $False

#Account unlock
Read-Host "Enter the user account to unlock" | Unlock-ADAccount

#hHow to copy user attributes to another field
#Find all accounts with a a Deparment
#Copy that value into Description

Get-ADUser -LDAPFilter '(Department=*)' -Properties Description,Department |
    Select-Object * -First 5 |
    ForEach-Object {Set-ADObject -Identity $_.DistinguishedName `
    -Replace @{Description=$($_.Department)}}

#Updating groups
Get-ADGroup Legal

Add-ADGroupMember -Identity Legal -Members Ron
Add-ADGroupMember -Identity -Members (Get-ADUser -Filter 'Office -eq "MVA"' )

Get-ADGroup Legal -Properties Members, MemberOf
Get-ADGroup Legal -Properties Members, MemberOf | Select-Object -ExcludeProperty Members
Get-ADGroupMember Legal | ogv

#Deleting
Get-ADUser -Filter 'Office -eq "MVA"' | Remove-ADUser -WhatIf

Get-ADUser -Filter 'Office -eq "MVA"' | Remove-ADUser 

Get-ADUser -Filter 'Office -eq "MVA"' | Remove-ADUser -Confirm:$False

New-ADComputer MP3Server
Get-ADComputer MP3Server
Remove-ADComputer MP3Server -WhatIf
Get-ADComputer MP3Server | Remove-ADObject -Recursive

#Delete objects by Batches
do{
    $query = Get-ADObject -LDAPFilter '(&(objectClass=foo)(attribute=value))' -Server dc1.company,com
    $query = Remove-ADObject -Confirm:$False -Recurse
    Start-Sleep -Seconds (15*60)
}while($query)