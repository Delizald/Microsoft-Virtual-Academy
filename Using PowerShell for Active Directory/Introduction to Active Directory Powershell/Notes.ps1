#Version history
<#
Former scripting technologies:
WMI
ADODB
CMD utilities
ADSI (.NET Foundation)
#>

<#
RSAT AD OS Module. Powershell Verisons:
V1: Windows 7, Windows Server 2008 R2
V2: Windows 8, Windows Server 2012
V3: Windows 8.1, Windows Server 2012 R2
#>

<#
Server - DC with AD Web Service
#>


#New-PSSession
#Import-Module -PSSession
#Get-ADReplicationSubnet (not available in w7)

#ADAC (Active Directory Administrative Center) History

#Get-ADObject
#Set-ADUser

Import-Module activedirectory
Get-Command -Module activedirectory

Get-PSProvider

Get-ADDomain

#List of all domain controllers
Get-ADDomainController -Filter * | Format-Table Name, Domain, Forest, Site, IPv4Adddress -AutoSize

#Account unlock
Read-Host "Enter the user account to unlock" | Unlock-ADAccount

#Password reset
Set-ADAccountPassword (Read-Host 'User') -Reset


