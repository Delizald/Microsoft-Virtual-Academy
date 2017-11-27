#Querying
#LDAP Basics

#View Searcher properties
[ADSISEARCHER][ADSI]""

Get-Command Get-ADObject -Syntax

#-Identity
#samAccountName
Get-ADUser -Identity elizaldd
Get-ADUser -Identity $env:USERNAME

#SID security identifier
Get-ADUser -Identity S-1-5-21-29999-3434343433
Get-ADUser -Identity (whoami /user /fo /csv | ConvertFrom-CSV | Select-Object -ExpandProperty SID)
#DistinguishedName
Get-ADUser -Identity 'CN=elizaldd,OU=People,DC=COMPANY,DC=COM'
#ObjectGUID
Get-ADUser -Identity 9111114dcc-cc57-4bcv-asdsad

#Nerver use "filter star property star"
#Get-ADOBject -Filter * -Property *

#-SearchBase
#Popular search locations
Get-ADRootDSE | Select-Object -ExpandProperty namingContexts
($d = Get-ADRootDSE) | Get-Member -Name *Context | Select-Oject -ExpandProperty Name | % {("{0,-40}")}
($d = Get-ADDomain) | Get-Member -Name *Container | Select-Oject -ExpandProperty Name | % {("{0,-40}")}
($d = Get-ADForest) | Get-Member -Name *Container | Select-Oject -ExpandProperty Name | % {("{0,-40}")}

#users container
Get-ADUser -Filter * -SearchBase(Get-ADDomain).UsersContainer | Format-Wide Name -AutoSize
#Computers container
Get-ADComputer -Filter * -SearchBase(Get-ADDomain).UsersContainer | Format-Wide Name -AutoSize

#List of authorized DHCP servers
Get-ADObject -Filter * -Properties Created `
    -SearchBase ('CN=NetServices,CN=Services') + (Get-ADRootDSE).configurationNamingContext |
    Format-Table Name, Created -AutoSize

#Find a schema attribute
#Which logon attribute is in the global catalog
Get-ADObject -LDAPFilter '(|(cn=Last-Logon)(cn=Last-Logon-Timestamp))' `
-Properties isMemberOfPartalAttributeSet, LdapDisplayName `
-SearchBase (Get-ADRootDSE).schemaNamingContext |
Format-Table Name, LdapDisplayName, isMemberOfPartialAttributeSet -AutoSize


######Schema update report
$schema = Get-ADObject -SearchBase ((Get-ADRootDSE).schemaNamingContext) -SearchScope OneLevel -Filter
"`nDetails of schema objects changed by date:"
$schema | ft objectClass, name, whenCreated, whenChanged -GroupBy event
"`nCount of schema objects changed by date:"
$schema | Group-Object event
###############


#-SearchScope
#Default SearchScope is SubTree
Get-ADObject -Filter * -SearchBase (Get-ADRootDSE).configurationNamingContext
#The object itself
Get-ADObject -Filter * -SearchBase (Get-ADRootDSE).configurationNamingContext -SearchScope Base
#The immediate child level
Get-ADObject -Filter * -SearchBase (Get-ADRootDSE).configurationNamingContext -SearchScope OneLevel
#Recursive child objects
Get-ADObject -Filter * -SearchBase (Get-ADRootDSE).configurationNamingContext -SearchScope SubTree

#-Server
#Local forest
Get-ADForest
#Trusted forest
Get-ADForest -Server dca.wingtip.local

#Global catalog
Get-ADUser administrator -Properties *
Get-ADUser administrator -Properties * -Server localhost:3268
Get-ADUser administrator -Properties * -Server server.server.com

#-Credential
#Alternate credentials
Get-ADForest -Server server.server.com -Credential (Get-Credential domain\administrator)
Get-ADUser administrator -Server server.server.com -Credential (Get-Credential domain\administrator) 

#Filters
# -Filter is a required parameter if username is omitted
# Must use "-property *" to get all properties
# Capture $user and pipe into a set or get so that you don't have to type the DN
#Get-ADUser -Filter *    ->DO NOT USE!
Get-ADUser -Filer {name -eq 'elizaldd'}

#DO NOT DO THIS!
Get-ADUser -filter * -Properties *

#Get all users in OU
Get-ADUser -filter -SearchBase "OU=Migrated,DC=company,DC=com"

Get-ADObject -LDAPFilter '(cn=bob*)'
Get-ADObject -Filter 'CN -like "*bob*"'

Get-ADUser -LDAPFilter '(&(badpwdcount>=5)(badpwdcount=*)'
Get-ADUser -Filter 'badpwdcount -ge 5'