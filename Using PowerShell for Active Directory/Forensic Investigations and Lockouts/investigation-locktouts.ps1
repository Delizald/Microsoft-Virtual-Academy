#Metadata
#"Who did this?"

#Use this when the big accoutn and groups have been renamed
#Extrapolate other privileged groups and accounts using the formula below to construct their SIDs

Import-Module ActiveDirectory

#Calculate the SIDs of the highest privileged user and groups
$SID_GROUP_EA = [System.Security.Principal.SecurityIdentifier]"$((Get-ADDomain -Identity (Get-ADForest).Name).DomainSID)-519"
$SID_GROUP_DA = [System.Security.Principal.SecurityIdentifier]"$((Get-ADDomain).DomainSID)-512"
$SID_GROUP_AD = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$SID_USER_AD = [System.Security.Principal.SecurityIdentifier]"$((Get-ADDomain).DomainSID)-500"

#Get each one of these privileged security principlas
Get-ADGroup $SID_GROUP_EA -Properties * -Server (Get-ADForest).Name
Get-ADGroup $SID_GROUP_DA -Properties *
Get-ADGroup $SID_GROUP_AD -Properties *
Get-ADUser  $SID_USER_AD  -Properties *

#REPADMIN
#Get-ADReplicationAttributeMetadata
#Return the replication metadata for one or more Active Directory replication partners
repadmin /ShowObjMeta localhost "CN=Administrator,CN=Users,DC=company,DC=com"
#Wrapped Table
Get-ADUser Administrator |
    Get-ADReplicationAttributeMetadata -Server localhost |
    Format-Table LocalChangeUsn, LastOriginatingChangeDirectoryServerIdentity
#Out-GridView
Get-ADUser Administrator | 
    Get-ADReplicationAttributeMetadata -Server localhost
    Select-Object LocalChangeUsn, LastOriginatingChangeDirectoryServerIdentity, LastOriginatingChange |
    Out-GridView

#Make attribute updates
Get-ADUser Administrator | Get-ADReplicationAttributeMetadata -Server localhost | ogv
Set-ADUser Administrator -GivenName "Big Account"
Set-ADUser Administrator -GivenName "Biggest Account"
Get-ADUser Administrator | Get-ADReplicationAttributeMetadata -Server localhost | ? AttributeName
#Show all attributes that have been updated since creation
Get-ADUser Administrator |
    Get-ADReplicationAttributeMetadata -Server localhost |
    Where-Object Version -GT 1 |
    Format-Table AttributeName, Version, LastOriginatingChangeTime

#Shhow a user's group memerships and the dats they were added to those groups
Import-Module ActiveDirectory

$username = "elizaldd"
$userobj = Get-ADUser $username

Get-ADUser $userobj.DistinguishedName -Properties memberOf |
    Select-Object -ExpandProperty memberOf | 
    ForEach-Object {
        Get-ADReplicationAttributeMetadata $_ -Server localhost -ShowAllLinkedValues |
            Where-Object {$_.AttributeName -eq 'member' -and
            $_AttributeValue -eq $userobj.DistinguishedName} |
            Select-Object FirstOriginatingCreateTime, Object, AttributeValue
    } | Sort-Object FirstOriginatingCreateTime -Descending | Out-GridView


#EventLogs
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
$Events = @()
ForEach ($DC in $DCs){
    "Getting events from $($DC.DC)"

    #Must enable the firewall rule for remote EventLog management
    Invoke-Command -ComputerName $DC.DC -ScriptBlock {Get-NetFirewallRule -Name *eventlog* | Where-Object {$_.Enabled -eq 'False'} | Enable-NetFirewallRule -Verbose }

    #Filter for the userId in the event message properties
    #Filter for the last 24 hours
    $Events += Get-WinEvent -ComputerName $DC.DC -Filter $xmlFilter
}

ForEach ($Event in $Events){
    #Convert the event to XML
    $eventXML = [xml].$Event.ToXml()
    #Iterate through the XML message properties
    For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count;i++){
        #Append these as object properties
        Add-Member -InputObject $Event -MemberType NoteProperty -Force `
            -Name $eventXML.Event.EventData.Data[$i].name `
            -Value $eventXML.Event.EventData.Data[$i].'#text'
    }
}

#View the lockout details
$Events | Where-Object {$_.TargetUserName -eq $user} | Select-Object TargetUserName,IPAddress
$Events | fl *
$Events | Select-Object * -ExcludeProperty Message | Out-GridView
$Events | Export-Csv .\accLockout.csv -NoTypeInformation

#View current password lockout policy
Get-ADDefaultDomainPasswordPolicy -Current LoggedOnUser

#Any locket out accounts?
Search-ADAccount -LockedOut

#Setup the lockout report
$report = @()
$user = "elizaldd"

#Choose the DCs to crawl
$DC = Get-ADDomainController -Filter * | 
    Select-Object HostName, IPV4Address, Site, OperatingSystem, OperationMasterRoles | 
    Out-Grid-View -Title "Select the DCs to query" -PassThru | 
    Select-Object -ExpandProperty HostName

#Find the lockout stats for that user on all selected DCs
ForEach ($DC in $DCs){
    $report += Get-ADUser $user -Server $DC -ErrorAction Continue `
    -Properties cn, LockedOut, pwdLastSet, badPwdCount, badPasswordTime, lastLogon, lastLogoff |
    Select-Object *, @{name='DC';expression={$DC}}
}

#Permissions
Get-ACL

#ntSecurityDescriptor property
$ou = "OU=Users,DC=company,DC=com"
(Get-ADObject $ou -Property ntSecurityDescriptor | Select-Object -ExpandProperty ntSecurityDescriptor).Access

#Show assigned permissions for a user or group
$filter = Read-Host "Enter the user or group name to eacrh in OU permissions"
$report | 
    Where-Object {$_.IdentityReference -like "*$filter*"} |
    Select-Object IdentityReference, objectTypeName, OrganizationalUnit, IsInherited -Unique |
    Sort-Object IdentityReference

$report | ogv