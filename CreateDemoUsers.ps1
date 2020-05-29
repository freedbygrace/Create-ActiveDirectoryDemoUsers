# %ForceElevation% = Yes
#Requires -RunAsAdministrator

[CmdletBinding()]
    Param
    (        	
	    [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({(Test-Connection -ComputerName "$_" -Count 4 -Quiet) -and (Test-WSMAN -ComputerName "$_")})]	
        [String]$Server = "$(Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_ComputerSystem" -Property Domain | Select-Object -ExpandProperty Domain)"
    )

#This can be used if you want to be prompted for credentials from the argument
#[String]$Server = "$((Get-Credential -Message "Please Enter Your Credentials" -UserName "$(Get-WMIObject -Namespace "Root\CIMv2" -Class "Win32_ComputerSystem" -Property Domain | Select-Object -ExpandProperty Domain)\$((Get-WMIObject -Namespace "Root\CIMv2" -Class "Win32_ComputerSystem" -Property UserName | Select-Object -ExpandProperty UserName).Split('\')[1])").GetNetworkCredential().Domain)"


#Clear The Screen
    #Clear-Host

#Define Default Action Preferences
    $Global:DebugPreference = "SilentlyContinue"
    $Global:ErrorActionPreference = "Continue"
    $Global:VerbosePreference = "SilentlyContinue"
    $Global:WarningPreference = "Continue"
    $Global:ConfirmPreference = "None"
	
#Define ASCII Characters    
    $Equals = [Char]61
    $Space = [Char]32
    $SingleQuote = [Char]39
    $DoubleQuote = [Char]34
    $NewLine = "`r`n"

#Load WMI Classes
    $Bios = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_Bios" -Property * | Select *
    $ComputerSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_ComputerSystem" -Property * | Select *
    $ComputerSystemProduct = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_ComputerSystemProduct" -Property * | Select *
    $LogicalDisk = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_LogicalDisk" -Property * | Select *
    $OperatingSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_OperatingSystem" -Property * | Select *

#Retrieve property values
	$Make = $ComputerSystem.Manufacturer
    If ($Make -like "*Lenovo*") {$Model = $ComputerSystemProduct.Version} Else {$Model = $ComputerSystem.Model}
    $OSArchitecture = $($OperatingSystem.OSArchitecture).Replace("-bit", "").Replace("32", "86").Insert(0,"x").ToUpper()
    Try {$OSCaption = "{1} {2} {3}" -f $($OperatingSystem.Caption).Split(" ").Trim()} Catch {$OSCaption = "WindowsPE"}
    $OSVersion = [Version]$OperatingSystem.Version
    $OSVersionNumber = [Decimal]("{0}.{1}" -f $($OperatingSystem.Version).Split(".").Trim())
    $PSVersion = [Version]$PSVersionTable.PSVersion
    $OpticalDiskDriveLetter = $LogicalDisk | Where-Object {$_.DriveType -eq 5} | Select -First 1 -ExpandProperty DeviceID
    $SerialNumber = $Bios.SerialNumber.ToUpper()
    Try {([System.__ComObject]$TSEnvironment = New-Object -ComObject "Microsoft.SMS.TSEnvironment");($IsRunningTaskSequence = $True)} Catch {$IsRunningTaskSequence = $False}

#Set Path Variables  
    $ScriptDir = ($MyInvocation.MyCommand.Definition | Split-Path -Parent | Out-String).TrimEnd("\").Trim()
    $ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

#Define Functions
	#Encode a plain text string to a Base64 string
		Function ConvertTo-Base64 
	        { 
                [CmdletBinding(SupportsShouldProcess=$False)]
                    Param
                        (     
                            [Parameter(Mandatory=$True)]
                            [ValidateNotNullOrEmpty()]
                            [String]$String                        
                        )	            

                            $EncodedString = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($String))
	                        Write-Verbose -Message "$($NewLine)`"$($String)`" has been converted to the following Base64 encoded string `"$($EncodedString)`"$($NewLine)"
                    
                    Return $EncodedString
	        }	
		
    #Decode a Base64 string to a plain text string
	    Function ConvertFrom-Base64 
	        {  
                [CmdletBinding(SupportsShouldProcess=$False)]
                    Param
                        (     
                            [Parameter(Mandatory=$True)]
                            [ValidateNotNullOrEmpty()]
                            [ValidatePattern('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')]
                            [String]$String                        
                        )
                
                        $DecodedString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($String))
	                    Write-Verbose -Message "$($NewLine)`"$($String)`" has been converted from the following Base64 encoded string `"$($DecodedString)`"$($NewLine)"
                    
                    Return $DecodedString
	        }

    #Prompt For Choice
        Function Get-Choice
            {
                [CmdletBinding(SupportsShouldProcess=$False)]
                    Param
                        (
                            [Parameter(Mandatory=$True)]
                            [String]$Title,

                            [Parameter(Mandatory=$True)]
                            [String]$Message,
                            
                            [Parameter(Mandatory=$False)]
                            [String]$HelpMessageYes,
                            
                            [Parameter(Mandatory=$False)]
                            [String]$HelpMessageNo
                        )
                        
                            $Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "$($HelpMessageYes)"
                            $No = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "$($HelpMessageNo)"
                            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)
                            $Result = $Host.UI.PromptForChoice($Title, $Message, $Options, 1)
                            Write-Host "$($NewLine)" 
                                Switch ($Result)
                                    {
                                        0 {$Answer = $True}
                                        1 {$Answer = $False}
                                    }

                            Return $Answer
            }

#Start logging script output
    Start-Transcript -Path "$ScriptDir\$ScriptName.log" -Force

#Write information to the screen
    Write-Host "$($NewLine)"
    Write-Host "User = $($ComputerSystem.UserName)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Target Server = $($Server)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Manufacturer = $($Make)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Model = $($Model)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Operating System Architecture = $($OSArchitecture)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Operating System Caption = $($OSCaption)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Operating System Version = $($OperatingSystem.Version)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Powershell Version = $($PSVersion)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Script Directory = $($ScriptDir)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Script Name = $($ScriptName).ps1" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "Running Task Sequence = $($IsRunningTaskSequence)" -BackgroundColor Black -ForegroundColor Cyan
    Write-Host "$($NewLine)"
		
#Perform the following actions based on if a task sequence is running or not (This is a good place to set variables)
    If ($IsRunningTaskSequence -eq $True)
        {

        }
    ElseIf ($IsRunningTaskSequence -eq $False)
        {

        }

#Perform the following actions
    Import-Module -Name 'ActiveDirectory' -Force -NoClobber -ErrorAction Continue
    
    $Domain = Get-ADDomain -Server $Server
    
    $DomainDN = $Domain.DistinguishedName
    
    $Forest = $Domain.Forest

    $NetBiosName = $Domain.NetBiosName
    
    $ParentOUName = "$($NetBiosName)"
    
    If ((Get-ADOrganizationalUnit -Filter "Name -eq `"$ParentOUName`"" -Server $Server -ErrorAction SilentlyContinue))
        {
            $Response = Get-Choice -Title "Organizational Unit Removal Confirmation!" -Message "Do you wish to remove the `'Demo Accounts`' organizational unit and all objects beneath it?" -HelpMessageYes "Removes the `'Demo Accounts`' Organizational Unit and all objects beneath it." -HelpMessageNo "Retains the `'Demo Accounts`' Organizational Unit and all objects beneath it."
            
            If ($Response -eq $True)
                {
                    Get-ADOrganizationalUnit -Filter "Name -eq `"$ParentOUName`"" -SearchScope SubTree -Server $Server | Set-ADObject -ProtectedFromAccidentalDeletion:$False -Server $Server -PassThru | Remove-ADOrganizationalUnit -Confirm:$False -Server $Server -Recursive -Verbose
                }
            ElseIf ($Response -eq $False)
                {
                    Write-Warning -Message "No further processing neccessary. `'$($ScriptName).ps1`' will now exit."
                    Write-Host ""
                    Stop-Transcript
                    Write-Host ""
                    Break
                }
            
            Write-Host ""
        }
    
    Set-ADDefaultDomainPasswordPolicy $Forest -ComplexityEnabled $False -MaxPasswordAge "1000" -PasswordHistoryCount 0 -MinPasswordAge 0 -Server $Server
            
    New-ADOrganizationalUnit -Name $ParentOUName -Path $DomainDN -Verbose -Server $Server -ErrorAction Continue

    $ParentOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$ParentOUName`"" -Server $Server

    $UserOU = New-ADOrganizationalUnit -Name "Users" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue
    $GroupOU = New-ADOrganizationalUnit -Name "Groups" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue
    $RoleOU = New-ADOrganizationalUnit -Name "Roles" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue
    $ServiceAccountOU = New-ADOrganizationalUnit -Name "Service Accounts" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue
    $ServiceGroupOU = New-ADOrganizationalUnit -Name "Service Groups" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue
    $DevicesOU = New-ADOrganizationalUnit -Name "Devices" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue
    $WorkstationsOU = New-ADOrganizationalUnit -Name "Workstations" -Path $DevicesOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue
    $ServersOU = New-ADOrganizationalUnit -Name "Servers" -Path $DevicesOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Continue

    $UserCount = 1000 #Up to 2500 can be created
    
    $InitialPassword = "Password1" #Initial Password for all users
    
    $Company = "$($Domain.NetBiosName), LLC."

    #Create service accounts
        $svca_SQL = New-ADUser -Path $ServiceAccountOU.DistinguishedName -Name "svca_SQL" -GivenName "SQL" -Surname "Administrator" -DisplayName "SQL Administrator" -SamAccountName "svca_SQL" -UserPrincipalName "svca_SQL@$($Forest)" -AccountPassword (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force) -Enabled:$True -PasswordNeverExpires:$True -PassThru -Verbose
        $svca_SCCM = New-ADUser -Path $ServiceAccountOU.DistinguishedName -Name "svca_SCCM" -GivenName "SCCM" -Surname "Administrator" -DisplayName "SCCM Administrator" -SamAccountName "svca_SCCM" -UserPrincipalName "svca_SCCM@$($Forest)" -AccountPassword (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force) -Enabled:$True -PasswordNeverExpires:$True -PassThru -Verbose
        $svca_SCCM_NAA = New-ADUser -Path $ServiceAccountOU.DistinguishedName -Name "svca_SCCM_NAA" -GivenName "SCCM" -Surname "NetworkAccessAccount" -DisplayName "SCCM NetworkAccessAccount" -SamAccountName "svca_SCCM_NAA" -UserPrincipalName "svca_SCCM_NAA@$($Forest)" -AccountPassword (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force) -Enabled:$True -PasswordNeverExpires:$True -PassThru -Verbose
        $svca_IIS = New-ADUser -Path $ServiceAccountOU.DistinguishedName -Name "svca_IIS" -GivenName "IIS" -Surname "Administrator" -DisplayName "IIS Administrator" -SamAccountName "svca_IIS" -UserPrincipalName "svca_IIS@$($Forest)" -AccountPassword (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force) -Enabled:$True -PasswordNeverExpires:$True -PassThru -Verbose
        $svca_WSUS = New-ADUser -Path $ServiceAccountOU.DistinguishedName -Name "svca_WSUS" -GivenName "WSUS" -Surname "Administrator" -DisplayName "WSUS Administrator" -SamAccountName "svca_WSUS" -UserPrincipalName "svca_WSUS@$($Forest)" -AccountPassword (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force) -Enabled:$True -PasswordNeverExpires:$True -PassThru -Verbose
        Add-ADGroupMember -Identity "Domain Admins" -Members @("svca_SQL", "svca_SCCM", "svca_SCCM_NAA", "svca_IIS", "svca_WSUS") -Server $Server -Verbose
        Add-ADGroupMember -Identity "Schema Admins" -Members @("svca_SCCM") -Server $Server -Verbose
    
    #Create Service Groups
        $svcg_WorkstationAdmins = New-ADGroup -Name "svcg_WorkstationAdmins" -SamAccountName "svcg_WorkstationAdmins" -GroupCategory Security -GroupScope Global -Path $ServiceGroupOU.DistinguishedName -Description "Security Group for all workstation administrators"-Server $Server -PassThru -Verbose | Add-ADGroupMember -Members "svca_SCCM" -Server $Server -Verbose
    
    $Content = Import-CSV -Path "$($ScriptDir)\$($ScriptName).csv" -ErrorAction Continue | Get-Random -Count $UserCount | Sort-Object -Property State
    
    $Departments =  (
                        @{"Name" = "Accounting"; Positions = ("Manager", "Accountant", "Data Entry")},
                        @{"Name" = "Human Resources"; Positions = ("Manager", "Administrator", "Officer", "Coordinator")},
                        @{"Name" = "Sales"; Positions = ("Manager", "Representative", "Consultant", "Senior Vice President")},
                        @{"Name" = "Marketing"; Positions = ("Manager", "Coordinator", "Assistant", "Specialist")},
                        @{"Name" = "Engineering"; Positions = ("Manager", "Engineer", "Scientist")},
                        @{"Name" = "Consulting"; Positions = ("Manager", "Consultant")},
                        @{"Name" = "Information Technology"; Positions = ("Manager", "Engineer", "Technician", "Analyst")},
                        @{"Name" = "Planning"; Positions = ("Manager", "Engineer")},
                        @{"Name" = "Contracts"; Positions = ("Manager", "Coordinator", "Clerk")},
                        @{"Name" = "Purchasing"; Positions = ("Manager", "Coordinator", "Clerk", "Purchaser", "Senior Vice President")}
                    )
    
    $Users = $Content | Select-Object `
        @{Name="Name";Expression={"$($_.Surname), $($_.GivenName)"}},`
        @{Name="Description";Expression={"User account for $($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},`
        @{Name="SamAccountName"; Expression={"$($_.GivenName.ToCharArray()[0])$($_.MiddleInitial)$($_.Surname)"}},`
        @{Name="UserPrincipalName"; Expression={"$($_.GivenName.ToCharArray()[0])$($_.MiddleInitial)$($_.Surname)@$($Forest)"}},`
        @{Name="GivenName"; Expression={$_.GivenName}},`
        @{Name="Initials"; Expression={$_.MiddleInitial}},`
        @{Name="Surname"; Expression={$_.Surname}},`
        @{Name="DisplayName"; Expression={"$($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},`
        @{Name="City"; Expression={$_.City}},`
        @{Name="StreetAddress"; Expression={$_.StreetAddress}},`
        @{Name="State"; Expression={$_.State}},`
        @{Name="Country"; Expression={$_.Country}},`
        @{Name="PostalCode"; Expression={$_.ZipCode}},`
        @{Name="EmailAddress"; Expression={"$($_.GivenName.ToCharArray()[0])$($_.MiddleInitial)$($_.Surname)@$($Forest)"}},`
        @{Name="AccountPassword"; Expression={(ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force)}},`
        @{Name="OfficePhone"; Expression={$_.TelephoneNumber}},`
        @{Name="Company"; Expression={$Company}},`
        @{Name="Department"; Expression={$Departments[(Get-Random -Maximum $Departments.Count)].Item("Name") | Get-Random -Count 1}},`
        @{Name="Title"; Expression={$Departments[(Get-Random -Maximum $Departments.Count)].Item("Positions") | Get-Random -Count 1}},`
        @{Name="EmployeeID"; Expression={"$($_.Country)-$((Get-Random -Minimum 0 -Maximum 99999).ToString('000000'))"}},`
        @{Name="BirthDate"; Expression={$_.Birthday}},`
        @{Name="Gender"; Expression={"$($_.Gender.SubString(0,1).ToUpper())$($_.Gender.Substring(1).ToLower())"}},`
        @{Name="Enabled"; Expression={$True}},`
        @{Name="PasswordNeverExpires"; Expression={$True}}
         
    ForEach ($Department In $Departments.Name)
        {
            $CreateADGroup = New-ADGroup -Name "$Department" -SamAccountName "$Department" -GroupCategory Security -GroupScope Global -Path $GroupOU.DistinguishedName -Description "Security Group for all $Department users" -Verbose -OtherAttributes @{"Mail"="$($Department.Replace(' ',''))@$($Forest)"} -Server $Server -PassThru
            If ($Department -eq "Information Technology") {Add-ADGroupMember -Identity "svcg_WorkstationAdmins" -Members $Department -Verbose -Server $Server}
            If ($Department -ne "Information Technology") {Add-ADGroupMember -Identity "Domain Users" -Members $Department -Verbose -Server $Server}
        }

    Write-Host ""
    
    ForEach ($User In $Users)
        {
            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $UserOU.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $CountryOU = New-ADOrganizationalUnit -Name $User.Country -Path $UserOU.DistinguishedName -Country $User.Country -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $CountryOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -Server $Server
                }
   
            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $StateOU = New-ADOrganizationalUnit -Name $User.State -Path $CountryOU.DistinguishedName -State $User.State -Country $User.Country -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $StateOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -Server $Server
                }
               
            $DestinationOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU.DistinguishedName -Server $Server
    
            $CreateADUser = $User | Select-Object -Property @{Name="Path"; Expression={$DestinationOU.DistinguishedName}}, * | New-ADUser -Verbose -Server $Server -PassThru
            
            $AddADUserToGroup = Add-ADGroupMember -Identity $User.Department -Members $User.SamAccountName -Server $Server -Verbose
            
            $InformationTechnologyGroups = @("Account Operators", "Backup Operators", "Cryptographic Operators", "Network Configuration Operators", "Print Operators", "Server Operators", "DNSAdmins", "Domain Admins", "Enterprise Admins", "Schema Admins") 
            If ($User.Department -eq "Information Technology") {Add-ADGroupMember -Identity "$($InformationTechnologyGroups | Get-Random)" -Members $User.SamAccountName -Verbose -Server $Server}
            
            Write-Host ""
        }
         
    ForEach ($User In $Users)
        {
            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $WorkstationsOU.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $CountryOU_Workstations = New-ADOrganizationalUnit -Name $User.Country -Path $WorkstationsOU.DistinguishedName -Country $User.Country -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $CountryOU_Workstations = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $WorkstationsOU.DistinguishedName -Server $Server
                }

            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU_Workstations.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $StateOU_Workstations = New-ADOrganizationalUnit -Name $User.State -Path $CountryOU_Workstations.DistinguishedName -State $User.State -Country $User.Country -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $StateOU_Workstations = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU_Workstations.DistinguishedName -Server $Server
                }
        }

    ForEach ($User In $Users)
        {
            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $ServersOU.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $CountryOU_Servers = New-ADOrganizationalUnit -Name $User.Country -Path $ServersOU.DistinguishedName -Country $User.Country -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $CountryOU_Servers = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $ServersOU.DistinguishedName -Server $Server
                }

            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU_Servers.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $StateOU_Servers = New-ADOrganizationalUnit -Name $User.State -Path $CountryOU_Servers.DistinguishedName -State $User.State -Country $User.Country -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $StateOU_Servers = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU_Servers.DistinguishedName -Server $Server
                }
        }
                   
    ForEach ($Department In $Departments.Name)
        {
            $DepartmentManager = Get-ADUser -Filter {(Title -eq "Manager") -and (Department -eq $Department)} -Server $Server | Sort-Object | Select-Object -First 1     
            $SetDepartmentManager = Get-ADUser -Filter {(Department -eq $Department)} | Set-ADUser -Manager $DepartmentManager -Verbose
        }

    Write-Host ""

#Stop logging script output 
    $($NewLine)
    Stop-Transcript
