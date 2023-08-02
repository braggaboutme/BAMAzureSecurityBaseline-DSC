# Configuration Definition
Configuration Server2022_ASB {
    param (
        [string[]]$NodeName ='localhost'
        )
 
    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'GPRegistryPolicyDsc'
 
    Node $NodeName {

        ## Don't allow input personalization
        Registry 'InputPersonalization' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueName   = 'AllowInputPersonalization'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Allow Microsoft Accounts to be optional
        Registry 'AllowMSFTAccountsOptional' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'MSAOptional'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Block user from showing account details on sign-in
        Registry 'BlockShowingAccountDetailsOnSignIn' {
            Ensure      = 'Present'
            Key         = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName   = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Configure Solicited Remote Assistance
        Registry 'BlockSolicitedRemoteAssistance' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fAllowToGetHelp'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Do not display the password reveal button
        Registry 'DontDisplayPasswordRevealButton' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI'
            ValueName   = 'DisablePasswordReveal'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable RPC Endpoint Mapper Client Authentication 
        Registry 'EnableRPCEndpointMapperClient' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName   = 'EnableAuthEpResolution'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
        Registry 'TurnOffInternetConnectionWizard' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName   = 'ExitOnMSICW'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Turn off multicast name resolution
        Registry 'TurnOffMulticastNameResolution' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName   = 'EnableMulticast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Ensure 'Boot-Start Driver Initialization Policy' is set to 3 which means it will enable Good, unknown and bad but critical drivers
        Registry 'Boot-StartDriver' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'
            ValueName   = 'DriverLoadPolicy'
            ValueType   = 'DWord'
            ValueData   = '3'
        }
        ## Configured "Do not show feedback notifications"
        Registry 'FeedbackNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'DoNotShowFeedbackNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Prohibit use of Internet Connection Sharing on your DNS domain network
        Registry 'ProhibitICSonDNS' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName   = 'NC_ShowSharedAccessUI'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Disable App Screen Notifications on lock screen
        Registry 'DisableLockScreenAppNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'DisableLockScreenAppNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable Domain Firewall
        Registry 'EnableDomainFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable Private Firewall
        Registry 'EnablePrivateFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Enable Private Firewall Unicast Response
        Registry 'AllowUnicastResponsesPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Apply Local Connection Security Rules
        Registry 'ApplyLocalConnectionSecurityPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'AllowLocalIPsecPolicyMerge'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Allow Outbound Connections PrivateFW
        Registry 'AllowOutboundConnectionsPrivateFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Enable Public Firewall
        Registry 'EnablePublicFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Disable Public Firewall Unicast Response
        Registry 'DisableUnicastResponsesPublicFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Allow Outbound Connections PublicFW
        Registry 'AllowOutboundConnectionsPublicFW' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Disabled Private Firewall Display Notifications
        Registry 'DisablePrivateFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Disabled Public Firewall Display Notifications
        Registry 'DisablePublicFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Domain Firewall Log Dropped Packets
        Registry 'DomainFirewallLogDropped' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName   = 'LogDroppedPackets'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Public Firewall Log Sucessful Connections
        Registry 'PublicFirewallLogSuccess' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogSuccessfulConnections'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        ## Public Firewall Log Size
        Registry 'PublicFirewallLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogFileSize'
            ValueType   = 'DWord'
            ValueData   = '16384'
        }
        ## Setup: Specify the maximum log file size (KB)
        Registry 'SetupLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName   = 'MaxSize'
            ValueType   = 'DWord'
            ValueData   = '32768'
        }
        ## Behavior of the elvation prompt for admins in admin approval mode
        Registry 'AdminApprovalModeforAdmins' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'ConsentPromptBehaviorAdmin'
            ValueType   = 'DWord'
            ValueData   = '2'
        }
        ## Prohibit install on network bridge on DNS domain network
        Registry 'ProhibitInstallNetworkBridge' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName   = 'NC_AllowNetBridge_NLA'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        ## Sets the PKU2U setting to Not Set so that it doesn't show up in the Azure Security Baseline Guest Configuration
        Registry 'PKU2UNotSet' {
            Ensure      = 'Absent'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'
            ValueName   = 'AllowOnlineID'
        }
        ## Increase a process working set
        UserRightsAssignment IncreaseProcessWorkingSet {
            Policy       = 'Increase_a_process_working_set'
            Identity     = @('Administrators','LOCAL SERVICE')
            Force        = $true
        }
        ## Bypass Traverse Checking
        UserRightsAssignment Bypasstraversechecking {
            Policy       = 'Bypass_traverse_checking'
            Identity     = @('Administrators','Authenticated Users','Backup Operators','LOCAL SERVICE','NETWORK SERVICE')
            Force        = $true
        }
        SecurityOption AccountSecurityOptions {
            Name = 'AccountSecurityOptions'
        # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Enabled'  to allow Azure authentication
            #Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities  = 'Enabled'
        ## Determins wheter digital certificates are processed when software restriction policies are enabled and a user or process attempts to run software with an .exe file name extension
            System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'
        ## Do not display last username
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'
        ##Rename Guest Account
            Accounts_Rename_guest_account = 'd2tguest'
        }
        
        AuditPolicyGuid DetailedFileShareFailure
        {
            Name      = 'Detailed File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicyGuid OtherPolicyChangeFailure
        {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicyGuid FileShareSuccess
        {
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicyGuid FileShareFailure
        {
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

}
}

Server2022_ASB
