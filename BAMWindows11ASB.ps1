# Configuration Definition
Configuration Windows11_ASB {
    param (
        [string[]]$NodeName ='localhost'
        )
 
    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'GPRegistryPolicyDsc'
 
    Node $NodeName {
        AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'
            # 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                    = 24
            # 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
            Maximum_Password_Age                        = 70
            # 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
            Minimum_Password_Age                        = 1
            # 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
            Minimum_Password_Length                     = 14
            # 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'
            # 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            # 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 3
        }

        # Ensure 'Windows Search (WSearch)' is set to 'Disabled'
        Registry 'Wsearch' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Services\Wsearch'
            ValueName   = 'Start'
            ValueType   = 'DWord'
            ValueData   = '4'
        }
        # Configured "Allow Diagnostics Data" is set to '1' which mean, send only basic amount of diagnostic data
        Registry 'AllowTelemetry' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'AllowTelemetry'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        
        # Ensure 'Boot-Start Driver Initialization Policy' is set to 3 which means it will enable Good, unknown and bad but critical drivers
        Registry 'Boot-StartDriver' {
            Ensure      = 'Present'
            Key         = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'
            ValueName   = 'DriverLoadPolicy'
            ValueType   = 'DWord'
            ValueData   = '3'
        }
        # Configured "Do not show feedback notifications"
        Registry 'FeedbackNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName   = 'DoNotShowFeedbackNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Configured "Minimize Simultaneous Internet Connections. (Might be a problem for AVD)"
        Registry 'MinimizeSimultaneousInternetConnections' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName   = 'fMinimizeConnections'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Configured "Prohibit Network Bridge Installations"
        Registry 'ProhibitNetworkBridgeInstallation' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName   = 'NC_AllowNetBridge_NLA'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Disable App Screen Notifications on lock screen
        Registry 'DisableLockScreenAppNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'DisableLockScreenAppNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Allows Admins to create local connection firewall rules
        Registry 'AllowLocalConnSecurity' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'AllowLocalIPsecPolicyMerge'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Enabled Domain Firewall
        Registry 'EnablesDomainFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Enabled Private Firewall
        Registry 'EnablesPrivateFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disables Private Outbound Connections (0 = Allow Traffic)
        Registry 'DisablesPrivateFirewallOutbound' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Enabled Private Firewall Local Connection Rules
        Registry 'LocalConnSecurityPrivateFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'AllowLocalIPsecPolicyMerge'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disabled Private Firewall Display Notifications
        Registry 'DisablePrivateFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Enabled Public Firewall State
        Registry 'EnablesPublicFirewall' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Disables Public Outbound Connections (0 = Allow Traffic)
        Registry 'DisablesPublicFirewallOutbound' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Disabled Public Firewall Display Notifications
        Registry 'DisablePublicFirewallNotifications' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Use Certificate Rules on Windows Executables
        Registry 'EnableCertificateRulesOnExecutables' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
            ValueName   = 'AuthenticodeEnabled'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Private Firewall Don't allow Unicast Response
        Registry 'PrivateFirewallBlockUnicastResponse' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Public Firewall allow Unicast Response
        Registry 'PublicFirewallAloowUnicastResponse' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        # Domain Firewall Log Dropped Packets
        Registry 'DomainFirewallLogDropped' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName   = 'LogDroppedPackets'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Private Firewall Log Sucessful Connections
        Registry 'PrivateFirewallLogSuccess' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueName   = 'LogSuccessfulConnections'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Public Firewall Log Sucessful Connections
        Registry 'PublicFirewallLogSuccess' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogSuccessfulConnections'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        # Public Firewall Log Size
        Registry 'PublicFirewallLogSize' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueName   = 'LogFileSize'
            ValueType   = 'DWord'
            ValueData   = '16384'
        }
        # Caching of logon credentials must be limited
        Registry 'LimitLogonCredCache' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueName   = 'CachedLogonsCount'
            ValueType   = 'DWord'
            ValueData   = '4'
        }
        # Users required to enter password to access private keys
        Registry 'KeyProtection' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography'
            ValueName   = 'ForceKeyProtection'
            ValueType   = 'DWord'
            ValueData   = '2'
        }
        # Behavior of the elvation prompt for admins in admin approval mode
        Registry 'AdminApprovalModeforAdmins' {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'ConsentPromptBehaviorAdmin'
            ValueType   = 'DWord'
            ValueData   = '2'
        }
        # 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
        AuditPolicySubcategory "Audit Credential Validation (Success)"
        {
            Name      = 'Credential Validation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        # Bypass Traverse Checking
        UserRightsAssignment BypassTraverseChecking {
            Policy       = 'Bypass_traverse_checking'
            Identity     = 'Administrators, Users, Backup Operators, Everyone, LOCAL SERVICE, NETWORK SERVICE'
        }
        UserRightsAssignment Allowlogonlocally {
            Policy       = 'Allow_log_on_locally'
            Identity     = 'Administrators, Users'
        }
        # 2.2.17 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
        }
        # 2.2.18 (L1) Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
        }
        # 2.2.20 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
        }
        # 2.2.16 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests'
        }
        # 2.2.25 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Windows Manager\Windows Manager Group'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators, Window Manager\Window Manager Group'
        }
        # Increase a process working set
        UserRightsAssignment IncreaseProcessWorkingSet {
            Policy       = 'Increase_a_process_working_set'
            Identity     = 'Administrators, Users, LOCAL SERVICE'
        }
        SecurityOption AccountSecurityOptions {
            Name = 'AccountSecurityOptions'
        # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Enabled'  to allow Azure authentication
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities  = 'Enabled'
        }
}

Windows11_ASB
