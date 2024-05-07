# 1. Azure Overview
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/95f39d20-c3f4-4dec-b3e2-4dc94596843d) 

# 2. Roles (RBAC) 
`Security Reader` is enough for investigation or higher is `Global Reader`. 

# 3. AzureAD (Entra ID) 
## 3.1 Application and Service Principal 
- **Application object**: contains metada and configuration about the application such as `display name`, `identifier`, `reply URLs`,...
- **Service Principal**: represents the application in AzureAD that allows the application to authenticate and request access to resources on behalf of users or itself.

**Application object (App registration)** 
- When you want to intergrate an App with AzureAD for `single sign-on (SSO)` or to access `MS Graph API` or other resources, you need to resgiter that App in AzureAD. The registration creates an `Application Object` that contains metadata and configuratons about the App.
- In an APP in AzureAD, you can configure 2 important aspects: `API permission` and `Certificates and Secrets`. 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/bcf297f8-aa46-4a89-bb11-66543098a136)

**Security Principal (Enterprise App)** 
- When an App registered in AzureAD, it becomes an `Enterprise Application` or `Service Principal`. It represents application's presence in the directory and enables the application to grant access resources within that tenant. 
- Each application has its own `unique identifier`. When a user or service principal request to access a resource (MS365 service, API,...), AzureAD checks its permission to determine if access should be allowed. 

### Permission Role 
- **Application Administrators**: manage all application objects and service principals within a tenant.
- **Owner**: control over a specific application and manage settings including: `who can access the app`, `which permissions it requires` and other relevant configurations.

### Application Object Permissions 
- **Certificates and Secrets**: You can add credentials to the application. These credentials used for non-interactive logons, allows the application to authenticate and obtain access token without requiring direct user interaction. 
- **API permissions**: You will need API permission for your application to access the resources. For example, if you want your application to interact with user mailboxs in MS Exchange Online via MS Graph, you need to request `read all mail` permission from MS Graph API. 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/4f43ced0-c985-4283-b8aa-548480509a46)

### Credentials with AzureAD Application 
Credentials are generated for the application to provide access to services such as SharePoint or Exchange Online. 
There are 2 types of credentials. 
#### Secret 
A secret is much like a password, and is a long string of text generated automatically for you within the portal. 
You can generate a secret on an application on the 'Certificates & secrets' tab on the application portal in Microsoft Entra ID. 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/4f26efae-1ee5-4153-a4c8-04e9344a3c4f) 

Once a secret is generated, it is given a unique Secret ID (or credential identifier) 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/c26d7a04-c497-4aa1-85eb-76e0ef4cd3d9) 

#### Certificate 
Certificate credentials allow administrators to upload the public key of a certificate, the private key is then provided during authentication, and the application authenticated. These certificates can be self signed, or generated from PKI environments. 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/b9e7b40d-f942-417a-bfb7-920b2ed5c45e) 

- Like secrets, you can have multiple certificates on an application. Each is identified by a Certificate ID, and additionally, the thumbprint of the certificate.

### Applications sign-in information 
You can select `Service principal sign-ins` in the EntraID: 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/d621cb40-3862-40d4-be0a-13d5b0088fe7)

If you send logs to a SIEM like Sentinel, you can monitor via  `AADServicePrincipalSignInLogs` event: 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/85c86f62-195d-4c57-b50f-90e73bc6e62b) 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/124a9e7e-167c-497a-a4e4-b9de7a95a761) 

- You can see important info such as `AppID`, `IpAddres`, `ServicePrincipalName`, `ResourceDisplayName`,... 

### Attack cases 
#### Owner of Service Principal Object (Enterprise App) 
The compromised user is the `owner` of `Service Principal Object`, but this is not the worst case. The attacker will have the same permissions as the compromised user, so there will not have `PrivEsc`. 

#### Owner of Application Object (App Registration) 
In this case, there will be a chance for attacker to `PrivEsc`. The attacker can make changes to settings, configurations, access controls of the application. This could lead to broader access organization's resources or even unauthorized access to sensitive data. 

## 3.2 Log Sources 
When do IR, we need to focus 3 types of logs: 
- **Sign-in Logs**: provide information about signin activities in AzureAD bao gồm nhiều cách thức (`interactive`, `non-interactive`, `Service principal sign-ins`, ...).  
- **Audit Logs**: provide informations about events in AzureAD. 
- **Activity Logs**: provide informations about events in `subcription` level (`Azure`) including: `create VM`, `run VM`, `modify keyvault`,...

## 3.3 Log investigation  
> Tip: if the customer does not forward log to `Log Analytics`, you can export `Sign-in log` and `Audit log` in AzureAD and ingest in `Azure Data Explorer` to continue investigate.

### Setup Azure Data Explorer 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/dbeb0d03-b4bf-4696-8f6e-f81011225e2e) 

### Hunt for important information  

| Log source | Retention | Information | 
| --- | --- | --- |
| Sign-in log | <p> 30 days | <p> - Who signed in ? <p> - When the sign-in occured ? <p> - Which applications used for authentication? <p> - Source IP add |
| Audit log | <p> 30 days | <p> - User creation <p> - User password reset <p> User/Application addition <p> - - Modification of Service Principal | 
| Activity log | <p> 90 days | <p> - VM creation <p> - Permission assigned to user <p> - Extension addition |

### Useful fields   
#### Audit Log
- **Activity Tab**

| Fields  | Information |
| --- | --- |
| Activity Type | indicate the actual operation logged in the Audit Logs entry |
| Initiated by (actor) | indicate identifiers of the entity conducting the relevant action. This part can include different types of entities: `applications` (represented as “app”)  with the Display Name and `users` (represented as “user”)  with the “User Principal Name” |
| Status | indicate the operation successfully accomplished or not (“success”/”failure”) |
| IP Address | indicate `the source IP` from which the relevant action had been conducted. Note that this might provide an `indication about Microsoft IP Addresses` potentially related to some inter-communication and not the external source IP from which the user conducted the actual action | 

- **Target tab**

| Fields  | Information |
| ------------- | ------------- |
| Type | indicate the type of targeted object | 
| User Principal Name | UPN of target entity against which the event/action had been conducted | 
| Modified Properties | provide an indication of properties that had been modified as part of this audit log entry related operation |

#### Sign-in Log 
**Category**: there are 4 category types: `User Sign-ins`, `Non-Interactive User Sign-ins`, `Managed Identities Sign-ins`, and `Service Principal Sign-ins`. Looking at the correct category is crucial to make sure not missing sign-in events.

- Location Tab 

| Fields | Information |
| --- | --- |
| IP address | indicate the source IP from which the Sign-in originated from |
| Location | indicate geographical location identified as related to the sign-in attempt | 

- Basic Info Tab

| Fields | Information |
| --- | --- |
| Authentication requirements | provides an indication about the authentication requirements needed for authentication (single-factor authentication, multifactor authentication, etc.) | 
| Status | was the sign-in successful? | 
| User & Username | The identity of the signed-in entity | 
| User Type | the type of the signed-in user account (member, guest, etc.) |  
| Client app | provides an indication about the authentication clients that had been used to sign-in (e.g. browser, mobile apps and desktop clients, etc.) | 
| Application | Can provide indication about the target application/service to which the user had been authenticated (Azure Portal, Microsoft Azure CLI, Microsoft Azure PowerShell, OfficeHome, Microsoft Office 365 Portal, etc.) | 
| User Agent | The user-agent identified as being used as part of the sign-in attempt | 

## 3.4 Some hunting queries 
### Sensitive permissions
 Attackers tend to add sensitive permissions to `application` or `service principal`. 
- Mail.* (including Mail.Send*, but not Mail.ReadBasic*) 
- Contacts. * 
- MailboxSettings.* 
- People.* 
- Files.* 
- Notes.* 
- Directory.AccessAsUser.All 
- User_Impersonation

### TA adds new credentials to an existing application 
This allows TA `authenticate as` the `application` or `service principal`. The attacker can create a `secret` and connect via the secret,  granting them access to all resources to which it has permissions. 

```kql
// Application Administrator role has the ability to add credentials (secrets or certificates) to any existing application in Azure AD.
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName contains "Certificates and secrets management"
| extend AppId = tostring(AdditionalDetails[1].value)
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend modifiedProperties = TargetResources[0].modifiedProperties
| project-reorder  TimeGenerated,  AppDisplayName, AppId, Actor, Result, modifiedProperties
``` 
### New API permissions added to service principals 
If the attacker can't find an app or a service principal with high privilege, they will often attemp to add more permissions to that app or service principal. (Of course they will need Application Administrator or Owner). 
API permissions granted look like the followings: 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/52edfd91-e635-4948-a0a3-9dd8f923f52f) 

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName contains  "Add delegated permission grant"
| extend DelegatedPermissionsAdded = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)))
| extend AppId = tostring(TargetResources[1].id)
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ActorIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| project-reorder  TimeGenerated, OperationName, AppId, DelegatedPermissionsAdded,Actor, ActorIPAddress
```

After adding permission, the attacker often atemp to consent the application so that it can access the resources itself. 
```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName contains "Consent to application"
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend Consent = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[4].newValue)))
| parse Consent with * "Scope:" PermissionsConsentedto ']' *
| extend WhoConsented = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend AdminConsent = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)))
| extend AppType = tostring(TargetResources[0].type)
| extend AppId = tostring(TargetResources[0].id)
| project-reorder  TimeGenerated, AdminConsent, AppDisplayName, AppType, AppId, PermissionsConsentedto, WhoConsented
```
- You can join 2 tables on `AppID` to get details about what app was added permission and consented.

#### Add member to sensitive roles or groups 
Another approach is the attacker add service principal to existing directory roles or groups. 

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add member to role"
```

## 3.5 Response and Remeidation 
### Compromised users 
1. Disable account and reset password: on-premises passwords should be reset twice to mitigate the risk of pass-the-hash attacks.
3. Disable user device
4. Review authentication methods
5. Do investigation to understand the scope 
More info: [here](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)

### Compromised applications 
If credentials were compromised, all the credentials associated with an application should be deleted from the application and investigate full scope of compromise. 
#### Investigate any resources accessed 
For example, if an application was compromised and it accessed the Azure Key Vault resource, then you should investigate activity logs and diagnostic logging associated with your Azure Key Vaults to understand what actions occurred on that resource. 
> Tip: `MS Graph Activity Log` is able to provide more insight about resources accessed by an application too, I will mention it in next sections.  

# 4. Azure 
## 4.1 Azure Activity Log 
### Useful fields  

| Fields | Information |
| --- | --- | 
| Resource | the resource identified is being presented in a URN format: /subscriptions/<subscription id>/resourceGroup/<resource group name>/providers/<resource provider namespace>/<resource type>/<resource name> | 
| Operation Name | indicate the actual operation that occurred such as **Restart Virtual Machine**, **Create or Update Virtual Machine Extension** | 
| Event initiated by | indicate the identifier (UPN) of the entity that conducted the action | 
| JSON Tab | <p> includes a JSON view, which includes in-depth information about the log entry, including some of the information mentioned above, as well as other useful fields <p> - action: the exact action using URN identification. For example, for operation name of **Validate Deployment** we’ll see action value of: **Microsoft.Resources/deployments/validate/action** <p> - ipaddr: provide an indication about the source IP address from which the logged action had been conducted <p> - name: the name of the identity conducted the logged action | 

## 4.2 Unified Audit Log (UAL) 
UAL records activities in `AzureAD` and `Office365` of `users` và `admin` including: file access, mailbox access,... 
### Enable UAL 
#### Through Compliance Portal 
- Go to `https://compliance.microsoft.com/`.
- Select `Audit` under `Solution.
- If auditing is not turned on for your organization, a banner prompting ‘Start recording user and admin activity’ will be displayed in the New Search tab.
- Click on the banner to enable the audit logs.
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/61808e94-a0e0-479a-a409-ae266a4e64dc) 

#### Through Powershell 
- Check for `UAL` status: `Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled`.
- Enable UAL: `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true`.
- Disable UAL: `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false`. 
> Note: It takes about 60 minutes for the changes.

####  Audit (premium) 
Enabled to record and search for 2 events `Exchange Online` and `Sharepoint Online`.  

#### UAL retention 
MS Purview offers distinct audit solution: `Standard` and `Premium`. `Premium` allow retention up to 10 years. 

### Permissions 
Assign role on `Role Groups` page in `Microsoft Purview Portal` and `Permission` page in `Compliance` portal. 
- **Audit Manager**: can do everything related to audit logs.
- **Audit Reader**: can only search and export audit logs. 

### Log investigation 
#### UAL list 
Source: https://learn.microsoft.com/en-us/purview/audit-log-activities 

![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/43a9710b-0030-4bfb-87de-a8938c686c5a) 
> Tip: you can just export them and ingest to `Azure Data Explorer`. 

## 4.3 Microsoft Graph Activity Log 
Microsoft Graph activity logs are an audit trail of `all HTTP requests` that the `Microsoft Graph service` received and processed for a tenant. (ref: https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview) 
### Log Forwarding 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/99fc2640-7244-4371-a913-c5b84d7ee1cf) 

### Log investigation 
#### Useful fields 
- **RequestMethod**: type of requests such as `POST` or `GET` request.
- **ResponseStatusCode**: identify fail or successfull requets.
- **IpAddress**: requests that made by `service principal` is  a MS IP address. Requests that made by a `UserID` is the real IP address.
- **RequestUri**: it's an important field, it reveals what was requested.
- **AppID**: the application that makes the requests.
- **ServicePrincipalID**: When a service principal object is used this field is filled with its identifier.
- **UserID**: it reveals the specific user who is responsile for making the requests.
- **Scopes**: the permissions that were asssigned to the application making the requests.
- **Roles**: identify what possible access an application has.

#### Some Hunting Cases 
##### Data transfer/ exfiltration 
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| summarize total_bytes_tranfered = sum(ResponseSizeBytes) by AppId
| extend readable = format_bytes(total_bytes_tranfered, 2, "MB")
``` 
> Tip: you can find `app display name` with search bar, just paste `AppID` into it. 

##### Find UPN (User Principal Name) 
Graph Log contains only `UserID` not `User Principal Name (UPN)`, you can join with `IdentityInfo` table to find UPN. 
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| where isnotempty( UserId)
| join kind=inner (
    IdentityInfo
    | where TimeGenerated > ago(30d)
    ) on $left.UserId == $right.AccountObjectId
``` 
##### Detect AzureHound 
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| where UserAgent contains "azurehound"
```
You found a compromised user that is the `Owner` of an `Application`, you can track what resources that App requested. If you don't understand what I mean, you can move to the next section. 
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| where AppId  == "add yours"
| extend ParsedUri = tostring(parse_url(RequestUri).Path)
``` 
## 4.4 Azure Blob Storage and Storage Account 
`Blob Storage` is handled by `Storage Account`. This account is used to access Azure services such as blobs, files, tables,... 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/cce0eab5-a8ab-444e-b3fa-170ff0e613fc) 

- From  attackers's perspective, they will want to know what containers exist and what blobs exist within that container. After that, the attacker can enumerate, access, download files. 
The defualt base address of a blob storage: `https://<STORAGE ACCOUNT NAME>.blob.core.windows.net/<CONTAINER NAME>/<FILE NAME>`.

### Access levels 
There are 3 options: 
- No public read access
- Public read access for blobs only (Recommended) 
- Public read access

![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/86b1690d-a4be-47fd-8e3c-1f2f991ec55c)

### Detection 
#### Azure Activity Logs 
Show administrative related operation such as `storage account creation` or `listing storage account keys`,...  
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/1cedd321-2fd8-43e9-87de-63d5a72342c4) 
Important info: 
- **Operation**: List Storage Account Keys
- **ipaddr**: actor's remote IP
- **Status**: show the request is successfull or not
- **Caller**: the user account performs the action 

#### Storage Analytics Logs ([more info](https://learn.microsoft.com/en-us/rest/api/storageservices/storage-analytics-logged-operations-and-status-messages))
This logs show interesting information about what the attacker did: 
- File accessed
- Blob Viewed 

##### Enabling Logs 
These logs are not enabled by default, you need [enable through PowerShell or Azure Portal](https://learn.microsoft.com/en-us/azure/storage/common/manage-storage-analytics-logs?tabs=azure-portal) 

##### Checking Logs Avaibility 
You can go to Azure Portal and view container with storage account. If there is a container named `$logs`, it means log was enabled. 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/601c30a4-d7a8-45e1-8b10-3c68a0c66b56)

##### Important Log Fields 
###### File Access 
- **Operation**: GetBlob
- **Blob**
- **Status Code** 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/0affa311-45d8-4ef9-a4e2-d589c64e363a) 

###### Enumeration Activities 
- GetContainerProperties 
- ListBlobs 
- ListContainers 
- GetAccountInformation 
- GetBlobProperties 

## 4.5 Virtual Machines (VM) 
Attacker can create VM to keep the connection as well as access to many resources in the environment. 

### Analysing the logs.  
You can check for activities related to VM with `Azure Activity log` such as: `VM creation`, `VM password reset`, `VM script/command execution`, ... 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/4589ee99-5670-4c1d-986e-b9c449db0221) 

### Some attack vectors 
#### Leveraging Custom Script Extensions (CSE)
##### Intro
- [Custom Script Extensions](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows) downloads and runs scripts on Azure virtual machines (VMs). Use this extension for post-deployment configuration, software installation, or any other configuration or management task. You can download scripts from `Azure Storage or GitHub`.
- Since these scripts are intended to be a part of regular VM management, their execution might not raise immediate red flags, allowing us to operate under the radar for longer.

##### Required Permissions 
- `Write/Deploy Custom Script Extension`: Microsoft.Compute/virtualMachines/extensions/write
- `Read existing custom script extension (to modify to inject backdoor, malicious code,...)`: Microsoft.Compute/virtualMachines/extensions/read
- `Az PowerShell command`: Set/Get-AzVMExtension 
Download script and execute it on a VM: 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/4e364afa-5e19-4e66-8831-454e54ccc545) 
> Note: CSE download and execute scripts as `SYSTEM`. 

##### Detection 
###### Scripts-stored Location 
Scripts are stored in location: `C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\<version>\Downloads\<other version>\<script name>` 
> `Note`: the attacker can remove traces with `Remove-AzVMCustomScriptExtension`. If the CSE is deleted from the VM via the Azure front door then the Guest Agent will delete the entire `Microsoft.Compute.CustomScriptExtension` folder from `C:\Packages\Plugins\` and all its contents.

###### Event Logs 
- `EventID 4688` with Powershell commandline process
- `Event ID 7` shows `installation`, `maintenance`, and `removal` of the CustomScriptExtension plugin. This should not appear in the Event logs of a VM which has never had CSEs deployed. Logs Location: `%SystemRoot%\System32\Winevt\Logs\Microsoft-WindowsAzure-Status%4Plugins.evtx`.

#### Serial Console Access 
With `Serial Console` you can connect to the target VM regardless of the network restrictions placed on the VM. 
Azure serial console is also a good technique for bypassing Just-in-Time (JIT) admin access controls implemented by Microsoft Defender for Cloud. JIT is designed to harden security by enabling administrators to grant access to VM ports and functionality during specific time windows. 

Azure Serial Console offers various capabilities in unauthenticated SAC console mode: 
- **cmd** = Create a command prompt channel. 
- **d** = Dump the current kernel log. 
- **l** = List all IP network numbers and their IP addresses and set IP info.  
- **t** = Display the task list. 
- **livedump** = create a live kernel dump, this allows us to exfiltrate Secrets from the dump.

![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/9ff2d61e-4823-4eec-8821-4e05dde41bb3) 
![image](https://github.com/Knightz1/Noven-SOC/assets/91442807/3d033a1c-ec2e-4174-8a30-09f7c2d0450b) 

##### Detection 
To activate a CMD session on the VM through SAC, we use the command cmd . This action triggers the execution of `sacsess.exe`, that then subsequently initiates `cmd.exe` within the VM. You can detect with `EventID 4688`. 

##### Required permission 
`Microsoft.SerialConsole/serialPorts/connect/action` 

### Digital Forensics (Comming soon) 
To know more about what the attacker did in VM. 
#### Linux 
#### Windows 

# 5. Hunt for attack vectors 
## 5.1 Identify malicious activities 
- Users activities in incident time.
- Third-party app usage.
- Who access files/folders (Office365).
- Suspicous policies.
- Users addtion to sensitive group. 

## 5.2 Office365 activities (comming soon) 
If you have `Microsoft Defender for Cloud Apps`, you dont need `UAL`. 

# Reference 
- https://www.hunters.security/en/blog/human-friendly-guide-incident-response-microsoft-and-threat-hunting-azure-1#azure-ad-m365
- https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/
- https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors
- https://blog.admindroid.com/unified-audit-log-a-guide-to-track-office-365-activities/#Turn%20on%20auditing%20through%20the%20compliance%20portal
- https://cyberdom.blog/2023/07/29/persistence-via-app-registration-in-entra-id/
- https://www.invictus-ir.com/news/everything-you-need-to-know-about-the-microsoftgraphactivitylogs
- https://github.com/AtomicGaryBusey/AzureForensics/blob/master/FORENSIC%20ARTIFACTS%20-%20Azure%20Custom%20Script%20Extension%20Use.md
- https://github.com/microsoft/MSEntraIDProtectionGuidance/tree/main/docs 









