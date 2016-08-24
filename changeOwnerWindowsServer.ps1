#change owner access in windows servers , in this case DCOM access changed from 'Trusted Installer' to 'Administrators'

#set acl using powershell

function enable-privilege {
 param(
  ## The privilege to adjust. This set is taken from
  ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
  [ValidateSet(
   "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
   "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
   "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
   "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
   "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
   "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
   "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
   "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
   "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
   "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
   "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
  $Privilege,
  ## The process on which to adjust the privilege. Defaults to the current process.
  $ProcessId = $pid,
  ## Switch to disable the privilege, rather than enable it.
  [Switch] $Disable
 )

 ## Taken from P/Invoke.NET with minor adjustments.
 $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

 $processHandle = (Get-Process -id $ProcessId).Handle
 $type = Add-Type $definition -PassThru
 $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}





#Checking OS Version and changing Registry Key permissions accordingly. We don't need
# to change reg-key ownership for Win Server 2008, but in 2008 R2, owner of one of
# the required keys is TrustedInstaller instead of Administrator. Thus we need to
# change the owner back to Admin in order to make any changes to that key.
echo "Checking Operating System Version..."
$cv = (gi "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion")
$wv = $cv.GetValue("ProductName")
echo "$wv"
# Mounting HKey_ClassesRoot Registry key as a drive - Silent
New-PSDrive -name HKCR -PSProvider Registry -root HKEY_CLASSES_ROOT | Out-Null
$acl = Get-Acl "HKCR:\CLSID\{76A64158-CB41-11D1-8B02-00600806D9B6}"
$owner = $acl.Owner
echo "$owner"


# Case 48188: Because Windows has server version like Windows Web Server 2008 R2, we
# cannot validate the version name using "Windows Server 2008 R2". We will only
# check if the name contains "Server 2008 R2" or "Server 2012".
if($wv.Contains("Server 2008 R2") -or $wv.Contains("Server 2012")  -and !$owner.Contains("Administrators"))
{
  echo "Setting Administrators Group privileges in Windows Registry..."
  $boolResult = enable-privilege SeTakeOwnershipPrivilege
    if(-not $boolResult)
    {
      echo "Privileges could not be elevated. Changing ownership of the registry"
      echo "key would fail. Please change ownership of key"
      echo "HKCR\CLSID\{76A64158-CB41-11D1-8B02-00600806D9B6} to Administrators"
      echo "Group manually."
      return
    }
  $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey(
    "CLSID\{76A64158-CB41-11D1-8B02-00600806D9B6}",
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
    [System.Security.AccessControl.RegistryRights]::takeownership
  )
  # You must get a blank acl for the key b/c you do not currently have access
  $acl = $key.GetAccessControl(
    [System.Security.AccessControl.AccessControlSections]::None
  )
  $owner = [System.Security.Principal.NTAccount]"Administrators"
  $acl.SetOwner($owner)
  $key.SetAccessControl($acl)

  # After you have set owner you need to get the acl with the perms so you can
  # modify it.
  $acl = $key.GetAccessControl()
  $person = [System.Security.Principal.NTAccount]"Administrators"
  $access = [System.Security.AccessControl.RegistryRights]"FullControl"
  $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit"
  $propagation = [System.Security.AccessControl.PropagationFlags]"None"
  $type = [System.Security.AccessControl.AccessControlType]"Allow"

  $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    $person,$access,$inheritance,$propagation,$type
  )
  $acl.SetAccessRule($rule)
  $key.SetAccessControl($acl)

  $key.Close()
  echo "Administrators Group ownership privileges set."
  
  #Add IUSR to local administrators group
  net localgroup "Administrators" "IUSR" /add
  echo "IUSR added to Administrators Group"
}

#Powershell.exe -executionpolicy remotesigned -File  C:\Users\SE\Desktop\ps.ps1
#PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& 'C:\Users\SE\Desktop\ps.ps1'"
#PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""C:\Users\SE\Desktop\ps.ps1""' -Verb RunAs}"
