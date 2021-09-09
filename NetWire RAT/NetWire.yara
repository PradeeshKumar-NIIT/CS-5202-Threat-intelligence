rule NetWire
{
meta:
	Description = "Simple YARA rule to detect Netwire RAT"

strings:
	$ipaddrs = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii

	$str01 = "GetKeyboardType"
	$str02 = "AutoHotkeys"
	$str03 = "MapVirtualKey"
	$str04 = "_TrackMouseEvent"
	$str05 = "GetCapture"
	$str06 = /(SOFTWARE\\Borland\\|Software\\Borland\\)(Delphi\\RTL|Delphi\\Locales|Locales)/
	$str11 = "<CreateApplication>b__30_0"
	$str12 = /(O_0_0_0_0_0_0_0_0_0_0_0|O_O_O_O_O_O_O_O_O_O)/ 

	$str21 = "ScreenToClient"
	$str22 = "Software\\Microsoft\\Windows\\CurrentVersion"
	$str23 = "Control Panel\\Desktop\\ResourceLocale"

	$str31 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii nocase
	$str32 = "200 OK"
	$str33 = /(%.2d-%.2d-%.4d|%s%.2d-%.2d-%.4d|%.2d:%.2d:%.2d|%u.%u%s%s)/ 

	$str41 = /(CryptAcquireContext|CryptCreateHash|CryptDeriveKey)/
	$str42 = "RtlMoveMemory"
	$str43 = "VirtualProtect"
	$str44 = "htons"

condition:
	5 of ($str0*) 
	or ($ipaddrs and all of ($str1*))
	or (all of ($str2*) and $str33)
	or 3 of ($str3*)
	or 3 of ($str4*)
}
