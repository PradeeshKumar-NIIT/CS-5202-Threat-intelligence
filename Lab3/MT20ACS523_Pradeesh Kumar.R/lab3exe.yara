rule lab3exe
{
meta:
	Description = "Simple YARA rule to detect 2018-05-KPOT"
	Author = "Pradeesh Kumar.R (MT20ACS523)"
	Date = "2021-08-31"

strings:
	$str01 = "http://%s" //References a URL Pattern
	$str02 = "https://%S/a/%S" wide //References a URL Pattern
	$str03 = "HTTP Server URL" wide //References a HTTP Server URL
	$str04 = "password-check" //Checks for passwords
	$str05 = "*.wallet" wide //.WALLET file belongs to the category of Data Files used in operating systems such as Windows 11, 10, Windows 7, Windows 8 / 8.1, Windows Vista, Windows XP. A WALLET file is a file encrypted by the CryptoMix, or CrypMix, virus, which is ransomware utilized by cybercriminals. It contains a user's file, such as a . PDF or . DOCX file, encrypted with AES encryption by the virus.
	$str06 = "*.rdp" wide //RDP files mostly belong to Remote Desktop Connection by Microsoft Corporation. An .RDP file contains all of the information for a connection to a terminal server, including the options settings that were configured when the file was saved.

	$sr01 = "9087654356.exe" wide //References a malicious exe file present in the sample
	$sr02 = "PowerShell" //The downloader, in turn, fetches parts of a PowerShell script that includes the Base64-encoded payload from the various links

	$reg01 = /(SMTP|POP3|IMAP)\s(User|Password|Port|Server)/ wide //References the username, password, portnumber and Server of SMTP, POP3 and IMAP
	$reg02 = /(HttpWeb|Web|Get)(Request|Response|Client)/ //To request and respond data from a host server

condition:
	all of ($str*)
	or all of ($sr*)
	and 1 of ($reg*)
}
