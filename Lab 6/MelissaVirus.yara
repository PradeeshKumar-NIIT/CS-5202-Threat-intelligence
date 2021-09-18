rule MelissaVirus
{
meta:
	Description = "Simple YARA rule to detect Melissa Virus"
	Author = "Pradeesh Kumar.R (MT20ACS523)"
	Date = "2021-09-18"

strings:
	$str01 = /(Macro|Security|HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\9.0\\Word\\Security)/ //Checks for Word security controls for Word 2000 and disables them
	$str02 = /(Options|ConfirmConversions|VirusProtectionoD|SaveNormalPrompt)/ //Checks for Word security controls for Word 97 and disables them
	$str03 = /(HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\|Melissa|... by Kwyjibo)/ //Checks if machine is already infected
	$str04 = /(Subject|Important Message From |FullName)/ //Subject send to the recepient
	$str05 = /(Body|Here is that document you asked for ... don't show anyone else)/ //Message send to the recepient
	$str06 = /(Attachment|AddressList)/ //Attachment and recepient email address
	$str07 = "Outlook.Application" //Checks for Outlook Application.
	$str08 = "WORD/Melissa written by Kwyjibo" //If Outlook Application is not found, modifies the value of the registry key 
	$str09 = " Twenty-two points, plus triple-word-score, plus fifty points for using all my letters.  Game's over.  I'm outta here. " //References a URL Pattern
	$str10 = /(Works in both Word 2000 and Word 97|Word -> Email | Word 97 <--> Word 2000 ... it's a new age!)/ //Indicates the malicious code in the document
	$str11 = "Worm? Macro Virus? Word 97 Virus? Word 2000 Virus? You Decide!" //Indicates the malicious code in the document

condition:
	all of ($str*)
}
