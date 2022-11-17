rule eicar_standard_test_file
{
	meta:
		description = "Simple YARA rule to detect the Eicar Standard Antivirus Test File"
		author = "Mitchell Telatnik"
		date = "11/16/2022"

	strings:
		$a = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

	condition:
		$a
}