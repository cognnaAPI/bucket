rule malicious_yaml {
	strings:
		$s1 = "ca_certificate: " ascii
	condition:
		any of them
}