rule malicious_yaml {
	strings:
		$s1 = "ca_certificate: " ascii
	condition:
		any of them
}
rule bad_real_bad_file {
	strings:
		$s1 = "Exports Registry Key To an Alternate Data Stream" asciIi
	condition:
		any of them
}