rule cve_2015_1770 
{
meta:
    author = "rotem.salinas@gmail.com"
    filetype = "doc"
    cve = "CVE-2015-1770"
strings:
    $doc_header = {D0 CF}
    $hex_string1 = { 77 6F 72 64 2F 61 63 74 69 76 65 ( 58 | 78 ) 2F 61 63 74 69 76 65 ( 58 | 78 ) ?? ?? 2E 78 6D 6C } // word/activeX/activeX1.xml
    $hex_string2 = { 77 6F 72 64 2F 61 63 74 69 76 65 ( 58 | 78 ) 2F 41 63 74 69 76 65 ( 58 | 78 ) ?? 2E 62 69 6E } // word/activeX/ActiveX1.bin
condition:
    ($doc_header at 0) and all of ($hex_string*)
}
