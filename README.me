## Information
This is a simple tool to try to allow for quick, simple, and effective yara rule creation to isolate malware families. This is an experiement and thus far I've had pretty good success with it. It is a work in progess and I welcome forks and feedback! 

To utilize this you must find a few files from a malware family you wish to profile, (the more the better, three to four samples seems to be effective). Place the samples in their own directory, and run the tool. Thats it! Yara Magic! Please note however that this tool will only be as precise as you are in chosing what you are looking for...

The theory behind the tool is this:
   As opposed to intensive analytical examination of a cadre of malware to determine similarites, by extracting all present strings and ensuring only to signature for those present in all desired samples and requiring ENOUGH of them to be present to equal a match, similar results can be achieved. 

   In many ways this is less flexible than the existing methodology, but in some ways more so, as it relies less on anomoylous indicators which can eaisly be changed. That said it needs a lot of work and tuning, because the risk is run of capturing strings only present in your sample set, but not the family at large. Lowering the critical hit from 100% of strings may approach a usable compromise there.

   In the future I will create a list of thousands of strings we never want to signature for and remove them from potentials for the rules. 

   Current hard set variables are 30 random strings selected from those present in all binary samples of six or more printable chars.

## Author & Licence

YaraGenerator is copyrighted by Chris Clark 2013. Contact me at Chris@xenosys.org

YaraGenerator is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
YaraGenerator is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with YaraGenerator. If not, see http://www.gnu.org/licenses/.

## Example
<pre>
Usage is as follows with an example of a basic search +  hitting all of
the switches below:

usage: yaraGenerator.py [-h] -r RULENAME [-a AUTHOR] [-d DESCRIPTION]
                        InputDirectory

YaraGenerator

positional arguments:
  InputDirectory        Path To Files To Create Yara Rule From

optional arguments:
  -h, --help            show this help message and exit
  -r RULENAME         Enter A Rule/Alert Name (No Spaces + Must Start with Letter)
  -a AUTHOR           Enter Author Name
  -d DESCRIPTION      Provide a useful description of the Yara Rule

Example Usage To Build Two Rules from 3-4 Samples:

python yaraGenerator.py pipedream/ -r Trojan_Win_PipeDream -d "I Have Recently found this backdoor present in various customer environments, it has an interesting beacon containing many |'s thus the name" -a "Chris Clark Chris@xenosec.org"

[+] Yara Rule Generated: Trojan_Win_PipeDream.yar

  [+] Files Examined: ['50b136889962d0cbdb4f7bd460d7cd29', '79dce17498e1997264346b162b09bde8', '92ee1fb5df21d8cfafa2b02b6a25bd3b', 'a669c0da6309a930af16381b18ba2f9d']
  [+] Author Credited: Chris Clark Chris@xenosec.org
  [+] Rule Description: I Have Recently found this backdoor present in various customer environments, it has an interesting beacon containing many |'s thus the name

[+] YaraGenerator (C) 2013 Chris@xenosec.org https://github.com/Xen0ph0n/YaraGenerator

python yaraGenerator.py greencat/ -r Trojan_Win_GreenCat -d "This is a test to find the GreenCat Trojan from APT1 (Comment Panda)" -a "Chris Clark Chris@xenosec.org"

[+] Yara Rule Generated: Trojan_Win_GreenCat.yar

  [+] Files Examined: ['871cc547feb9dbec0285321068e392b8', '6570163cd34454b3d1476c134d44b9d9', '57e79f7df13c0cb01910d0c688fcd296']
  [+] Author Credited: Chris Clark Chris@xenosec.org
  [+] Rule Description: This is a test to find the GreenCat Trojan from APT1 (Comment Panda)

[+] YaraGenerator (C) 2013 Chris@xenosec.org https://github.com/Xen0ph0n/YaraGenerator

Resulting Yara Rules:

{
meta:
      author = "Chris Clark Chris@xenosec.org"
      date = "2013-05-04"
      description = "This is a test to find the GreenCat Trojan from APT1 (Comment Panda)"
      hash0 = "871cc547feb9dbec0285321068e392b8"
      hash1 = "6570163cd34454b3d1476c134d44b9d9"
      hash2 = "57e79f7df13c0cb01910d0c688fcd296"
      yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
      $string0 = "\\cmd.exe"
      $string1 = "%-24s %s"
      $string2 = "CD-ROM"
      $string3 = "GetComputerNameA"
      $string4 = "Invalid"
      $string5 = "KERNEL32.dll"
      $string6 = "CreateProcess failed"
      $string7 = "Start shell first."
      $string8 = "HttpAddRequestHeadersA"
      $string9 = "OpenT failed with %d"
      $string10 = "WININET.dll"
      $string11 = "3@YAXPAX@Z"
      $string12 = "strrchr"
      $string13 = " and the PID is %d"
      $string14 = "Removeable"
      $string15 = "%-26s %5d"
      $string16 = "YYt5j\\"
      $string17 = "CreateThread"
      $string18 = "InternetReadFile"
      $string19 = "_adjust_fdiv"
      $string20 = "GetModuleHandleA"
      $string21 = "ReadFile"
      $string22 = "__getmainargs"
      $string23 = "OpenService failed"
      $string24 = "list service failed"
      $string25 = "%s Connected"
      $string26 = "ADVAPI32.dll"
      $string27 = "OpenSCManagerA"
      $string28 = "whoami"
condition:
      all of them
}


rule Trojan_Win_PipeDream
{
meta:
      author = "Chris Clark Chris@xenosec.org"
      date = "2013-05-04"
      description = "I Have Recently found this backdoor present in various customer environments, it has an interesting beacon containing many |'s thus the name"
      hash0 = "50b136889962d0cbdb4f7bd460d7cd29"
      hash1 = "79dce17498e1997264346b162b09bde8"
      hash2 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
      hash3 = "a669c0da6309a930af16381b18ba2f9d"
      yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
      $string0 = "ToArray"
      $string1 = "lpLCData"
      $string2 = "op_Explicit"
      $string3 = "EditorBrowsableAttribute"
      $string4 = "m_MyWebServicesObjectProvider"
      $string5 = "Activator"
      $string6 = "Rectangle"
      $string7 = "AppWinStyle"
      $string8 = "GetWindowThreadProcessId"
      $string9 = "DebuggerHiddenAttribute"
      $string10 = "Object"
      $string11 = "WriteAllText"
      $string12 = "SpecialFolder"
      $string13 = "Microsoft.VisualBasic"
      $string14 = "CreateInstance"
      $string15 = "System.Threading"
      $string16 = "DirectoryInfo"
      $string17 = "Command"
      $string18 = "Graphics"
      $string19 = "FileInfo"
      $string20 = "Strings"
      $string21 = "Cursor"
      $string22 = "Process"
      $string23 = "get_Parent"
      $string24 = "GetWindowTextLength"
      $string25 = "8.0.0.0"
      $string26 = "Cursors"
      $string27 = "m_ComputerObjectProvider"
condition:
      all of them
}
</pre>

## Results

<pre>

PipeDream:

100% Hits on Samples: 

$ yara -r Trojan_Win_PipeDream.yar pipedream/
Trojan_Win_PipeDream pipedream//VTDL50B136889962D0CBDB4F7BD460D7CD29.danger
Trojan_Win_PipeDream pipedream//VTDL79DCE17498E1997264346B162B09BDE8.danger
Trojan_Win_PipeDream pipedream//VTDL92EE1FB5DF21D8CFAFA2B02B6A25BD3B.danger
Trojan_Win_PipeDream pipedream//VTDLA669C0DA6309A930AF16381B18BA2F9D.danger

100% True Negatives on ~5,000 Malware Samples
$ yara -r Trojan_Win_PipeDream.yar ../../MalwareSamples/

100% True Negatives on ~10,000 Clean Files
$ yara -r Trojan_Win_PipeDream.yar ../../CleanFiles/

100% Success Hunting On Virus Total


GreenCat Rule:

100% Hits on Test Samples:

$ yara -r Trojan_Win_GreenCat.yar greencat/
Trojan_Win_GreenCat greencat//8bf5a9e8d5bc1f44133c3f118fe8ca1701d9665a72b3893f509367905feb0a00
Trojan_Win_GreenCat greencat//c196cac319e5c55e8169b6ed6930a10359b3db322abe8f00ed8cb83cf0888d3b
Trojan_Win_GreenCat greencat//c23039cf2f859e659e59ec362277321fbcdac680e6d9bc93fc03c8971333c25e

100% True Positives On Other Samples In the APT1 Cadre which were detected as Green Cat By Other Yara Rules:

$ yara -r Trojan_Win_GreenCat.yar ../../MalwareSamples/APT1Malware/
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//13765eb12853f6268ce5052295c25e2fe53acf6e7b04c1c0ae1c78c5f4ae52bf
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//14a22f11c0121492cfabc529bcffecda5d076e79e459a87b87e6db7c20b6c89d
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//1877a5d2f9c415109a8ac323f43be1dc10c546a72ab7207a96c6e6e71a132956
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//20ed6218575155517f19d4ce46a9addbf49dcadb8f5d7bd93efdccfe1925c7d0
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//25485ac0aaceb982231a4d5f08e81b4dcf04b4e531d33145b5d6a5ee8d50d138
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//25f3aa7489eccce3fdd84b62d0285885f413b1d9696a947842a1b5581f25816a
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//4144820d9b31c4d3c54025a4368b32f727077c3ec253753360349a783846747f
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//4487b345f63d20c6b91eec8ee86c307911b1f2c3e29f337aa96a4a238bf2e87c
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//468bef292236e98a053333983f7094f64551a05509837c775fa65fdb785ca95a
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//6ad0190caa69dc0d662088f86aab7ee3355e788b1196552dd7487f6052150d8e
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//6c38678549ff31aff2c0164566c2494f57987b1af43650f476a824fc10b26108
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//72e01e875b93e6808e8fff0e8a8f19b842ed213a9fcb38c175f6e8533af57d51
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//78e07f4cbbbf119e5dac565e764a4fc7cf2d1938e5948cea03ae3b597d63c34f
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//7d4e44037e53b6e5de45deb9ee4cf5921b52f8eb1073136f7c853e6f42516247
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//89e0016fc5bd3cd4e25f88c70f9f8f13f81a45e3c6dc8ac2a4be44b5c5274957
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//8bf5a9e8d5bc1f44133c3f118fe8ca1701d9665a72b3893f509367905feb0a00
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//a4f141b99b50cd537644b334d14575060522ee77a7d362e49f2bdc733379f982
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//c196cac319e5c55e8169b6ed6930a10359b3db322abe8f00ed8cb83cf0888d3b
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//c23039cf2f859e659e59ec362277321fbcdac680e6d9bc93fc03c8971333c25e
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//dd5261df621077ed13be8741f748f61c5ed09bd04ca48526492fc0b559832184
Trojan_Win_GreenCat ../../MalwareSamples/APT1Malware//f76dd93b10fc173eaf901ff1fb00ff8a9e1f31e3bd86e00ff773b244b54292c5

100% True Negatives on clean files:

$ yara -r Trojan_Win_GreenCat.yar ../../CleanFiles/

</pre>
