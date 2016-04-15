This program is built to search XOR keyfiles for output and to extract messages at specific offsets.

  * The newest windows binary (unstable) can be found here: http://otpxor.googlecode.com/svn/trunk/Release/OtpXor.exe
  * The newest source code (unstable) can be found here: http://code.google.com/p/otpxor/source/browse/trunk
  * The newest stable windows package (with source) can be found to your left, in the sidebar.

The source-code **should** be linux/G++ compatible. If you have problems, please add an Issue Tracker entry.

## Usage ##
```
USAGE: otpxor.exe <command> <parameters>
Commands:
 h - help
 e - extract (parameters: keyfile, messagefile, offset, outputfile)
 a - extract + AutoCorrect (parameters: keyfile, messagefile, offset, outputfile)
 s - scan (parameters: keyfile messagefile)
 g - scan + gzip detection (parameters: keyfile messagefile)
Examples:
 OtpXor.exe e elpaso.bin blackotp18009.bin 1930 test.out
 - XORs blackotp18009.bin against elpaso.bin using offset 1930, and saves to test.out
 OtpXor.exe s elpaso.bin blackotp18009.bin
 - Searches elpaso.bin for a XOR sliding-window-scan result that is readable.
Notes:
 This program expects raw byte contents (aka "binary data") in input files.
 - It does not understand Hex (ff023b...) or Binary (110100...) or other cleartext.
```