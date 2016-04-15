# Introduction #
Normally, a keyfile and the encoded data are aligned so that a byte of each, sequentially, can be used to decode a message.  When there is a data missing or incorrect, using the normal sequence may lead to corruption of the output, rendering it unreadable.  Xor decoding with human-transcribed or lossy data can be a tedious task and there is a great potential for errors of this kind.

**Autoalignment** is a feature presented in OtpXor, OtpBot and WebXor where the position is adjusted between the key and the encoded data to reduce the effects of lossy data and mistranscriptions on the rest of the message.  This particular feature only applies to decoded output of ANSI text.



# Error detection #
When a message decode is assumed to be in ANSI text, all of the byte values can be assumed to be in a certain byte value range.  This fact presents the ability to detect whether a decoded byte is error or not.

# Determining the best alignment #
Because we can detect errors for individual bytes, we can also run some limited tests to see if there are sequences of bytes near the ones we've been given that produce less errors than others.

By testing single adjustments to the alignment (within tolerances) between the two data sets, when an error occurs, the alignment adjustment that presents the least errors in the remaining bytes to decode can be selected to salvage the rest of the message.

See the specific "Types" sections for more detailed behavior.

## In specific programs ##
This document discusses best behaviors for autoalignment which include manipulating the current decoding byte position in both the key and encoded data within adjustable tolerances - however related program behavior may differ.

For the purpose of salvaging message data, adjustment of the position for a single buffer (either the key or encoded data) through both advancement and reversing is sufficient (-N to +M). Depending on the implementation of these, extraneous bytes may be added or skipped at the location of the error.

For implementations which advance both the position of either the key or encoded-data (0 to +N each) it is more likely that any extraneous bytes will appear at the end of the message than the middle - and responsible bounds checking can easily eliminate these.

> A list of how related programs handle alignment is listed below:
  * _OtpXor_ - Supports only Key position autoalignment -2 to +2 bytes with extraneous bytes at error locations.
  * _OtpBot_ - Implements OtpXor
  * _WebXor 1.1 and lower_ - Supports only Key position autoalignment -N to +N bytes adjustable tolerance and skips error bytes.
  * _WebXor 2.0 and higher_ - Will support dual position autoalignment of adjustable tolerances.  Error-indicator-byte insertion may be implemented.



# Types of Data Errors #
Generally in the way of lossy data and transcriptions, errors occur in several ways:
  1. The byte value was misinterpreted as a different value
  1. The byte value was misinterpreted as more than one value
  1. The byte was missed entirely
  1. The byte value was mistaken for part of another byte

Because XOR decoding expects bytes from the key and encoded data to be aligned into pairs and decoded sequentially, Type 2,3&4 errors will corrupt further data.  Autoalignment targets these problems specifically.

Type 1 errors will not change the number of bytes (length of data) and so do not mismatch/misalign or corrupt the decoded message.

To help explain the behavior of Autoalignment in each of these cases, examples are shown below.
For the sake of simplicity below, examples will be shown below in hexadecimal where a correct decode results in all 0's (the byte values will match) rather than ANSI Text.  For example:
| **Key Data**        | 0A | 0B | 0C | 0D | 0E | 0F |
|:--------------------|:---|:---|:---|:---|:---|:---|
| **Encoded Data**    | 0A | 0B | 0C | 0D | 0E | 0F |
| **Decoded Message** | 00 | 00 | 00 | 00 | 00 | 00 |

## Type 2 Behavior ##
In Type 2 errors, there are more bytes in the encoded data than originally intended by the author of the message.

In the example below, the value 03 was added by mistranscription after 0B (positions 1 and 2, respectively). Despite the fact that the rest of the message was transcribed properly, when this was decoded, all further decoding after position 2 was corrupted.

| Position | 0 | 1 | 2 | 3 | 4 | 5 | 6 |
|:---------|:--|:--|:--|:--|:--|:--|:--|
| **Key Data**        | <font color='green'>0A <table><thead><th> <font color='green'>0B </th><th> <font color='green'>0C </th><th> <font color='green'>0D </th><th> <font color='green'>0E </th><th> <font color='green'>0F </th></thead><tbody>
<tr><td> <b>Encoded Data</b>    </td><td> <font color='green'>0A </td><td> <font color='green'>0B </td><td> <font color='red'>03 </td><td> <font color='orange'>0C </td><td> <font color='orange'>0D </td><td> <font color='orange'>0E </td><td> <font color='orange'>0F </td></tr>
<tr><td> <b>Decoded Message</b> </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td><td> <font color='red'>0F </td><td> <font color='red'>01 </td><td> <font color='red'>03 </td><td> <font color='red'>01 </td><td> <font color='red'>?? </td></tr></tbody></table>

By detecting the error at position 2, the rest of the message is salvaged by advancing the encoded-data position by 1 at the error.<br>
<br>
See below, the extraneous byte is detected at Position 2, and the autoalignment skips to the next byte of the encoded-data to allow proper decoding.<br>
<table><thead><th> <b>Key Position</b>          </th><th>  0 </th><th>  1 </th><th>  <b>2</b> </th><th>  2 </th><th>  4 </th><th>  5 </th><th>  6 </th></thead><tbody>
<tr><td> <b>Encoded Pos Alignment</b> </td><td>  0 </td><td>  0 </td><td>  <b>0</b> </td><td> +1 </td><td> +1 </td><td> +1 </td><td> +1 </td></tr>
<tr><td> <b>Key Data</b>              </td><td> 0A </td><td> 0B </td><td> <b>0C</b> </td><td> 0C </td><td> 0D </td><td> 0E </td><td> 0F </td></tr>
<tr><td> <b>Encoded Data</b>          </td><td> <font color='green'>0A </td><td> <font color='green'>0B </td><td> <font color='red'><b>03</b> </td><td> <font color='green'>0C </td><td> <font color='green'>0D </td><td> <font color='green'>0E </td><td> <font color='green'>0F </td></tr>
<tr><td> <b>Decoded Message</b>       </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td><td>           </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td></tr></tbody></table>

Note that this document does not define a behavior for handling the undecodable byte "03" in this example, and whether it is discarded (as in this example) or represented somehow is implementation-specific.<br>
<br>
<h2>Type 3&4 behavior</h2>
In Type 3&4 errors, there are less bytes in the encoded data than originally intended by the author of the message - data has been irrecoverably lost. However, the data that has not been lost can also suffer from corruption:<br>
<br>
In the example below, a person transcribing did not hear the byte "0C" in an audio recording and did not enter it. Running it through a normal XOR decode hopelessly scrambles all of the message after the single missed byte.<br>
<table><thead><th> <b>Position</b>        </th><th>  0 </th><th>  1 </th><th>  2 </th><th>  2 </th><th>  4 </th><th>  5 </th></thead><tbody>
<tr><td> <b>Key Data</b>        </td><td> 0A </td><td> 0B </td><td> 0C </td><td> 0D </td><td> 0E </td><td> 0F </td></tr>
<tr><td> <b>Encoded Data</b>    </td><td> <font color='green'>0A </td><td> <font color='green'>0B </td><td> <font color='orange'>0D </td><td> <font color='orange'>0E </td><td> <font color='orange'>0F </td></tr>
<tr><td> <b>Decoded Message</b> </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td><td> <font color='red'>01 </td><td> <font color='red'>03 </td><td> <font color='red'>01 </td><td> <font color='red'>?? </td></tr></tbody></table>

By being able to detect the error at position 2, the rest of the message is easily salvaged by advancing the Key position to the next byte:<br>
<table><thead><th> <b>Encoded-Data Position</b> </th><th>  0 </th><th>  1 </th><th>  <b>2</b> </th><th>  2 </th><th>  3 </th><th>  4 </th></thead><tbody>
<tr><td> <b>Key Alignment</b>         </td><td>  0 </td><td>  0 </td><td>  <b>0</b> </td><td> +1 </td><td> +1 </td><td> +1 </td></tr>
<tr><td> <b>Key Data</b>              </td><td> <font color='green'>0A </td><td> <font color='green'>0B </td><td> <font color='red'><b>0C</b> </td><td> <font color='green'>0D </td><td> <font color='green'>0E </td><td> <font color='green'>0F </td></tr>
<tr><td> <b>Encoded Data</b>          </td><td> <font color='green'>0A </td><td> <font color='green'>0B </td><td> <font color='red'><b>0D</b> </td><td> <font color='green'>0D </td><td> <font color='green'>0E </td><td> <font color='green'>0F </td></tr>
<tr><td> <b>Decoded Message</b>       </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td><td>           </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td><td> <font color='green'>00 </td></tr></tbody></table>

Like in the Type 2 description, no behavior is defined here to indicate the position of the missing byte and is implementation-defined.