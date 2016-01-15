# Clipenc

Clipenc is an easy tool for encryption and decryption of your files, text messages or images. Key are managed automaticaly by the tool and encryption/decryption process can be performed directly through the clipboard.

# Installing

## Ubuntu/Debian

Launch install script from a terminal:
	`sudo ./install.sh`

## Fedora/Redhat

Launch install script from a terminal:
	`su`
	`./install.sh`
Then create three keyboard shortcuts for the following scripts :
  * c_enc: encryption of the clipboard (Shift + Ctrl + e)
  * c_dec: decryption of the clipboard (Shift + Ctrl + d)
  * c_gen: generation of a new key (Shift + Ctrl + g) 

## Other Linux/Unix distribution or installing from Makefile

Clipenc required OpenSSL development package and xclip package.

Compile from the source code:
	`make`
Installing:
	`make install`

Then create three keyboard shortcuts as explained in the previous section.

# Usage

## Clipboard usage

### Key generation
If it is your first utilization, start to generate a new key by pressing Shift + Ctrl + g. Other keys can be generated using the same keyboard shortcut.

### Encryption
First, highlight with the mouse the text that you want to encrypt. Then press Shift + Ctrl + e to encrypt it. Finaly press Ctrl + v in any text editor to output the encrypted text.

### Decryption
First, higlight the encrypted text with the mouse. Be carefull, the text higlighted must contained at least the starting tag `<enc>`and the ending tag `<\enc>`. Any text that is not encluded in these tag will be considered as plaintext. The press Shift + Ctrl + d to decrypt it. Finaly press Ctrl + v in any text editor to output the decrypted text.

## Terminal usage

Command `clipenc -h`will display the help.
	
