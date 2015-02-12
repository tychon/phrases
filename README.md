### TODO

* make resalt and change-lock more user-friendly / "safe"
* formula for pbkdf2 rounds
* maybe use ForeignPtr and mlock as suggested in
  http://stackoverflow.com/questions/11932246/against-cold-boot-attacks-how-to-restrain-sensitive-information-in-haskell
* license!

For more TODOs use `git grep TODO`


# Short Intro

After you've got it to run (see section below) you can create your container with `./phrases init teststorage`. This will ask you for a passphrase and create a file in the current directory. You can then do `./phrases open teststorage` to open the storage and change anything. One important thing: Everytime you change something the storage is saved to disk, so you can't restore anything by killing the program. Also: don't miss the information on security I've posted below.

After you've authorized and the file was decrypted you get a command prompt. There are different prompt symbols. The simplest one is `>` you should then type `list` get a list of all entries or `list hub` to get a list of all entries containing `hub` in their name (case insensitive regex).

The prompt then changes to `SELECT >` and you should enter a number giving one of the results in the list and the prompt changes to `name >` where `name` is the name of the selected entry. Now you can use the type specific commands (listed in Commands on Prompt) too.

To create a new entry for your github password say `new phrase` then it will ask you for a name. There you should enter something like `tychon@github` so you can recognise this password later. Then enter a comment or leave it empty, then enter your passphrase.

If you wan't to know a password use `name > plain` to show in terminal or `name > clipboard` to copy to clipboard without printing in plaintext to your terminal. The clipboard commands vary for the different data types.

To delete an entry, select it and type `delete`.

# Install

Requires the following haskell modules:

* pbkdf
* drbg
* ansi-terminal
* regex-tdfa
* hclip (also requires external program xclip or xsel on linux)

Try `cabal install ...` to get them.
Use `make` to compile.

# Basic Usage

This helptext is shown by the program with `phrases help`.
It is extracted by awk in the makefile and embedded into the Haskell code:
```
%% BEGIN_HELPTEXT

$ phrases COMMAND [arguments]

Commands:

version     show version number
init FILE   create new container
info FILE   show information (version number) about container
open FILE   open container for reading and changing

migrate OLDVERSION NEWVERSION
            migrate container from old version to new one.
            See version command for supported versions.
            In general version numbers of containers corresponds to git tag of
            source code. If you forgot the version number of your storage file,
            open in hex editor and look for the version=X property.
dump CONTAINERFILE PLAINFILE
            Open container and dump serialized Storage object to file.
            Use with care.

Supported Versions:
  reading: 1, 2
  writing: 2

When running:

You can always simply press Enter to clear screen.
Type "help" to see list of available commands in prompt.

For more information see the README.
%% END_HELPTEXT
```

### Commands on prompt

This helptext is shown if you type `help` in the programs
command prompt. It's embedded on compiletime into the haskell code.
```
%% BEGIN_PROMPTHELP
quit        Exit program (unsupported on some systems, try 'exit')
exit        Exit program (deprecated, use 'quit')
stats       Show stats about storage.
save        Save storage to file again (pretty useless).
change-lock Change passphrase of container.
resalt      Change permanent salt of container
test        Enter a passphrase and test if it matches the current one.
list REGEX  Search in names of entries for POSIX regex.
new TYPE    Create new entry, types: phrase, asym, field, data

With selected entry:
  plain       Show plaintext password on stdout.
  rename      Choose a new name
  comment     Change comment of entry
  delete      Delete entry.
  clear       Clear clipboard

Type-specific commands:
  phrase
    phrase          Change passphrase
    clipboard | cb  Copy data to clipboard.
  asym
    fingerprint  Set fingerprint
    set [FILE]   Load public key from file or stdin
    put [FILE]   Save public key to file or stdout
    setpriv [FILE]   Load private key from file or stdin
    putpriv [FILE]   Save private key to file or stdout
    fprintcb     Put fingerprint into clipboard
    pubcb        Put public key into clipboard
    privcb       Put private key into clipboard
  field
    set [FILE]  Load data from file or stdin
    put [FILE]  Save data to file or stdout
When entering long texts with using the load command on console
use Ctrl-D (maybe 2 times) to finsh.
%% END_PROMPTHELP
```

# Notes on Security

* Since Haskell trades memory for speed, your passwords may end up all over
  your memory. You should check if your system applies appropriate memory
  protection measures.
* The hash of your passphrase is stored in memory, so the program can save
  your file after every change.
* The security of this program relies heavily on the modules listes in
  'Requirements'. I have not reviewed the code nor do i have to knowledge to
  review strong crypto algorithms. I simply assume that the algorithms provided
  in mainstream packages on hackage are well-imlemented.
* The randomness comes from System.Crypto.Random which uses your systems
  secure entropy. Make sure your system can provide secure entropy in the
  way required. This module seems to be untested on Windows. Refer to doc.
* Don't overdo the security here. You are going to post the password
  in your crappy browser anyways.


# Under The Hood

### Haskell coding style:
* No exceptions in pure code.
* Document impure behaviour ( exitFailiure, exitSuccess, error, ... )
* Many else I don't know yet, still learning ...

### Embedded files
The help texts and the GHC version are embedded into the code on compiletime
by Template Haskell. Have a look at EmbeddedContent.hs
When the embedded file content changed, run 'make clean' and then 'make'

### Storage file layout:
```
File:
|StorageProps|0|hash|hash|representation of Storage data type|
|plaintext     |encrypted                                    |
```

* length of one hash (SHA256): 32 bytes
* length of salt: min 16 bytes
* length of innersalt: min 16 bytes

The salt is not changed. Use 'resalt' to get new salt.
The innersalt is changed every time the file is saved to make sure the byte
stream from the DRBG is not the same as the previous one.
The two hashes are compared to see if the passphrase was correct, then the
contained serialized storage's hash is checked against one of them to ensure
the data is not corrupted. The lockhash is generated by running PBKDF2 on
passphrase and salt.

How to decrypt:

  * readProps
    * read StorageProps
  * checkStorageProps
    * check them for sane values
  * decrypt
    * retrieve passphrase
    * put passphrase and salt into sha512PBKDF2
    * seed HashDRBG with PBKDF2 result concatenated with innersalt
    * xor byte stream from DRBG with rest of file
    * check if the two hashes match
  * checkHash
    * check if one hash and the SHA256 of the plaintext storage data match
    * use 'readMaybe' to cast String to Storage
  * set lockhash and props in Storage

How to encrypt:

  * clear props and lockhash from storage
  * generate hash of serialized storage
  * generate innersalt
  * seed HashDRBG with lockhash concatenated with new innersalt
  * construct plaintext to be encrypted: concat two hashes and 'show storage'
  * xor byte stream from DRBG with plaintext

### The modules

* CryptoBackend (CryptoBackend.hs)
  All pure functions for en- and decryption.
* BasicUI (BasicUI.hs)
  IO functions doing the interesting IO things.
* EmbeddedContent (EmbeddedContent.hs)
  Provide the helptext and the ghc version by loading it on compiletime.
* Main (phrases.hs)
  Parsing of arguments, the prompt and tying together the basic IO things.

