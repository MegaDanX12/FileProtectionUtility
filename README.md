# FileProtectionUtility

This is a very simple utility that allows to password protect files and entire folders.

# Command line format

The command line must have the following format:

FileEncryptionUtility /{command} {path} {password} [-options]

The file or folder path does not have to be absolute, in that case the current directory is searched.

If the path points to a directory it must end with a directory separator.

If the path points to a directory all files in it are encrypted/decrypted using the same password.

# Commands and options

Only two commands are accepted:

/encrypt: encrypts a file or a folder

/decrypt: decrypts a file or a folder


The following options are available:

-overwrite: overwrites the encrypted file if it already exists

-recurse: the command is run on all files in the directory and its subdirectories (by default the command is executed only on the specified directory)

-keeporiginal: keeps the original unencrypted file (by default the original file is deleted after the operation is completed)
