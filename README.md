# Hash-cracking
This program is designed to implement a multi-threaded password-cracking application using the crypt() family of functions to crack hashed passwords.

Command-Line Options:
-i(Input file): Specifies the file contatining hashed passwords to be cracked (required)
-o(Output file): Specifies the output file for cracked passwords; defaults to stdout if not provided.
-d (Dictionary file): Specifies the dictionary file with plain-text passwords to match against the hashes (required).
-t (Threads): Specifies the number of threads to use (default:1,up to 24).
-v (Verbose): Enables verbose output for debugging; writes diagnostics to stderr.
-h (Help): Outputs usage instructions to stderr.
-n (Nice): Applies the nice() function to deprioritize the process for CPU scheduling.
