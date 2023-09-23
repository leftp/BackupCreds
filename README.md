# backupcreds

```
________________________________________________
|      _____________________________           |
| [][] _____________________________ [_][_][_] |
| [][] [_][_][_] [_][_][_][_] [_][_] [_][_][_] |
|            Dump all the Creds!               |
| [][] [][][][][][][][][][][][][][_] [][][][]  |
| [][] [_][][][][][][][][][][][][][] [][][][]  |
| [][] [__][][][][][][][][][][][][_] [][][][]  |
| [][] [___][][][][][][][][][][][__] [__][][]  |
|          [_][______________][_]              |
|          Lefteris (lefty) Panos              |
|______________________________________________|
```
## Abusing SeTrustedCredmanAccessPrivilege to dump user creds
The program provides the ability to dump the stored credentials a user might have in the Windows Credential Manager. It is a useful technique in cases were an elevated shell exists and multiple users are currently logged in.

1) Finds the right WinLogon process of the user we want to dump the creds
2) Opens the WinLogon process with PROCESS_QUERY_LIMITED_INFORMATION access 
3) Duplicates token with TOKEN_DUPLICATE access
4) Turns token to impersonation token
5) Enables SeTrustedCredmanAccessPrivilege permission
6) Opens the target process of the user
7) Steals and impersonates target user
8) Calls CredBackupCredentials while impersonating the WinLogon token passing a path to write to and a NULL password to disable the user encryption
9) While still impersonating opens the file and decrypts it using the CryptUnprotectData API
10) Deletes the file

## Usage
backupcreds [PID of target user] [path to save file]
Must be run from an elevated context.

## OPSEC
Currently writes to disk to an operator provided path. Will delete the path once done.
Accesses WinLogon.

## Credits
* Based on https://www.tiraniddo.dev/2021/05/dumping-stored-credentials-with.html
* Uses parts of SharpDPAPI (https://github.com/GhostPack/SharpDPAPI/)
* Shouts to @eksperience for helping out with the parsing and Nettitute RT
