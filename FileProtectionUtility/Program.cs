using System.Security.Cryptography;

namespace FileProtectionUtility
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Title = Resources.ConsoleTitle;
            Console.WriteLine(Resources.ConsoleTitle);
            Console.WriteLine();
            if (args.Length is 0 or 1 or 2)
            {
                Console.WriteLine(Resources.ParametersString);
                Console.WriteLine();
                Console.WriteLine(Resources.ExitString);
                _ = Console.ReadKey(true);
            }
            else
            {
                if (args[0] is "/encrypt" or "/decrypt")
                {
                    string FilePath;
                    bool IsDirectory;
                    if (!Path.IsPathFullyQualified(args[1]))
                    {
                        FilePath = AppDomain.CurrentDomain.BaseDirectory + "\\" + args[1];
                    }
                    else
                    {
                        FilePath = args[1];
                    }
                    IsDirectory = Path.EndsInDirectorySeparator(args[1]);
                    if (IsDirectory)
                    {
                        bool Recurse = args.Contains("-recurse");
                        string[] FilePaths = Directory.GetFiles(FilePath, "*", Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
                        bool DeletionFailed = false;
                        bool OperationFailure = false;
                        string[] Options = args.Skip(3).ToArray();
                        foreach (string path in FilePaths)
                        {
                            if (RunCommand(args[0], path, args[2], Options, out bool OriginalNotDeleted))
                            {
                                if (!DeletionFailed && OriginalNotDeleted)
                                {
                                    DeletionFailed = OriginalNotDeleted;
                                }
                            }
                            else
                            {
                                OperationFailure = true;
                            }
                        }
                        if (!OperationFailure)
                        {
                            if (DeletionFailed)
                            {
                                Console.WriteLine(Resources.MultipleDeletionFailedWarningMessageString);
                            }
                            else
                            {
                                Console.WriteLine(Resources.OperationCompletedString);
                            }
                        }
                        else
                        {
                            Console.WriteLine(Resources.MultipleOperationFailedErrorString);
                        }
                    }
                    else
                    {
                        Console.WriteLine(Resources.EncryptingString);
                        Console.WriteLine();
                        if (RunCommand(args[0], FilePath, args[2], args.Skip(3).ToArray(), out bool OriginalNotDeleted))
                        {
                            if (OriginalNotDeleted)
                            {
                                Console.WriteLine(Resources.DeletionFailedWarningMessageString);
                            }
                            else
                            {
                                Console.WriteLine(Resources.OperationCompletedString);
                            }
                        }
                        else
                        {
                            Console.WriteLine(Resources.OperationFailedErrorString);
                        }
                    }
                }
                else
                {
                    Console.WriteLine(Resources.UnrecognizedCommandErrorString);
                }
                Console.WriteLine();
                Console.WriteLine(Resources.ExitString);
                _ = Console.ReadKey(true);
            }
        }

        /// <summary>
        /// Esegue il comando.
        /// </summary>
        /// <param name="Command">Comando.</param>
        /// <param name="FilePath">Percorso del file.</param>
        /// <param name="Password">Password.</param>
        /// <param name="Options">Opzioni del comando.</param>
        /// <param name="OriginalNotDeleted">Indica se il file originale è stato eliminato o meno.</param>
        private static bool RunCommand(string Command, string FilePath, string Password, string[] Options, out bool OriginalNotDeleted)
        {
            OriginalNotDeleted = false;
            try
            {
                using FileStream OriginalFileStream = new(FilePath, FileMode.Open, FileAccess.Read, FileShare.None);
                bool Result = false;
                if (Command is "/encrypt")
                {
                    bool Overwrite = Options.Contains("-overwrite");
                    Console.WriteLine(Resources.EncryptingString);
                    Console.WriteLine();
                    Result = EncryptFile(OriginalFileStream, FilePath, Password, Overwrite);
                    OriginalFileStream.Dispose();
                    if (Result)
                    {
                        try
                        {
                            File.Delete(FilePath);
                        }
                        catch (Exception ex) when (ex is IOException or PathTooLongException or UnauthorizedAccessException)
                        {
                            OriginalNotDeleted = true;
                        }
                    }
                    return Result;
                }
                else
                {
                    if (Path.GetExtension(FilePath) is ".enc")
                    {
                        Console.WriteLine(Resources.DecryptingString);
                        Console.WriteLine();
                        Result = DecryptFile(OriginalFileStream, FilePath, Password);
                        OriginalFileStream.Dispose();
                        if (Result)
                        {
                            try
                            {
                                File.Delete(FilePath);
                            }
                            catch (Exception ex) when (ex is IOException or PathTooLongException or UnauthorizedAccessException)
                            {
                                OriginalNotDeleted = true;
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine(Resources.InvalidExtensionErrorString);
                    }
                    return Result;
                }
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine(Resources.FileNotFoundErrorString);
                return false;
            }
        }

        /// <summary>
        /// Esegue la codifica di un file.
        /// </summary>
        /// <param name="OriginalFileStream">Oggetto <see cref="FileStream"/> relativo al file originale.</param>
        /// <param name="FilePath">Percorso del file originale.</param>
        /// <param name="Password">Password.</param>
        /// <param name="Overwrite">Indica se sovrascrivere il file se già esiste.</param>
        /// <returns>true se l'operazione è riuscita, false altrimenti.</returns>
        private static bool EncryptFile(FileStream OriginalFileStream, string FilePath, string Password, bool Overwrite)
        {
            try
            {
                byte SaltSize = 16;
                using Rfc2898DeriveBytes Generator = new(Password, SaltSize);
                using Aes EncryptionAlg = Aes.Create();
                EncryptionAlg.IV = Generator.GetBytes(EncryptionAlg.BlockSize / 8);
                EncryptionAlg.Key = Generator.GetBytes(EncryptionAlg.KeySize / 8);
                using FileStream NewFile = new(FilePath + ".enc", Overwrite ? FileMode.Create : FileMode.CreateNew, FileAccess.Write, FileShare.None);
                NewFile.Write(Generator.Salt, 0, SaltSize);
                using CryptoStream EncryptedStream = new(NewFile, EncryptionAlg.CreateEncryptor(), CryptoStreamMode.Write);
                OriginalFileStream.CopyTo(EncryptedStream);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(Resources.GeneralErrorString + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Esegue la decodifica di un file.
        /// </summary>
        /// <param name="OriginalFileStream">Oggetto <see cref="FileStream"/> relativo al file originale.</param>
        /// <param name="FilePath">Percorso del file.</param>
        /// <param name="Password">Password.</param>
        /// <returns>true se l'operazione è riuscita, false altrimenti.</returns>
        private static bool DecryptFile(FileStream OriginalFileStream, string FilePath, string Password)
        {
            try
            {
                byte SaltSize = 16;
                byte[] Salt = new byte[SaltSize];
                OriginalFileStream.Read(Salt, 0, SaltSize);
                Rfc2898DeriveBytes Generator = new(Password, Salt);
                Aes EncryptionAlg = Aes.Create();
                EncryptionAlg.IV = Generator.GetBytes(EncryptionAlg.BlockSize / 8);
                EncryptionAlg.Key = Generator.GetBytes(EncryptionAlg.KeySize / 8);
                using FileStream DecryptedFile = new(FilePath.Replace(".enc", string.Empty), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using CryptoStream DecryptionStream = new(OriginalFileStream, EncryptionAlg.CreateDecryptor(), CryptoStreamMode.Read);
                DecryptionStream.CopyTo(DecryptedFile);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(Resources.GeneralErrorString + ex.Message);
                return false;
            }
        }
    }
}