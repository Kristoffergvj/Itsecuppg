using System;
using System.Text.Json;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Itsecuppg
{
    class Program
    {
        static void Main(string[] args)
        {
            //if (args[0] == "init")
            //{
            //    Init();
            //}



            //string readfile = File.ReadAllText(path);

            // Console.WriteLine(readfile);

            //RandomNumberGenerator rng = new RandomNumberGenerator();
            //byte[] a = new byte[15];


            // Client client1 = new Client();

            Init();
            SecretKey();
            
        }

        public void ReadFile()
        {

        }

        public void GetFile()
        {

        }
        public static void Init()
        {
            //generar en IV  ska lagras i Server Fil
            
            string input = Console.ReadLine();
            
            if (input == "init")
            {

              
                using (Aes myAes = Aes.Create())
                {

                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes_Aes(VaultKey() , myAes.IV);

                    // Decrypt the bytes to a string.
                    string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

                    string decrypted = "";

                    foreach (var item in encrypted)
                    {
                        decrypted += item;
                    }
                    Console.WriteLine("Round Trip: {0}", decrypted);


                    File.WriteAllText(@"serverFile.txt", decrypted);
                    if (!File.Exists(@"serverFile.txt"))
                    {
                        string s = decrypted;
                        File.WriteAllText(decrypted, s);
                    }
                }
            }

            static byte[] EncryptStringToBytes_Aes(byte[] Key, byte[] IV)
            {
                // Check arguments.
               
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                byte[] encrypted;

                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            //using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            //{
                            //    //Write all data to the stream.
                            //    swEncrypt.Write(plainText);
                            //}
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }

                // Return the encrypted bytes from the memory stream.
                return encrypted;
            }

            static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
            {
                // Check arguments.
                if (cipherText == null || cipherText.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {

                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return plaintext;
            }

            
            //Generar ett hemlig nyckeln _ lagras i clientfilen
            //lagra den hemliga nyckekn
        }

        public static byte[] SecretKey()
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            byte[] secretkey = new byte[16];
            rng.GetBytes(secretkey);

            string savedsecretkey = "";
            foreach (var item in secretkey)
            {
                Console.Write(item);
                savedsecretkey += item;

            }
            File.WriteAllText(@"clientFile.txt", savedsecretkey);
            if (!File.Exists(@"clientFile.txt"))
            {
                string s = savedsecretkey;
                File.WriteAllText(savedsecretkey, s);
            }
            return secretkey;

        }

        public static byte[] VaultKey()
        {
            string masterPassword = "hassan";
            byte[] secretKey = SecretKey();
            byte[] salt = new byte[] { 0x06, 0x07, 0x08, 0x09, 0x0A };
            int iterations = 10000;
            Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(masterPassword, salt, iterations, HashAlgorithmName.SHA256);

            int keyLength = 256 / 8; // 256 bits / 8 bits per byte = 32 bytes
            byte[] derivedKey = keyGenerator.GetBytes(keyLength);

            byte[] vaultKey = new byte[secretKey.Length];
            for (int i = 0; i < secretKey.Length; i++)
            {
                vaultKey[i] = (byte)(secretKey[i] ^ derivedKey[i]);
            }
            return vaultKey;

        }

    }


}

