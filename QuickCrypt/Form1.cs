using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace QuickCrypt {
    public partial class Form1 : Form {
        public Form1() {
            InitializeComponent();
        }


        public struct DataBlock {
            public string key;
            public string hash;
            public string text;
        }

        private DataBlock GetDataFromForm() {
            DataBlock data = new DataBlock();
            data.key = txtKey.Text;
            data.hash = txtHash.Text;
            data.text = txtText.Text;
            return data;
        }

        private void btnDecrypt_Click(object sender, EventArgs e) {
            DataBlock data = GetDataFromForm();
            DecryptAction(ref data);
            txtText.Text = data.text;
            txtHash.Text = data.hash;
        }

        private void btnEncrypt_Click(object sender, EventArgs e) {
            DataBlock data = GetDataFromForm();
            EncryptAction(ref data);
            txtText.Text = data.text;
            txtHash.Text = data.hash;
        }

        private void DecryptAction(ref DataBlock dataBlock) {
            dataBlock.hash = GetHashofString(dataBlock.text);
            dataBlock.text = DecryptA(dataBlock.text, dataBlock.key, GetIV(dataBlock.key));
        }

        private void EncryptAction(ref DataBlock dataBlock) {
            dataBlock.text = EncryptA(dataBlock.text, dataBlock.key, GetIV(dataBlock.key));
            dataBlock.hash = GetHashofString(dataBlock.text);
        }




        public static string EncryptA(string dataToEncrypt, string password, string salt) {
            AesManaged aes = null;
            MemoryStream memoryStream = null;
            CryptoStream cryptoStream = null;

            try {
                //Generate a Key based on a Password, Salt and HMACSHA1 pseudo-random number generator 
                Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));

                //Create AES algorithm with 256 bit key and 128-bit block size 
                aes = new AesManaged();
                aes.Key = rfc2898.GetBytes(aes.KeySize / 8);
                aes.IV = rfc2898.GetBytes(aes.BlockSize / 8);

                //Create Memory and Crypto Streams 
                memoryStream = new MemoryStream();
                cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

                //Encrypt Data 
                byte[] data = Encoding.Unicode.GetBytes(dataToEncrypt);
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                //Return Base 64 String 
                return Convert.ToBase64String(memoryStream.ToArray());
            }
            finally {
                if (cryptoStream != null)
                    cryptoStream.Close();

                if (memoryStream != null)
                    memoryStream.Close();

                if (aes != null)
                    aes.Clear();
            }
        }

        public static string DecryptA(string dataToDecrypt, string password, string salt) {
            AesManaged aes = null;
            MemoryStream memoryStream = null;
            CryptoStream cryptoStream = null;

            try {
                //Generate a Key based on a Password, Salt and HMACSHA1 pseudo-random number generator 
                Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));

                //Create AES algorithm with 256 bit key and 128-bit block size 
                aes = new AesManaged();
                aes.Key = rfc2898.GetBytes(aes.KeySize / 8);
                aes.IV = rfc2898.GetBytes(aes.BlockSize / 8);

                //Create Memory and Crypto Streams 
                memoryStream = new MemoryStream();
                cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);

                //Decrypt Data 
                byte[] data = Convert.FromBase64String(dataToDecrypt);
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                //Return Decrypted String 
                byte[] decryptBytes = memoryStream.ToArray();
                return Encoding.Unicode.GetString(decryptBytes, 0, decryptBytes.Length);
            }
            finally {
                if (cryptoStream != null)
                    cryptoStream.Close();

                if (memoryStream != null)
                    memoryStream.Close();

                if (aes != null)
                    aes.Clear();
            }
        }






        public static byte[] EncryptString(ref DataBlock block) {
            //System.Security.Cryptography.AesManaged managed = new System.Security.Cryptography.AesManaged();
            //ICryptoTransform crypto = managed.CreateEncryptor(StringToByteArray(block.key), StringToByteArray(GetIV(block.key)));
            return null;
        }

        public static string GetIV(string input) {
            return "wivaoinOI#$U(*#Ukjlvs:L:A)_32-942";
        }



        static byte[] encryptStringToBytes_AesManaged(string plainText, byte[] Key, byte[] IV) {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            // Declare the streams used
            // to encrypt to an in memory
            // array of bytes.
            MemoryStream msEncrypt = null;
            CryptoStream csEncrypt = null;
            StreamWriter swEncrypt = null;

            // Declare the AesManaged object
            // used to encrypt the data.
            AesManaged AesManagedAlg = null;

            try {
                // Create an AesManaged object
                // with the specified key and IV.
                AesManagedAlg = new AesManaged();
                AesManagedAlg.Key = Key;
                AesManagedAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = AesManagedAlg.CreateEncryptor(AesManagedAlg.Key, AesManagedAlg.IV);

                // Create the streams used for encryption.
                msEncrypt = new MemoryStream();
                csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                swEncrypt = new StreamWriter(csEncrypt);

                //Write all data to the stream.
                swEncrypt.Write(plainText);

            }
            finally {
                // Clean things up.

                // Close the streams.
                if (swEncrypt != null)
                    swEncrypt.Close();
                if (csEncrypt != null)
                    csEncrypt.Close();
                if (msEncrypt != null)
                    msEncrypt.Close();

                // Clear the AesManaged object.
                if (AesManagedAlg != null)
                    AesManagedAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return msEncrypt.ToArray();

        }

        static string decryptStringFromBytes_AesManaged(byte[] cipherText, byte[] Key, byte[] IV) {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            // TDeclare the streams used
            // to decrypt to an in memory
            // array of bytes.
            MemoryStream msDecrypt = null;
            CryptoStream csDecrypt = null;
            StreamReader srDecrypt = null;

            // Declare the AesManaged object
            // used to decrypt the data.
            AesManaged AesManagedAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try {
                // Create an AesManaged object
                // with the specified key and IV.
                AesManagedAlg = new AesManaged();
                AesManagedAlg.Key = Key;
                AesManagedAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = AesManagedAlg.CreateDecryptor(AesManagedAlg.Key, AesManagedAlg.IV);

                // Create the streams used for decryption.
                msDecrypt = new MemoryStream(cipherText);
                csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                srDecrypt = new StreamReader(csDecrypt);

                // Read the decrypted bytes from the decrypting stream
                // and place them in a string.
                plaintext = srDecrypt.ReadToEnd();
            }
            finally {
                // Clean things up.

                // Close the streams.
                if (srDecrypt != null)
                    srDecrypt.Close();
                if (csDecrypt != null)
                    csDecrypt.Close();
                if (msDecrypt != null)
                    msDecrypt.Close();

                // Clear the AesManaged object.
                if (AesManagedAlg != null)
                    AesManagedAlg.Clear();
            }

            return plaintext;

        }



        private static byte[] EncodeToBase64(byte[] inputData) {
            MemoryStream sourceFile = new MemoryStream(inputData);
            MemoryStream targetFile = new MemoryStream();
            // Create a new ToBase64Transform object to convert to base 64.
            ToBase64Transform base64Transform = new ToBase64Transform();
            
            // Create a new byte array with the size of the output block size.
            byte[] outputBytes = new byte[base64Transform.OutputBlockSize];

            // Retrieve the file contents into a byte array.
            byte[] inputBytes = new byte[sourceFile.Length];
            sourceFile.Read(inputBytes, 0, inputBytes.Length);

            // Verify that multiple blocks can not be transformed.
            if (!base64Transform.CanTransformMultipleBlocks) {
                // Initializie the offset size.
                int inputOffset = 0;

                // Iterate through inputBytes transforming by blockSize.
                int inputBlockSize = base64Transform.InputBlockSize;

                while (inputBytes.Length - inputOffset > inputBlockSize) {
                    base64Transform.TransformBlock(
                        inputBytes,
                        inputOffset,
                        inputBytes.Length - inputOffset,
                        outputBytes,
                        0);

                    inputOffset += base64Transform.InputBlockSize;
                    targetFile.Write(
                        outputBytes,
                        0,
                        base64Transform.OutputBlockSize);
                }

                // Transform the final block of data.
                outputBytes = base64Transform.TransformFinalBlock(
                    inputBytes,
                    inputOffset,
                    inputBytes.Length - inputOffset);

                targetFile.Write(outputBytes, 0, outputBytes.Length);
                Console.WriteLine("Created encoded file at " + targetFile);
            }

            // Determine if the current transform can be reused.
            if (!base64Transform.CanReuseTransform) {
                // Free up any used resources.
                base64Transform.Clear();
            }

            // Close file streams.
            sourceFile.Close();
            byte[] outputData = targetFile.ToArray();
            targetFile.Close();
            return outputData;
        }

        public static byte[] DecodeFromBase64(byte[] inputData) {
            MemoryStream inStream = new MemoryStream(inputData);
            MemoryStream outStream = new MemoryStream();
            FromBase64Transform myTransform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces);

            byte[] myOutputBytes = new byte[myTransform.OutputBlockSize];

            //Retrieve the file contents into a byte array.
            byte[] myInputBytes = new byte[inStream.Length];
            inStream.Read(myInputBytes, 0, myInputBytes.Length);

            //Transform the data in chunks the size of InputBlockSize.
            int i = 0;
            while (myInputBytes.Length - i > 4/*myTransform.InputBlockSize*/) {
                myTransform.TransformBlock(myInputBytes, i, 4/*myTransform.InputBlockSize*/, myOutputBytes, 0);
                i += 4/*myTransform.InputBlockSize*/;
                outStream.Write(myOutputBytes, 0, myTransform.OutputBlockSize);
            }

            //Transform the final block of data.
            myOutputBytes = myTransform.TransformFinalBlock(myInputBytes, i, myInputBytes.Length - i);
            outStream.Write(myOutputBytes, 0, myOutputBytes.Length);

            //Free up any used resources.
            myTransform.Clear();

            inStream.Close();
            byte[] outData = outStream.ToArray();
            outStream.Close();
            return outData;
        }



        public static string GetHashofString(string input) {
            System.Security.Cryptography.MD5 hasher = System.Security.Cryptography.MD5.Create();
            ASCIIEncoding ascii = new ASCIIEncoding();
            byte[] data = ascii.GetBytes(input);
            byte[] digest = hasher.ComputeHash(data);
            return GetAsString(digest);
        }

        public static string GetAsString(byte[] bytes) {
            StringBuilder s = new StringBuilder();
            int length = bytes.Length;
            for (int n = 0; n < length; n++) {
                s.Append((int)bytes[n]);
                //if (n != length - 1) { s.Append(' '); } //adds spaces for formatting--unnecessary for us
            }
            return s.ToString();
        }

        public static byte[] StringToByteArray(string input) {
            ASCIIEncoding ascii = new ASCIIEncoding();
            byte[] data = ascii.GetBytes(input);
            return data;
        }

        private void DecryptActionOLD(ref DataBlock dataBlock) {
            //decode cipher text from base64
            byte[] rawEncrypyted = DecodeFromBase64(StringToByteArray(dataBlock.text));

            //decrypt cipher text
            string plainText = decryptStringFromBytes_AesManaged(rawEncrypyted, StringToByteArray(dataBlock.key), StringToByteArray(GetIV(dataBlock.key)));

            //hash clear text
            dataBlock.hash = GetHashofString(plainText);

            //compare with passed hash (if available)

            //populate dataBlock
            dataBlock.text = plainText;
        }

        private void EncryptActionOLD(ref DataBlock dataBlock) {
            //hash clear-text
            dataBlock.hash = GetHashofString(dataBlock.text);

            //encrypt clear-text
            byte[] encresult = encryptStringToBytes_AesManaged(dataBlock.text, StringToByteArray(dataBlock.key), StringToByteArray(GetIV(dataBlock.key)));

            //encode cipher text to base64
            byte[] base64result = EncodeToBase64(encresult);

            //populate dataBlock
            dataBlock.text = GetAsString(base64result);
        }
    }
}
