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
            catch (Exception e) {
                return "";
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
            catch (Exception e) {
                return "";
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



        public static string GetIV(string input) {
            return "wivaoinOI#$U(*#Ukjlvs:L:A)_32-942";
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

    }
}
