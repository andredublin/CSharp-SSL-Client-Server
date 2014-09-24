using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertClient
{
    class Program
    {
        static X509Certificate2 clientCertificate;
        static X509Certificate2Collection certificateCollection;

        static void Main(string[] args)
        {
            FileStream fileStream = File.OpenRead("cert.pfx");
            byte[] buffer = new byte[fileStream.Length];
            int bytesRead = fileStream.Read(buffer, 0, (int)fileStream.Length);
            clientCertificate = new X509Certificate2(buffer, "password");

            certificateCollection = new X509Certificate2Collection(clientCertificate);

            TcpClient client = new TcpClient();
            client.Connect(IPAddress.Loopback, 8888);

            SslStream sslStream = new SslStream(
                client.GetStream(),
                false,
                new RemoteCertificateValidationCallback(ValidateServerCertificate),
                new LocalCertificateSelectionCallback(SelectUserCertificate));

            sslStream.AuthenticateAsClient("127.0.0.1", certificateCollection, SslProtocols.Default, false);

            string data = "Hey You Guys!";
            byte[] bData = Encoding.UTF8.GetBytes(data);

            if (client.Connected && sslStream.CanWrite)
            {
                sslStream.Write(bData);
            }

            client.Close();
            sslStream.Dispose();
        }

        static X509Certificate2 SelectUserCertificate(
            object sender,
            string targetHost,
            X509CertificateCollection collection,
            X509Certificate remoteCert,
            string[] acceptableIssuers)
        {
            return clientCertificate;
        }

        static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                byte[] clientCertBytes = certificate.GetRawCertData();
                byte[] serverCertBytes = clientCertificate.GetRawCertData();

                if (clientCertBytes.Length != serverCertBytes.Length)
                {
                    throw new Exception("Client/server certificates do not match.");
                }

                for (int i = 0; i < clientCertBytes.Length; i++)
                {
                    if (clientCertBytes[i] != serverCertBytes[i])
                    {
                        throw new Exception("Client/server certificates do not match.");
                    }
                }
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }
    }
}
