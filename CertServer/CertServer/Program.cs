using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertServer
{
    class Program
    {
        static X509Certificate2 serverCertificate = null;

        static void Main(string[] args)
        {
            FileStream fileStream = File.OpenRead("cert.pfx");
            byte[] buffer = new byte[fileStream.Length];
            int bytesRead = fileStream.Read(buffer, 0, (int)fileStream.Length);
            serverCertificate = new X509Certificate2(buffer, "password");

            TcpListener listener = new TcpListener(IPAddress.Loopback, 8888);
            listener.Start();

            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();
                ProcessClient(client);
            }
        }

        static void ProcessClient(TcpClient client)
        {
            client.ReceiveBufferSize = 0x8000;
            SslStream sslStream = new SslStream(
                client.GetStream(),
                false,
                new RemoteCertificateValidationCallback(ValidateClientCertificate));

            sslStream.AuthenticateAsServer(serverCertificate, true, SslProtocols.Default, false);

            if (!sslStream.IsEncrypted || !sslStream.IsAuthenticated)
            {
                throw new Exception("SslStream is not secure.");
            }
            else
            {
                int bufferSize = 0x8000;
                int bytesRead = 0;
                string message = String.Empty;

                if (client.Connected && sslStream.CanRead)
                {
                    do
                    {
                        try
                        {
                            StringBuilder messageData = new StringBuilder();
                            byte[] buffer = new byte[bufferSize];
                            Decoder decoder = Encoding.UTF8.GetDecoder();

                            bytesRead = sslStream.Read(buffer, 0, bufferSize);
                            char[] chars = new char[decoder.GetCharCount(buffer, 0, bytesRead)];
                            decoder.GetChars(buffer, 0, bytesRead, chars, 0);
                            messageData.Append(chars);

                            Console.WriteLine(messageData.ToString());
                        }
                        catch
                        {
                            bytesRead = 0;
                        }
                    }
                    while (bytesRead > 0);
                }

                client.Close();
                sslStream.Dispose();
            }
        }

        static bool ValidateClientCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                byte[] clientCertBytes = certificate.GetRawCertData();
                byte[] serverCertBytes = serverCertificate.GetRawCertData();

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
            catch
            {
                return false;
            }

            return true;
        }
    }
}
