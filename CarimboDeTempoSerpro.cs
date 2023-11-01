using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509.Store;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Utils
{
    internal class CarimboDeTempoSerpro
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param> Conteúdo a ser carimbado
        /// <param name="certRequestBytes"></param> Certificado que será utilizado para autenticação com os serviços de carimbo da SERPRO
        /// <param name="certPassword"></param> Senha do certificado que será utilizado para autenticação dos os serviços de carimbo da SERPRO
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static string Execute(string data, byte[] certRequestBytes, string certPassword)
        {
            //Calculando o resumo criptografico SHA-256 do conteudo que sera carimbado
            byte[] imprint = SHA256.HashData(Encoding.UTF8.GetBytes(data));

            //Enviando requisição de carimbo do tempo
            byte[] carimbo = GetTimestampToken(imprint, certRequestBytes, certPassword);

            if (carimbo.Length > 0)
            {
                return Convert.ToBase64String(carimbo);
            }

            throw new Exception("Falha ao obter carimbo de tempo");
        }

        public static byte[] GetTimestampToken(byte[] imprint, byte[] certRequestBytes, string certPassword)
        {
            TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
            tsaGenerator.SetCertReq(true);

            //Definido o OID da politica
            tsaGenerator.SetReqPolicy("2.16.76.1.6.2");

            //OID SHA-256
            TimeStampRequest timeStampRequest = tsaGenerator.Generate("2.16.840.1.101.3.4.2.1", imprint, Org.BouncyCastle.Math.BigInteger.ValueOf(DateTime.Now.Ticks));
            byte[] request = timeStampRequest.GetEncoded();

            RequestSigner requestSigner = new();
            byte[] signedRequest = requestSigner.SignRequest(request, certRequestBytes, certPassword);

            byte[] responseBytes = GetTSAResponse(signedRequest);

            TimeStampResponse response = new(responseBytes);

            PkiFailureInfo failure = response.GetFailInfo();
            int value = (failure == null) ? 0 : failure.IntValue;
            if (value != 0)
            {
                throw new Exception(string.Format("invalid.tsa.1.response.code.2", "", value.ToString()));
            }
            TimeStampToken tsToken = response.TimeStampToken;
            if (tsToken == null)
            {
                throw new Exception(string.Format("tsa.1.failed.to.return.time.stamp.token.2", "", value.ToString()));
            }

            response.Validate(timeStampRequest);

            return tsToken.GetEncoded();
        }

        public static byte[] GetTSAResponse(byte[] content)
        {
            TcpClient client = new();
            client.ReceiveTimeout = 30000;

            client.Connect("act.serpro.gov.br", 3318);
            NetworkStream networkStream = client.GetStream();

            networkStream.Write(IntToByteArray(1 + content.Length), 0, 4);
            networkStream.WriteByte(0x00);
            // Envie os dados para o servidor
            networkStream.Write(content, 0, content.Length);

            Thread.Sleep(500);
            // Lendo tamanho total
            byte[] tamanhoRetorno = new byte[4];
            networkStream.Read(tamanhoRetorno, 0, 4);
            int tamanho = (int)new System.Numerics.BigInteger(tamanhoRetorno);

            Thread.Sleep(500);
            // Lendo flag
            byte[] retornoFlag = new byte[1];
            networkStream.Read(retornoFlag, 0, 1);
            // tamanho total menos o tamanho da flag
            tamanho -= 1;

            Thread.Sleep(500);
            // Lendo dados carimbo
            byte[] retornoCarimboDeTempo = new byte[tamanho];
            networkStream.Read(retornoCarimboDeTempo, 0, tamanho);

            return retornoCarimboDeTempo;
        }

        public static byte[] IntToByteArray(int value)
        {
            byte[] buffer = new byte[4];

            // PROTOCOL RFC 3161 - format big-endian of JVM
            buffer[0] = (byte)(value >> 24 & 0xff);
            buffer[1] = (byte)(value >> 16 & 0xff);
            buffer[2] = (byte)(value >> 8 & 0xff);
            buffer[3] = (byte)(value & 0xff);

            return buffer;
        }
    }

    public class RequestSigner
    {
        public byte[] SignRequest(byte[] request, byte[] certRequestBytes, string certPassword)
        {
            Pkcs12Store pkcs12Store = new Pkcs12StoreBuilder().Build();
            using (MemoryStream certStream = new(certRequestBytes))
            {
                pkcs12Store.Load(certStream, certPassword.ToCharArray());
            }

            string alias = pkcs12Store.Aliases.Cast<string>().FirstOrDefault();
            //Caso a lista de alias venha desordenada, basta informar abaixo, o alias correto referente ao certificado (geralmente é o último nome da cadeia de certificação)
            AsymmetricKeyParameter privateKey = pkcs12Store.GetKey(alias).Key;

            X509Certificate signCert = new(certRequestBytes, certPassword);

            var bcCertificate = DotNetUtilities.FromX509Certificate(signCert);

            SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder().Build(new Asn1SignatureFactory("SHA256WITHRSA", privateKey), bcCertificate);

            CmsSignedDataGenerator generator = new();
            generator.AddSignerInfoGenerator(signerInfoGenerator);

            var allCerts = new List<Org.BouncyCastle.X509.X509Certificate>
            {
                bcCertificate
            };

            X509CollectionStoreParameters storeParams = new (allCerts);
            var certStore = X509StoreFactory.Create("Certificate/Collection", storeParams);

            generator.AddCertificates(certStore);

            CmsProcessableByteArray data = new(request);
            CmsSignedData signed = generator.Generate(data, true);

            return signed.GetEncoded();
        }
    }
}

