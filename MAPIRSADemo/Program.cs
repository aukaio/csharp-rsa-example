using System;
using System.Text;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using Crypto.Extensions;  // Needed to be able to import *.pem files into RSACryptoServiceProvider (Crypto is installed from NuGet)


class MerchantApiKeyAuth
{
    // This class handles RSA signing accoriding to the mCASH Merchant API.

    public string merchantId;
    public string userId;
    public RSAPKCS1SignatureFormatter signer;
    public string hashAlgorithm = "SHA256";
    public string encoding = "UTF-8";

    public Encoding encoder
    {
        get
        {
            return Encoding.GetEncoding(encoding);
        }
    }
    public HashAlgorithm hasher
    {
        get
        {
            return HashAlgorithm.Create(hashAlgorithm);
        }
    }

    public MerchantApiKeyAuth(string merchantId, string userId, RSA privateKey)
    {
        this.merchantId = merchantId;
        this.userId = userId;
        signer = new RSAPKCS1SignatureFormatter(privateKey);
    }
    public void SetHeaders(HttpWebRequest request, byte[] data)
    {
        // Sets the required headers to authorize with auth level KEY in the Merchant API.
        // This involves signing the request with an RSA signature.
        request.Headers["X-Mcash-Merchant"] = merchantId;
        request.Headers["X-Mcash-User"] = userId;
        request.Headers["X-Mcash-Content-Digest"] = String.Format("{0}={1}", hashAlgorithm, ComputeContentDigest(data));
        request.Headers["X-Mcash-Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        // Last step is calculating the value for the Authorization header.
        // Must be done after adding all X-Mcash-headers as they are included in the signature.
        request.Headers["Authorization"] = String.Format("RSA-{0} {1}", hashAlgorithm, ComputeSignature(request));  
    }

    public string ComputeContentDigest(byte[] data)
    {
        // Compute value for the X-Mcash-Content-Digest header
        return Convert.ToBase64String(hasher.ComputeHash(data));
    }

    public byte[] GetSignatureMessage(HttpWebRequest request)
    {
        // Generate the string that should be signed based on the request headers.

        WebHeaderCollection headers = request.Headers;
        string[] keys = headers.AllKeys;
        StringBuilder msgBuilder = new StringBuilder();
        msgBuilder.Append(request.Method + "|");
        msgBuilder.Append(request.RequestUri + "|");
        Array.Sort(keys);
        string sep = "";
        foreach (string key in keys)
        {
            if (!key.ToUpper().StartsWith("X-MCASH-")) continue;
            msgBuilder.Append(sep);
            msgBuilder.AppendFormat("{0}={1}", key.ToUpper(), headers[key]);
            sep = "&";
        }
        return encoder.GetBytes(msgBuilder.ToString());
    }

    public string ComputeSignature(HttpWebRequest request)
    {
        // Compute the signature for the request. The resulting value should go in the credentials part in the Authorization header.
        byte[] msg = GetSignatureMessage(request);
        signer.SetHashAlgorithm(hashAlgorithm);
        return Convert.ToBase64String(signer.CreateSignature(hasher.ComputeHash(msg)));
    }
}


class MerchantApiClient
{
    public string URL_PREFIX = "https://merchanttestbed.appspot.com/merchant/v1";
    public string encoding = "UTF-8";
    public MerchantApiKeyAuth auth;

    public MerchantApiClient(string merchantId, string userId, RSA privateKey)
    {
        auth = new MerchantApiKeyAuth(merchantId, userId, privateKey);
    }

    public string merchantId
    {
        get
        {
            return auth.merchantId;
        }
    }

    public string userId
    {
        get
        {
            return auth.userId;
        }
    }

    public Encoding encoder
    {
        get
        {
            return Encoding.GetEncoding(encoding);
        }
    }

    public HttpWebRequest GetRequest(string url, string method)
    {
        HttpWebRequest request = WebRequest.CreateHttp(URL_PREFIX + url);
        request.AllowAutoRedirect = false;
        request.Method = method;  // Must be set BEFORE signature is computed.
        request.Accept = "application/vnd.mcash.api.merchant.v1+json";
        return request;
    }

    public WebResponse DoRequest(string url, string method, string data = null)
    {
        HttpWebRequest request = GetRequest(url, method);
        byte[] encodedData;
        if (data == null)
        {
            encodedData = new byte[0];
        }
        else
        {
            encodedData = encoder.GetBytes(data);
            Stream requestStream = request.GetRequestStream();
            BinaryWriter requestWriter = new BinaryWriter(requestStream);
            requestWriter.Write(encodedData);
            requestWriter.Close();
            request.ContentType = "application/json; charset=" + encoding;
        }
        auth.SetHeaders(request, encodedData);
        return request.GetResponse();
    }
    public WebResponse Get(string url)
    {
       return DoRequest(url, "GET");
    }
    public WebResponse Post(string url, string data = null)
    {
       return DoRequest(url, "POST", data);
    }
    public WebResponse Put(string url, string data = null)
    {
       return DoRequest(url, "PUT", data);
    }
    public WebResponse Delete(string url)
    {
       return DoRequest(url, "DELETE");
    }
}


namespace MAPIRSADemo
{
    class Program
    {
        public static void LogResponse(WebResponse response)
        {
            Stream dataStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(dataStream);
            string responseData = reader.ReadToEnd();
            reader.Close();
            Console.WriteLine("Response from " + response.ResponseUri);
            Console.WriteLine(responseData);
        }

        static void Main(string[] args)
        {
            RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)RSACryptoServiceProvider.Create();
            using (StreamReader pemFile = File.OpenText("su.pem"))
            {
                rsa.LoadPrivateKeyPEM(pemFile.ReadToEnd());
            }
            MerchantApiClient client = new MerchantApiClient("c8kqcf", "su", rsa);
            LogResponse(client.Get("/merchant/" + client.merchantId + "/"));
            LogResponse(client.Post("/pos/", "{\"id\": \"pos1\", \"name\":\"pøs1\", \"type\":\"store\"}"));
            LogResponse(client.Delete("/pos/pos1/"));
        }
    }
}
