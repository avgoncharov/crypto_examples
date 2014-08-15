
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
/*
 * User: Andrey Goncharov.
 * Date: 2014-08-13. 
 */
using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace CmsByHand
{
	/// <summary>
	/// Program create CMS container by using BouncyCastle.
	/// </summary>
	class Program
	{
		static void Main(string[] args)
		{
			if (!Prepare())
				return;

			byte[] encodedData = CreateCmsByBouncyCastle();

			Verify(encodedData);

			//encodedData = CreateCmsByHand();

			//Verify(encodedData);

			
			Console.ReadKey();
		}		

		#region Utility metods.
		private static byte[] CreateCmsByHand()
		{
			var dig = new Sha1Digest();
			dig.BlockUpdate(_data, 0, _data.Length);
			
			byte[] fileHash = new byte[dig.GetDigestSize()];
			dig.DoFinal(fileHash, 0);

			var signTime = DateTime.UtcNow;
			var extSignGen = new ExternalSignerInfoGenerator(
				SignType.Pkcs7, 
				CmsSignedDataGenerator.DigestSha1,
				CmsSignedDataGenerator.EncryptionRsa,
				"BC");

			throw new NotImplementedException();

		}

		
		private static bool Verify(byte[] encodedData)
		{
			try {
				CmsSignedData cms = new CmsSignedData(new CmsProcessableByteArray(_data), encodedData);
				SignerInformationStore signers = cms.GetSignerInfos();

				foreach (SignerInformation itr in signers.GetSigners()) {
					foreach (Org.BouncyCastle.X509.X509Certificate certItr in _store.GetMatches(itr.SignerID)) {
						if (!itr.Verify(certItr))
							Console.WriteLine("Verification is failed.");
						else
							Console.WriteLine("Verified successfully.");
					}					
				}

				return true;
			}
			catch (Exception ex) {
				Console.WriteLine(ex.ToString());
				return false;
			}
		}

		private static byte[] CreateCmsByBouncyCastle()
		{
			Org.BouncyCastle.Crypto.AsymmetricKeyParameter key = DotNetUtilities.GetKeyPair(_certificate.PrivateKey).Private;

			CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
			gen.AddSigner(key, DotNetUtilities.FromX509Certificate(_certificate), CmsSignedDataGenerator.EncryptionRsa, CmsSignedDataGenerator.DigestSha1);
			gen.AddCertificates(_store);

			CmsSignedData signedData = gen.Generate("1.2.840.113549.1.7.1", new CmsProcessableByteArray(_data), true);  // <- here is the flag
			return signedData.GetEncoded();
		}

		private static Org.BouncyCastle.X509.Store.IX509Store PrepareStore()
		{
			try {
				ArrayList certList = new ArrayList();
				certList.Add(DotNetUtilities.FromX509Certificate(_certificate));

				Org.BouncyCastle.X509.Store.X509CollectionStoreParameters PP = new Org.BouncyCastle.X509.Store.X509CollectionStoreParameters(certList);

				return Org.BouncyCastle.X509.Store.X509StoreFactory.Create("CERTIFICATE/COLLECTION", PP);
			}
			catch (Exception ex) {
				Console.WriteLine(ex.ToString());
				return null;
			}
		}

		private static X509Certificate2 GetCertificate(StoreLocation storeLocation, StoreName storeName, X509FindType x509FindType, string value)
		{
			var store = new X509Store(storeName, storeLocation);
			store.Open(OpenFlags.ReadOnly);

			X509Certificate2Collection certs = store.Certificates.Find(x509FindType, value, false);

			if (certs == null || certs.Count == 0)
				return null;

			return certs[0];
		}

		private static bool Prepare()
		{			
			try {
				_data = File.ReadAllBytes("Yes_We_Scan_Deal_With_It_Wide.jpeg");
			}
			catch (Exception ex) {
				ex.ToString();
				return false;
			}

			if (_data == null || _data.Length == 0) {
				Console.WriteLine("Data is empty.");
				return false;
			}

			_certificate = GetCertificate(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindBySubjectName, "avgserv");

			if (_certificate == null) {
				Console.WriteLine("Certificate wasn't found.");
				return false;
			}

			_store = PrepareStore();

			return _store != null;
		}

		#endregion

		#region Fields.
		private static byte[] _data;
		private static X509Certificate2 _certificate;
		private static Org.BouncyCastle.X509.Store.IX509Store _store;
		#endregion 
	}
}
