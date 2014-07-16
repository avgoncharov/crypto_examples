namespace BouncyCastleExamples
{
	using System;
	using Org.BouncyCastle.X509;
	using Org.BouncyCastle.X509.Extension;
	using Org.BouncyCastle.Asn1;
	using Org.BouncyCastle.Asn1.X509;
	using System.IO;

	/// <summary>
	/// This program shows how CRL file can be processed by using BouncyCastle lib.
	/// </summary>
	class Program
	{
		/// <summary>
		/// Process CRL file.
		/// </summary>
		/// <param name="args">Arguments. arg[0] - full name of crl-file.</param>
		/// <returns>Result code: 0 - if Ok, otherwise 1.</returns>
		static int Main(string[] args)
		{
			if (args.Length != 1) {
				Console.WriteLine("Expected one argument - full name of crl file.");
				Console.WriteLine("Example: BouncyCastleExamples c:\\my.crl");
				return 0;
			}

			if (!File.Exists(args[0])) {
				Console.WriteLine("File '{0}' wasn't found.", args[0]);
				return 1;
			}

			try {
				var crlParser = new X509CrlParser();
				X509Crl crl = crlParser.ReadCrl(File.ReadAllBytes(args[0]));

				foreach (X509CrlEntry itr in crl.GetRevokedCertificates()) {
					Console.Write("SerialNumber: {0}; RevDate: {1}; ", itr.SerialNumber, itr.RevocationDate);

					Asn1OctetString revReasonCode = itr.GetExtensionValue(X509Extensions.ReasonCode);
					
					if (revReasonCode == null) {
						Console.WriteLine("ReasonCode: Undefined.");
						continue;
					}

					var code = X509ExtensionUtilities.FromExtensionValue(revReasonCode) as DerEnumerated;
					Console.WriteLine("ReasonCode: {0}", code.Value.ToString());
				}								
				return 0;
			}
			catch (Exception ex) {
				Console.WriteLine("Faild.");
				Console.WriteLine(ex.ToString());
				return 1;
			}		
		}
	}
}
