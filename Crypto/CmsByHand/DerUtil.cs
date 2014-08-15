using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CmsByHand
{
	static class DerUtil
	{
		public static byte[] GetHash(byte[] content, string digestAlgOID, string securityProvider)
		{
			Org.BouncyCastle.Crypto.IDigest md = null;

			if (CmsSignedDataGenerator.DigestSha1 == digestAlgOID)
				md = new Sha1Digest();
			else if (CmsSignedDataGenerator.DigestGost3411 == digestAlgOID)
				md = new Gost3411Digest();
			
			md.BlockUpdate(content, 0, content.Length);

			var hash = new byte[md.GetByteLength()];
			md.DoFinal(hash, 0);
			return hash;
		}
	}
}
