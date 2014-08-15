using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CmsByHand
{
	private sealed class ExternalSignerInfoGenerator
	{
		#region Ctor.
		public ExternalSignerInfoGenerator(SignType signType, string digestAlgOID, string encryptionAlgOID, string securityProvider)
		{
			_signType = signType;
			_digestAlgOID = digestAlgOID;
			_encryptionAlgOID = encryptionAlgOID;
			_securityProvider = securityProvider;
			_unsignedAttrTable = new Org.BouncyCastle.Asn1.Cms.AttributeTable((new Hashtable()) as IDictionary);
			_signedAttrTable = new Org.BouncyCastle.Asn1.Cms.AttributeTable((new Hashtable()) as IDictionary);
		}
		#endregion

		#region Public.
		public byte[] GetCMSBytesToSign(
			byte[] hash,
			DateTime signingTime,
			DerObjectIdentifier contentType,
			X509Certificate x509Cert,
			TimeStampToken timeStampToken)
		{
			Asn1EncodableVector signedAttrVector = BuildSignedAttributes(hash, signingTime, contentType, x509Cert);

			throw new NotImplementedException();
		}

		#endregion

		#region Private.
		protected Asn1EncodableVector BuildSignedAttributes(
			byte[] hash,
			DateTime signingTime,
			DerObjectIdentifier contentType,
			X509Certificate x509Cert)
		{
			Asn1EncodableVector signedAttrVector = new Asn1EncodableVector();

			IDictionary attrMap = _signedAttrTable.ToDictionary();

			if (contentType != null) {
				if (attrMap.Contains(CmsAttributes.ContentType)) {
					signedAttrVector.Add(attrMap[CmsAttributes.ContentType] as Org.BouncyCastle.Asn1.Cms.Attribute);
					attrMap.Remove(CmsAttributes.ContentType);
				}
				else {
					signedAttrVector.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.ContentType, new DerSet(contentType)));
				}
			}

			if (attrMap.Contains(CmsAttributes.SigningTime)) {
				signedAttrVector.Add(attrMap[CmsAttributes.SigningTime] as Org.BouncyCastle.Asn1.Cms.Attribute);
				attrMap.Remove(CmsAttributes.SigningTime);
			}
			else {
				signedAttrVector.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.SigningTime, new DerSet(new Time(signingTime))));
			}
			if (attrMap.Contains(CmsAttributes.MessageDigest)) {
				signedAttrVector.Add(attrMap[CmsAttributes.MessageDigest] as Org.BouncyCastle.Asn1.Cms.Attribute);
				attrMap.Remove(CmsAttributes.MessageDigest);
			}
			else {
				signedAttrVector.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(hash))));
			}

			// check if add id_aa_signingCertificateV2 attribute
			if (_signType != SignType.Pkcs7 && _signType != SignType.PDF && _signType != SignType.XMLDSIG) {
				if (attrMap.Contains(PkcsObjectIdentifiers.IdAASigningCertificateV2)) {
					signedAttrVector.Add(attrMap[PkcsObjectIdentifiers.IdAASigningCertificateV2] as Org.BouncyCastle.Asn1.Cms.Attribute);
					attrMap.Remove(PkcsObjectIdentifiers.IdAASigningCertificateV2);
				}
				else {
					if (x509Cert != null) {
						signedAttrVector.Add(BuildSigningCertificateV2Attribute(x509Cert));
					}
				}
			}

			// add other attributes			
			foreach (var itr in attrMap)
				signedAttrVector.Add(Org.BouncyCastle.Asn1.Cms.Attribute.GetInstance(itr));

			_signedAttr = new DerSet(signedAttrVector);

			return signedAttrVector;
		}

		protected Org.BouncyCastle.Asn1.Cms.Attribute BuildSigningCertificateV2Attribute(X509Certificate x509Cert)
		{
			byte[] certHash = DerUtil.GetHash(x509Cert.GetRawCertData(), _digestAlgOID, _securityProvider);

			Org.BouncyCastle.X509.X509Certificate holder = DotNetUtilities.FromX509Certificate(x509Cert);
			Org.BouncyCastle.Asn1.X509.X509Name x509name = holder.IssuerDN;

			var generalName = new Org.BouncyCastle.Asn1.X509.GeneralName(x509name);
			var generalNames = new Org.BouncyCastle.Asn1.X509.GeneralNames(generalName);

			var issuerSerial = new Org.BouncyCastle.Asn1.X509.IssuerSerial(generalNames, new DerInteger(holder.SerialNumber));
			var essCert = new Org.BouncyCastle.Asn1.Ess.EssCertIDv2(new AlgorithmIdentifier(_digestAlgOID), certHash, issuerSerial);
			var scv2 = new Org.BouncyCastle.Asn1.Ess.SigningCertificateV2(new Org.BouncyCastle.Asn1.Ess.EssCertIDv2[] { essCert });

			return new Org.BouncyCastle.Asn1.Cms.Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(scv2));
		}
		#endregion

		#region Fields.
		private Org.BouncyCastle.Asn1.Cms.AttributeTable _unsignedAttrTable = null;
		private Org.BouncyCastle.Asn1.Cms.AttributeTable _signedAttrTable = null;
		private Org.BouncyCastle.Asn1.Asn1Set _unsignedAttr = null;
		private Org.BouncyCastle.Asn1.Asn1Set _signedAttr = null;
		private string _encryptionAlgOID;
		private string _digestAlgOID;
		private string _securityProvider;
		private SignType _signType;
		#endregion
	}
}
