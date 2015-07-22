package ru.avgoncharov.pkcs10;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import ru.CryptoPro.JCP.JCP;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * Created by a.v.goncharov on 22.07.2015.
 * Simple implementation ContentSigner interface for GOST algorithm.
 */
public class GostCryptoSigner  implements org.bouncycastle.operator.ContentSigner{
	//region Ctor.
	public GostCryptoSigner(PrivateKey pk) throws
			java.security.NoSuchAlgorithmException,
			java.security.InvalidKeyException
	{
		signature = Signature.getInstance(JCP.GOST_DHEL_SIGN_NAME);
		signature.initSign(pk);
		buffer = new ByteArrayOutputStream();
	}
	//endregion

	//region Public.
	@Override
	public AlgorithmIdentifier getAlgorithmIdentifier()
	{
		return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.643.2.2.3"));
	}

	@Override
	public OutputStream getOutputStream()
	{
		return buffer;
	}

	@Override
	public byte[] getSignature()
	{
		try
		{
			byte[] data = buffer.toByteArray();
			signature.update(data);

			return signature.sign();
		}
		catch (java.security.SignatureException ex)
		{
			return null;
		}
	}
	//endregion

	//region Fields.
	private Signature signature;
	private ByteArrayOutputStream buffer;
	//endregion

}
