package ru.avgoncharov.cmsrsch;

import java.security.cert.X509Certificate;

/**
 * Created by a.v.goncharov on 22.07.2015.
 * This program gets set of certificates, which were used to signature, from cms.
 */
public class Program {
	public static void main(String[] args){

		CmsCertificatesLoader ccl = new CmsCertificatesLoader();
		try {
			X509Certificate[] result = ccl.getCertificateFromCms("path to cms in base64");
		}
		catch (Throwable th){
			th.printStackTrace();
		}
	}
}
