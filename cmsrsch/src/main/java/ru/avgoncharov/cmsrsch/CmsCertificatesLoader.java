package ru.avgoncharov.cmsrsch;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Created by a.v.goncharov on 27.07.2015.
 */
public class CmsCertificatesLoader {
	public X509Certificate[] getCertificateFromCms(String path) throws Throwable{
		CMSSignedData cms = new CMSSignedData(Base64.decode(Files.readAllBytes(Paths.get(path))));

		Store store = cms.getCertificates();
		SignerInformationStore signers = cms.getSignerInfos();

		List<X509Certificate> result = new ArrayList<X509Certificate>();

		for(Object itr : signers.getSigners()){
			if(!(itr instanceof SignerInformation))
				continue;

			SignerInformation si = (SignerInformation)itr;

			Collection crtHs = store.getMatches(si.getSID());
			for (Object crtHItr: crtHs){
				if(!(crtHItr instanceof  X509CertificateHolder))
					continue;

				X509Certificate cert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder)crtHItr);
				result.add(cert);
			}
		}

		X509Certificate[] buf = new X509Certificate[result.size()];
		result.toArray(buf);
		return buf;
	}
}
