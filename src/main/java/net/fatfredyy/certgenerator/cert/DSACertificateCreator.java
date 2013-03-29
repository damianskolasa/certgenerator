package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.util.Date;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class DSACertificateCreator extends CertificateCreator {
	
	public DSACertificateCreator(Date notBefore, Date notAfter, String subject, BigInteger serialNumber) {
		super(notBefore, notAfter, subject, serialNumber);
	}

	@Override
	public X509Certificate createSelfSignedCertificate(KeyPair keyPair, String contentSignAlg) throws Exception {

		registerContentSigner(contentSignAlg, keyPair.getPrivate());
		
		DSAPublicKey dsaPublicKey = (DSAPublicKey) keyPair.getPublic();
		DSAParams dsaParams = dsaPublicKey.getParams();
		DSAParameters dsaParameters = new DSAParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
		
		DSAPublicKeyParameters dsaPublicKeyParameters = new DSAPublicKeyParameters(dsaPublicKey.getY(), dsaParameters); 
		
		SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(dsaPublicKeyParameters);

		X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject,
				pubKeyInfo);

		X509CertificateHolder certHolder = v1CertGen.build(contentSigner);
		X509Certificate generatedCertificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

		serialNumber = serialNumber.add(BigInteger.ONE);
		return generatedCertificate;

	}

}
