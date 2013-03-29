package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public abstract class CertificateCreator {
	Date notBefore;
	Date notAfter;
	X500Name subject = new X500Name("CN=Test CA Certificate");
	BigInteger serialNumber;
	ContentSigner contentSigner;

	public CertificateCreator(Date notBefore, Date notAfter, String subject, BigInteger serialNumber) {
		super();
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.subject = new X500Name(subject);
		this.serialNumber = serialNumber;
	}

	public abstract X509Certificate createSelfSignedCertificate(KeyPair keyPair, String contentSignAlg) throws Exception;
	
	
	public void registerContentSigner(String contentSignAlg, PrivateKey privateKey) throws Exception {
		contentSigner = new JcaContentSignerBuilder(contentSignAlg).build(privateKey);
	}

}
