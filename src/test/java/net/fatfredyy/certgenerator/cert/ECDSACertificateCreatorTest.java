package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import net.fatfredyy.certgenerator.keypair.ECDSAKeyPairGenerator;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fest.assertions.Assertions;
import org.junit.BeforeClass;
import org.junit.Test;

public class ECDSACertificateCreatorTest {
	
	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void shoudCreateNotNullCertificate() throws Exception {
		// given
		ECDSACertificateCreator ecdsaCertificateCreator = new ECDSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair ecKeyPair = ECDSAKeyPairGenerator.generateECDSAKeyPair("prime192v1");
		
		//when
		X509Certificate certificate = ecdsaCertificateCreator.createSelfSignedCertificate(ecKeyPair, "SHA1withECDSA");
		
		// then
		Assertions.assertThat(certificate).isNotNull();
	}
	
	@Test
	public void shoudCreateCertificateWithGivenPublicKey() throws Exception {
		// given
		ECDSACertificateCreator ecdsaCertificateCreator = new ECDSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair ecKeyPair = ECDSAKeyPairGenerator.generateECDSAKeyPair("prime192v1");
		
		//when
		X509Certificate certificate = ecdsaCertificateCreator.createSelfSignedCertificate(ecKeyPair, "SHA1withECDSA");
		ECPublicKey pairECPublicKey = (ECPublicKey) ecKeyPair.getPublic();
		ECPublicKey certECPublicKey = (ECPublicKey) certificate.getPublicKey();
		
		// then
		Assertions.assertThat(certECPublicKey.getQ().getX().toBigInteger()).isEqualTo(pairECPublicKey.getQ().getX().toBigInteger());
		Assertions.assertThat(certECPublicKey.getQ().getY().toBigInteger()).isEqualTo(pairECPublicKey.getQ().getY().toBigInteger());
	}

}
