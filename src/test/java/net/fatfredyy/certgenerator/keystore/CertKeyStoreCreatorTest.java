package net.fatfredyy.certgenerator.keystore;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;

import net.fatfredyy.certgenerator.cert.DSACertificateCreator;
import net.fatfredyy.certgenerator.cert.ECCertificateCreator;
import net.fatfredyy.certgenerator.cert.ECDSACertificateCreator;
import net.fatfredyy.certgenerator.cert.RSACertificateCreator;
import net.fatfredyy.certgenerator.keypair.DSAKeyPairGenerator;
import net.fatfredyy.certgenerator.keypair.ECDSAKeyPairGenerator;
import net.fatfredyy.certgenerator.keypair.ECKeyPairGenerator;
import net.fatfredyy.certgenerator.keypair.RSAKeyPairGenerator;
import net.fatfredyy.certgenerator.test.CertInfoUtil;
import net.fatfredyy.certgenerator.test.SignatureUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fest.assertions.Assertions;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

public class CertKeyStoreCreatorTest {

	private static final String EC_KS_PATH = "target/ec_keystore.pkcs12";
	private static final String DSA_KS_PATH = "target/dsa_keystore.pkcs12";
	private static final String RSA_KS_PATH = "target/rsa_keystore.pkcs12";

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	@Ignore
	public void shoudCreateNotNullECDSAKeyStore() throws Exception {
		// given
		ECDSACertificateCreator ecdsaCertificateCreator = new ECDSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair ecKeyPair = ECDSAKeyPairGenerator.generateECDSAKeyPair("prime192v1");
		X509Certificate certificate = ecdsaCertificateCreator.createSelfSignedCertificate(ecKeyPair, "SHA1withECDSA");

		// when
		CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, ecKeyPair.getPrivate());
		KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());

		// then
		Assertions.assertThat(keyStore).isNotNull();
	}

	@Test
	public void shoudCreateNotNullECKeyStore() throws Exception {
		// given
		ECCertificateCreator ecCertificateCreator = new ECCertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = ECKeyPairGenerator.generateECKeyPair("prime192v1");

		// when
		X509Certificate certificate = ecCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withECDSA");
		CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, keyPair.getPrivate());
		KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());

		// then
		Assertions.assertThat(keyStore).isNotNull();
	}

	@Test
	public void shoudCreateNotNullDSAKeyStore() throws Exception {
		// given
		DSACertificateCreator dsaCertificateCreator = new DSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// when
		X509Certificate certificate = dsaCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withDSA");
		CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, keyPair.getPrivate());
		KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());

		// then
		Assertions.assertThat(keyStore).isNotNull();
	}

	@Test
	public void shoudCreateNotNullRSAKeyStore() throws Exception {
		// given
		RSACertificateCreator rsaCertificateCreator = new RSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);

		// when
		X509Certificate certificate = rsaCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withRSA");
		CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, keyPair.getPrivate());
		KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());

		// then
		Assertions.assertThat(keyStore).isNotNull();
	}

	@Test
	public void shouldStoreAndLoadValidECCertAndPrivateKey() throws Exception {
		// given
		ECCertificateCreator ecCertificateCreator = new ECCertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = ECKeyPairGenerator.generateECKeyPair("prime192v1");
		X509Certificate certificate = ecCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withECDSA");
		CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, keyPair.getPrivate());
		KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());

		// when
		CertKeyStoreCreator.saveKeyStore(keyStore, EC_KS_PATH, "123456".toCharArray());
		KeyStore loadedKeyStore = CertKeyStoreCreator.loadKeyStore(EC_KS_PATH, "123456".toCharArray());
		PrivateKey loadedPrivateKey = (PrivateKey) loadedKeyStore.getKey("privateKey", "132456".toCharArray());
		PublicKey loadedPublicKey = loadedKeyStore.getCertificate("certificate").getPublicKey();

		// then
		Assertions.assertThat(SignatureUtil.testSignAndVerify(loadedPrivateKey, loadedPublicKey, "SHA1withECDSA")).isTrue();
		Assertions.assertThat(SignatureUtil.testSignAndVerify(keyPair.getPrivate(), loadedPublicKey, "SHA1withECDSA")).isTrue();
		Assertions.assertThat(SignatureUtil.testSignAndVerify(loadedPrivateKey, keyPair.getPublic(), "SHA1withECDSA")).isTrue();
	}

	@Test
	public void shouldStoreAndLoadValidRSACertAndPrivateKey() throws Exception {
		// given
		RSACertificateCreator rsaCertificateCreator = new RSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		X509Certificate certificate = rsaCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withRSA");
		CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, keyPair.getPrivate());
		KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());

		// when
		CertKeyStoreCreator.saveKeyStore(keyStore, RSA_KS_PATH, "123456".toCharArray());
		KeyStore loadedKeyStore = CertKeyStoreCreator.loadKeyStore(RSA_KS_PATH, "123456".toCharArray());
		PrivateKey loadedPrivateKey = (PrivateKey) loadedKeyStore.getKey("privateKey", "132456".toCharArray());
		PublicKey loadedPublicKey = loadedKeyStore.getCertificate("certificate").getPublicKey();

		// then
		Assertions.assertThat(SignatureUtil.testSignAndVerify(loadedPrivateKey, keyPair.getPublic(), "SHA1withRSA")).isTrue();
		Assertions.assertThat(SignatureUtil.testSignAndVerify(loadedPrivateKey, loadedPublicKey, "SHA1withRSA")).isTrue();
		Assertions.assertThat(SignatureUtil.testSignAndVerify(keyPair.getPrivate(), loadedPublicKey, "SHA1withRSA")).isTrue();
	}

	@Test
	public void shouldStoreAndLoadValidDSACertAndPrivateKey() throws Exception {
		// given
		DSACertificateCreator dsaCertificateCreator = new DSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);
		X509Certificate certificate = dsaCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withDSA");
		CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, keyPair.getPrivate());
		KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());

		// when
		CertKeyStoreCreator.saveKeyStore(keyStore, DSA_KS_PATH, "123456".toCharArray());
		KeyStore loadedKeyStore = CertKeyStoreCreator.loadKeyStore(DSA_KS_PATH, "123456".toCharArray());
		PrivateKey loadedPrivateKey = (PrivateKey) loadedKeyStore.getKey("privateKey", "132456".toCharArray());
		PublicKey loadedPublicKey = loadedKeyStore.getCertificate("certificate").getPublicKey();
		
		// then
		Assertions.assertThat(SignatureUtil.testSignAndVerify(keyPair.getPrivate(), loadedPublicKey, "SHA1withDSA")).isTrue();
		Assertions.assertThat(SignatureUtil.testSignAndVerify(loadedPrivateKey, keyPair.getPublic(), "SHA1withDSA")).isTrue();
		Assertions.assertThat(SignatureUtil.testSignAndVerify(loadedPrivateKey, loadedPublicKey, "SHA1withDSA")).isTrue();
	}

}
