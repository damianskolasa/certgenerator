package net.fatfredyy.certgenerator.cert.generator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import net.fatfredyy.certgenerator.cert.ECCertificateCreator;
import net.fatfredyy.certgenerator.keypair.ECKeyPairGenerator;
import net.fatfredyy.certgenerator.keystore.CertKeyStoreCreator;
import net.fatfredyy.certgenerator.test.CertInfoUtil;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCertGenerator {
	
	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA384", "SHA512");

	/**
	 * @param args
	 */
	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Enumeration<String> en = ECNamedCurveTable.getNames();
		
		while(en.hasMoreElements()) {
			String curveName = en.nextElement();
			System.out.println("CurveName: " + curveName);
			KeyPair generatedKeyPair = ECKeyPairGenerator.generateECKeyPair(curveName);
			ECCertificateCreator ecCertificateCreator = new ECCertificateCreator(CertInfoUtil.getNotBeforeDate(),
					CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
			for (String digestAlg : digestAlgorithms) {
				X509Certificate certificate = ecCertificateCreator.createSelfSignedCertificate(generatedKeyPair, digestAlg+"withECDSA");
				CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, generatedKeyPair.getPrivate());
				KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());
				String ksPath = "src/test/resources/ks_ec_"+curveName+"_" + digestAlg+".p12";
				CertKeyStoreCreator.saveKeyStore(keyStore, ksPath, "132456".toCharArray());
				System.out.println("Creted ks: " + ksPath);
				
			}
		}

	}

}
