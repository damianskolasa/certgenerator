package net.fatfredyy.certgenerator.keystore;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CertKeyStoreCreator {
	
	private X509Certificate certificate;
	private PrivateKey privateKey;
	
	
	public KeyStore creteKeyStore(String privateKeyEntryAlias, String certificateAlias, char[] privateKeyPassword) throws Exception {
		
		KeyStore.PrivateKeyEntry privateKE = new KeyStore.PrivateKeyEntry(privateKey, (Certificate[]) Arrays.asList(certificate).toArray());
		KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
		ks.load(null);
		
		ks.setCertificateEntry(certificateAlias, certificate);
		ks.setEntry(privateKeyEntryAlias, privateKE, new KeyStore.PasswordProtection(privateKeyPassword));
		
		return ks;
	}
	
	public static void saveKeyStore(KeyStore keyStore, String filePath, char[] password) throws Exception {
		FileOutputStream fos = new FileOutputStream(filePath);
		keyStore.store(fos, password);
		fos.flush();
		fos.close();
	}

}
