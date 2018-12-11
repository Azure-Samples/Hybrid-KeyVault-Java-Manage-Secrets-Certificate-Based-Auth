package com.microsoft;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileInputStream;
import java.security.*;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.Executors;
import java.util.Enumeration;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import com.microsoft.aad.adal4j.AsymmetricKeyCredential;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;

public class KeyVaultCertificateAuthenticator {

	/**
	 * Do certificate based authentication using pem file
	 * 
	 * @param path        to pem file
	 * @param pemPassword the password to the pem file, this can be empty if the
	 *                    file is unencrypted
	 * @throws IOException
	 * @throws CertificateException
	 *
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws PKCSException
	 * @throws OperatorCreationException
	 */
	public static KeyVaultClient getAuthenticatedClient(String path, String pemPassword)
			throws CertificateException, OperatorCreationException, IOException, PKCSException {

		final String clientId = System.getProperty("AZURE_CLIENT_ID");
		final KeyCert certificateKey = readPem(path, pemPassword);

		final PrivateKey privateKey = certificateKey.getKey();

		// Do certificate based authentication
		KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultCredentials() {

			@Override
			public String doAuthenticate(String authorization, String resource, String scope) {

				AuthenticationContext context;
				try {
					context = new AuthenticationContext(authorization, false, Executors.newFixedThreadPool(1));
					AsymmetricKeyCredential asymmetricKeyCredential = AsymmetricKeyCredential.create(clientId,
							privateKey, certificateKey.getCertificate());
					// pass null value for optional callback function and acquire access token
					AuthenticationResult result = context.acquireToken(resource, asymmetricKeyCredential, null).get();

					return result.getAccessToken();
				} catch (Exception e) {
					e.printStackTrace();
				}
				return "";
			}
		});
		return keyVaultClient;
	}

	/**
	 * Do certificate based authentication using pfx file
	 * 
	 * @param path        to pfx file
	 * @param pfxPassword the password to the pfx file, this can be empty if thats
	 *                    the value given when it was created
	 * @param clientId    also known as applicationId which is received after app
	 *                    registration
	 */
	public static KeyVaultClient getAuthentication(String path, String pfxPassword, String clientId)
			throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
			NoSuchProviderException, IOException {

		KeyCert certificateKey = readPfx(path, pfxPassword);

		PrivateKey privateKey = certificateKey.getKey();

		// Do certificate based authentication
		KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultCredentials() {

			@Override
			public String doAuthenticate(String authorization, String resource, String scope) {

				AuthenticationContext context;
				try {
					context = new AuthenticationContext(authorization, false, Executors.newFixedThreadPool(1));
					AsymmetricKeyCredential asymmetricKeyCredential = AsymmetricKeyCredential.create(clientId,
							privateKey, certificateKey.getCertificate());
					// pass null value for optional callback function and acquire access token
					AuthenticationResult result = context.acquireToken(resource, asymmetricKeyCredential, null).get();

					return result.getAccessToken();
				} catch (Exception e) {
					e.printStackTrace();
				}
				return "";
			}
		});
		return keyVaultClient;
	}

	private static KeyCert readPem(String path, String password)
			throws IOException, CertificateException, OperatorCreationException, PKCSException {

		Security.addProvider(new BouncyCastleProvider());
		PEMParser pemParser = new PEMParser(new FileReader(new File(path)));
		PrivateKey privateKey = null;
		X509Certificate cert = null;
		Object object = pemParser.readObject();

		while (object != null) {
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			if (object instanceof X509CertificateHolder) {
				cert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) object);
			}
			if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
				PKCS8EncryptedPrivateKeyInfo pinfo = (PKCS8EncryptedPrivateKeyInfo) object;
				InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
						.build(password.toCharArray());
				PrivateKeyInfo info = pinfo.decryptPrivateKeyInfo(provider);
				privateKey = converter.getPrivateKey(info);
			}
			if (object instanceof PrivateKeyInfo) {
				privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
			}
			object = pemParser.readObject();
		}

		KeyCert keycert = new KeyCert(null, null);
		keycert.setCertificate(cert);
		keycert.setKey(privateKey);
		pemParser.close();
		return keycert;
	}

	/**
	 * Read pfx file and get privateKey
	 * 
	 * @param path     pfx file path
	 * @param password the password to the pfx file
	 */
	public static KeyCert readPfx(String path, String password) throws NoSuchProviderException, KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {

		try (FileInputStream stream = new FileInputStream(path)) {
			KeyCert keyCert = new KeyCert(null, null);

			boolean isAliasWithPrivateKey = false;

			// Access Java keystore
			final KeyStore store = KeyStore.getInstance("pkcs12", "SunJSSE");

			// Load Java Keystore with password for access
			store.load((InputStream) stream, password.toCharArray());

			// Iterate over all aliases to find the private key
			Enumeration<String> aliases = store.aliases();
			String alias = "";
			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				System.out.println(alias);
				// Break if alias refers to a private key because we want to use that
				// certificate
				if (isAliasWithPrivateKey = store.isKeyEntry(alias)) {
					break;
				}
			}

			if (isAliasWithPrivateKey) {
				// Retrieves the certificate from the Java keystore
				X509Certificate certificate = (X509Certificate) store.getCertificate(alias);
				System.out.println("the alias is: " + alias);

				// Retrieves the private key from the Java keystore
				PrivateKey key = (PrivateKey) store.getKey(alias, password.toCharArray());

				keyCert.setCertificate(certificate);
				keyCert.setKey(key);

				System.out.println("key in primary encoding format is: " + key.getEncoded());
			}
			return keyCert;
		}
	}

}

class KeyCert {

	X509Certificate certificate;
	PrivateKey key;

	public KeyCert(X509Certificate certificate, PrivateKey key) {
		this.certificate = certificate;
		this.key = key;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public PrivateKey getKey() {
		return key;
	}

	public void setKey(PrivateKey key) {
		this.key = key;
	}
}