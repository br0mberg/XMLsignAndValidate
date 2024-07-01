package org.brombin.xml.signature;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.*;
import org.springframework.boot.test.context.SpringBootTest;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class XMLSignatureHandlerTest {
	private static final String XML_WITH_BAD_SIGN = "src/test/resources/xmlWithBadSign.xml";
	private static final String XML_WITHOUT_SIGN = "src/test/resources/xmlWithoutSign.xml";
	private static final String KEYSTORE_PATH = "keystore.jks";
	private static final String KEYSTORE_PASSWORD = "password";
	private static final String ALIAS1 = "testalias1";
	private static final String ALIAS2 = "testalias2";
	private static final String ENTRY_PASSWORD = "password";

	private static XMLSignatureHandler xmlSignatureHandler;

	@BeforeAll
	public static void setup() throws Exception {
		xmlSignatureHandler = new XMLSignatureHandler();
		Security.addProvider(new BouncyCastleProvider());
		createKeystoreWithTwoEntries(KEYSTORE_PATH, KEYSTORE_PASSWORD, ALIAS1, ALIAS2, ENTRY_PASSWORD);
	}

	@BeforeEach
	public void setUp() throws Exception {
		// Создание файлов XML для тестов
		createXmlFile(XML_WITHOUT_SIGN, false, false);
		createXmlFile(XML_WITH_BAD_SIGN, true, false);
	}

	@AfterEach
	public void tearDown() {
		// Удаление файлов XML после выполнения тестов
		new File(XML_WITH_BAD_SIGN).delete();
		new File(XML_WITHOUT_SIGN).delete();
	}

	@Test
	public void testValidateXmlDocumentWithInvalidSignature() throws Exception {
		XMLSignatureHandler xmlSignatureHandler = new XMLSignatureHandler();
		// Проверяем XML с неверной подписью
		boolean isInvalid = xmlSignatureHandler.validateXmlDocument(XML_WITH_BAD_SIGN, KEYSTORE_PASSWORD);
		assertFalse(isInvalid, "Validation should fail for the XML document with invalid signature.");
	}

	@Test
	@Order(1)
	public void testValidateXmlDocumentWithoutSignature() throws Exception {
		XMLSignatureHandler xmlSignatureHandler = new XMLSignatureHandler();
		// Проверяем ещё не подписанный документ
		boolean isInvalid = xmlSignatureHandler.validateXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD);
		assertFalse(isInvalid, "Validation should fail for the XML document without signature.");
	}

	@Test
	@Order(2)
	public void testSignAndValidateXmlDocument() throws Exception {
		// Подписываем XML
		xmlSignatureHandler.signXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD, ALIAS1, ENTRY_PASSWORD);

		// Проверяем, что XML теперь подписан
		boolean isValid = xmlSignatureHandler.validateXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD);
		assertTrue(isValid, "Validation should pass for the XML document after signing.");
	}

	@Test
	@Order(3)
	public void testSignAndValidateXmlDocumentWithSign() throws Exception {
		// Подписываем XML
		xmlSignatureHandler.signXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD, ALIAS1, ENTRY_PASSWORD);

		// Проверяем, что XML теперь подписан
		boolean isValid = xmlSignatureHandler.validateXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD);
		assertTrue(isValid, "Validation should pass for the XML document after signing.");
	}

	private static void createKeystoreWithTwoEntries(String keystorePath, String keystorePassword, String alias1, String alias2, String entryPassword) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null); // Initialize a new keystore

		addKeyEntryToKeystore(keyStore, alias1, entryPassword);
		addKeyEntryToKeystore(keyStore, alias2, entryPassword);

		try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
			keyStore.store(fos, keystorePassword.toCharArray());
		}
	}

	private static void addKeyEntryToKeystore(KeyStore keyStore, String alias, String entryPassword) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();

		X509Certificate cert = generateSelfSignedCertificate(keyPair);

		keyStore.setKeyEntry(alias, keyPair.getPrivate(),
				entryPassword.toCharArray(), new Certificate[]{cert});
	}

	private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
		long now = System.currentTimeMillis();
		Date startDate = new Date(now);
		X500Principal dnName = new X500Principal("CN=Test, OU=Test, O=Test, L=Test, ST=Test, C=Test");
		BigInteger certSerialNumber = BigInteger.valueOf(now);
		Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000);

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());

		JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
				dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(contentSigner));
	}

	private static void createXmlFile(String filePath, boolean withSignature, boolean validSignature) throws Exception {
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(filePath))) {
			writer.println("<?xml version='1.0' encoding='UTF-8'?>");
			writer.println("<rootTag>");

			if (withSignature) {
				// Генерация некорректной подписи
				String signature = validSignature ? "validSignature" : "invalidSignature";
				writer.println("    <sign name=\"" + ALIAS1 + "\">" + signature + "</sign>");
			}

			writer.println("</rootTag>");
		}
	}
}
