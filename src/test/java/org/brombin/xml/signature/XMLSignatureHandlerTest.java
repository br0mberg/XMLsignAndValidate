package org.brombin.xml.signature;

import org.junit.jupiter.api.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
		File keystoreFile = new File(KEYSTORE_PATH);
		if (keystoreFile.exists()) {
			keystoreFile.delete();
		}
		createKeystoreWithTwoEntries(KEYSTORE_PATH, KEYSTORE_PASSWORD, ALIAS1, ALIAS2, ENTRY_PASSWORD);
	}

	@BeforeEach
	public void setUp() throws Exception {
		File xmlWithoutSignFile = new File(XML_WITHOUT_SIGN);
		File xmlWithBadSignFile = new File(XML_WITH_BAD_SIGN);
		if (xmlWithoutSignFile.exists()) {
			xmlWithoutSignFile.delete();
		}
		if (xmlWithBadSignFile.exists()) {
			xmlWithBadSignFile.delete();
		}
		createXmlFile(XML_WITHOUT_SIGN, false, false);
		createXmlFile(XML_WITH_BAD_SIGN, true, false);
	}

	@AfterEach
	public void tearDown() {
		new File(XML_WITH_BAD_SIGN).delete();
		new File(XML_WITHOUT_SIGN).delete();
	}

	@Test
	public void testValidateXmlDocumentWithInvalidSignature() throws Exception {
		boolean isInvalid = xmlSignatureHandler.validateXmlDocument(XML_WITH_BAD_SIGN, KEYSTORE_PASSWORD);
		assertFalse(isInvalid, "Validation should fail for the XML document with invalid signature.");
	}

	@Test
	@Order(1)
	public void testValidateXmlDocumentWithoutSignature() throws Exception {
		boolean isInvalid = xmlSignatureHandler.validateXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD);
		assertFalse(isInvalid, "Validation should fail for the XML document without signature.");
	}

	@Test
	@Order(2)
	public void testSignAndValidateXmlDocument() throws Exception {
		xmlSignatureHandler.signXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD, ALIAS1, ENTRY_PASSWORD);
		boolean isValid = xmlSignatureHandler.validateXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD);
		assertTrue(isValid, "Validation should pass for the XML document after signing.");
	}

	@Test
	@Order(3)
	public void testSignAndValidateXmlDocumentWithSign() throws Exception {
		xmlSignatureHandler.signXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD, ALIAS2, ENTRY_PASSWORD);
		boolean isValid = xmlSignatureHandler.validateXmlDocument(XML_WITHOUT_SIGN, KEYSTORE_PASSWORD);
		assertTrue(isValid, "Validation should pass for the XML document after signing.");
	}

	private static void createKeystoreWithTwoEntries(String keystorePath, String keystorePassword, String alias1, String alias2, String entryPassword) throws Exception {
		addKeyEntryToKeystore(keystorePath, keystorePassword, alias1, entryPassword);
		addKeyEntryToKeystore(keystorePath, keystorePassword, alias2, entryPassword);
	}

	private static void addKeyEntryToKeystore(String keystorePath, String keystorePassword, String alias, String entryPassword) throws Exception {
		ProcessBuilder pb = new ProcessBuilder(
				"keytool", "-genkeypair",
				"-alias", alias,
				"-keyalg", "RSA",
				"-keysize", "2048",
				"-keystore", keystorePath,
				"-storepass", keystorePassword,
				"-keypass", entryPassword,
				"-dname", "CN=Test, OU=Test, O=Test, L=Test, ST=Test, C=Test",
				"-validity", "365"
		);
		pb.inheritIO();
		Process process = pb.start();
		process.waitFor();
	}

	private static void createXmlFile(String filePath, boolean withSignature, boolean validSignature) throws Exception {
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(filePath))) {
			writer.println("<?xml version='1.0' encoding='UTF-8'?>");
			writer.println("<rootTag>");

			if (withSignature) {
				String signature = validSignature ? "validSignature" : "invalidSignature";
				writer.println("    <sign name=\"" + ALIAS1 + "\">" + signature + "</sign>");
			}

			writer.println("</rootTag>");
		}
	}
}
