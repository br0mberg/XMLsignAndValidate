package org.brombin.xml.signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;

@Component
public class XMLSignatureHandler {
    private static final Logger logger = LoggerFactory.getLogger(XMLSignatureHandler.class);
    private String keystorePath = "keystore.jks";
    private String keystoreType = "JKS";

    public void signXmlDocument(String xmlFilePath, String keystorePassword,
                                String alias, String entryPassword) throws Exception {
        logger.info("Starting XML document signing process.");
        Document xmlDocument = getXmlDocument(xmlFilePath);

        KeyStore keyStore = loadKeyStore(keystorePassword);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, entryPassword.toCharArray());
        Certificate certificate = keyStore.getCertificate(alias);

        String normalizedContent = getNormalizedXml(xmlDocument);
        String signatureBase64 = generateSignature(normalizedContent, privateKey);

        addSignatureToDocument(xmlDocument, alias, signatureBase64);
        saveXmlDocument(xmlDocument, xmlFilePath);

        logger.info("XML document signed successfully.");
    }

    private KeyStore loadKeyStore(String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }

        return keyStore;
    }

    private String getNormalizedXml(Document xmlDocument) throws TransformerException, ParserConfigurationException {
        Document newDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        Element root = newDoc.createElement(xmlDocument.getDocumentElement().getTagName());
        newDoc.appendChild(root);

        NodeList childNodes = xmlDocument.getDocumentElement().getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node node = childNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && !"sign".equals(node.getNodeName())) {
                root.appendChild(newDoc.importNode(node, true));
            }
        }

        sortChildElements(root);

        return convertDocumentToString(newDoc);
    }

    private String convertDocumentToString(Document xmlDocument) throws TransformerException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");

        DOMSource source = new DOMSource(xmlDocument);
        StreamResult result = new StreamResult(new StringWriter());

        transformer.transform(source, result);
        String xmlString = result.getWriter().toString();

        if (xmlString == null || xmlString.isEmpty()) {
            throw new TransformerException("Error converting XML to string");
        }

        return xmlString.replaceAll("\\s+", "");
    }

    private String generateSignature(String content, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private void addSignatureToDocument(Document xmlDocument, String alias, String signatureBase64) {
        Element elementSign = xmlDocument.createElement("sign");
        elementSign.setAttribute("name", alias);
        elementSign.setTextContent(signatureBase64);
        xmlDocument.getDocumentElement().appendChild(elementSign);
    }

    private void saveXmlDocument(Document xmlDocument, String xmlFilePath) throws TransformerException {
        DOMSource domSource = new DOMSource(xmlDocument);
        StreamResult streamResult = new StreamResult(new File(xmlFilePath));

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.transform(domSource, streamResult);
    }

    private static void sortChildElements(Element element) {
        NodeList nodeList = element.getChildNodes();
        List<Element> elements = new ArrayList<>();

        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                elements.add((Element) node);
            }
        }

        elements.sort(Comparator.comparing(Element::getTagName));

        for (Element child : elements) {
            element.removeChild(child);
        }

        for (Element child : elements) {
            element.appendChild(child);
            sortChildElements(child);
        }
    }

    private static Document getXmlDocument(String xmlFilePath)
            throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(true);
        builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return builderFactory.newDocumentBuilder().parse(xmlFilePath);
    }

    public boolean validateXmlDocument(String xmlFilePath, String keystorePassword) throws Exception {
        logger.info("Starting XML document validation process.");
        Document xmlDocument = getXmlDocument(xmlFilePath);

        NodeList signNodesList = xmlDocument.getDocumentElement().getElementsByTagName("sign");
        if (signNodesList.getLength() == 0) {
            logger.warn("No <sign> nodes found in the XML file.");
            return false;
        }

        List<Node> signNodes = extractAndRemoveSignNodes(xmlDocument, signNodesList);

        KeyStore keystore = loadKeyStore(keystorePassword);

        boolean allSignaturesValid = validateSignatures(xmlDocument, signNodes, keystore);

        if (allSignaturesValid) {
            logger.info("XML document validation completed successfully.");
        } else {
            logger.error("XML document validation failed.");
        }
        return allSignaturesValid;
    }

    private List<Node> extractAndRemoveSignNodes(Document xmlDocument, NodeList signNodesList) {
        List<Node> signNodes = new ArrayList<>();
        for (int i = 0; i < signNodesList.getLength(); ++i) {
            signNodes.add(signNodesList.item(i));
        }
        for (Node signNode : signNodes) {
            signNode.getParentNode().removeChild(signNode);
        }
        return signNodes;
    }

    private boolean validateSignatures(Document xmlDocument, List<Node> signNodes, KeyStore keystore) throws Exception {
        boolean allSignaturesValid = true;
        for (Node signNode : signNodes) {
            String signatureBase64 = signNode.getTextContent();
            String alias = ((Element) signNode).getAttribute("name");

            Certificate cert = keystore.getCertificate(alias);
            if (cert == null) {
                logger.error("No certificate found for alias: {}", alias);
                allSignaturesValid = false;
                continue;
            }

            if (!verifySignature(xmlDocument, signatureBase64, cert.getPublicKey())) {
                logger.error("Signature verification failed for alias: {}", alias);
                allSignaturesValid = false;
            }
        }
        return allSignaturesValid;
    }

    private boolean verifySignature(Document xmlDocument, String signatureBase64, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);

        String documentContent = getNormalizedXml(xmlDocument);
        signature.update(documentContent.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

        if (signatureBytes.length != 256) {
            logger.error("Invalid signature length: got {} but was expecting 256", signatureBytes.length);
            return false;
        }

        return signature.verify(signatureBytes);
    }
}
