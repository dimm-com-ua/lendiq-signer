package app.lendiq.signer;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.io.*;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

public class LendiqSigner {
    public static void main(String[] args)  {
        if(args.length < 3) {
            System.out.println("Usage: java jar lendiq-signer.jar --key <PFX_FILE> --password <PASSWORD> --cert <CERT> --file <FILE_PATH> --trusted_dir <TRUSTED_DIR>");
            System.exit(1);
        }
        System.setProperty("org.apache.logging.log4j.level", "DEBUG");
        System.setProperty("org.apache.logging.log4j.simplelog.level", "DEBUG");

        String pfxPath = null;
        String password = null;
        String inputFilePath = null;
        String certPath = null;
        String outFilePath = null;
        String trustedDir = null;

        for(int i = 0; i < args.length; i++) {
            if(args[i].equals("--key")) {
                pfxPath = args[++i];
            } else if(args[i].equals("--password")) {
                password = args[++i];
            } else if(args[i].equals("--file")) {
                inputFilePath = args[++i];
                outFilePath = inputFilePath + ".asice";
            } else if(args[i].equals("--cert")) {
                certPath = args[++i];
            } else if(args[i].equals("--trusted_dir")) {
                trustedDir = args[++i];
            }
        }

        if(pfxPath == null || password == null || inputFilePath == null || outFilePath == null) {
            System.out.println("Can't start. Missing required parameters");
        }

        File pfxFile = new File(pfxPath);
        if (!pfxFile.exists() || !pfxFile.isFile()) {
            System.out.println("PFX file not found: " + pfxPath);
            System.exit(1);
        } else {
            System.out.println("PFX file loaded: " + pfxPath + "");
        }

        File certFile = null;
        if(certPath != null) {
            certFile = new File(certPath);
            if (!certFile.exists() || !certFile.isFile()) {
                System.out.println("Certificate file not found: " + certPath);
                System.exit(1);
            } else {
                System.out.println("Certificate file loaded: " + certPath + "");
            }
        }

        File inputFile = new File(inputFilePath);
        if (!inputFile.exists() || !inputFile.isFile()) {
            System.out.println("Input file not found: " + inputFilePath);
            System.exit(1);
        } else {
            System.out.println("Input file loaded: " + inputFilePath + "");
        }

        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(pfxPath, new KeyStore.PasswordProtection(password.toCharArray()))) {
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                System.out.println("No private keys found.");
                return;
            } else {
                System.out.println("Found " + keys.size() + " private keys.");
            }
            DSSPrivateKeyEntry privateKeyDss = keys.get(0);
            System.out.println("privateKeyDss loaded with algorithm " + privateKeyDss.getEncryptionAlgorithm());

            DSSDocument documentToSign = new FileDocument(inputFile);
            System.out.println("dssDocument: " + documentToSign.getName() + " loaded.");

            ASiCWithCAdESSignatureParameters parametersASiC = new ASiCWithCAdESSignatureParameters();

            if(certFile!=null) {
                try (InputStream inStream = new FileInputStream(certFile)) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                    CertificateToken certificateToken = new CertificateToken(cert);
                    certificateToken.getCertificate().checkValidity();
                    parametersASiC.setSigningCertificate(certificateToken);
                    parametersASiC.setCertificateChain(certificateToken);
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                }
            } else {
                System.out.println("loading certificate from token");
                parametersASiC.setSigningCertificate(privateKeyDss.getCertificate());
                parametersASiC.setCertificateChain(privateKeyDss.getCertificate());
                System.out.println("==================================================================================================================================================================");
                System.out.println("found certificate SN: " + privateKeyDss.getCertificate().getSerialNumber());
                System.out.println("subject data: " + privateKeyDss.getCertificate().getSubject().getPrettyPrintRFC2253());
                System.out.println("issuer data: " + privateKeyDss.getCertificate().getIssuer().getPrettyPrintRFC2253());
                System.out.println("DSS id: " + privateKeyDss.getCertificate().getDSSIdAsString());
                System.out.println("==================================================================================================================================================================");
            }
            parametersASiC.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
            parametersASiC.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parametersASiC.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            parametersASiC.aSiC().setContainerType(ASiCContainerType.ASiC_E);

            ASiCWithCAdESService service = getASiCWithCAdESService(trustedDir);

            ToBeSigned dataToSign = service.getDataToSign(documentToSign, parametersASiC);

            SignatureValue sign = token.sign(dataToSign, parametersASiC.getDigestAlgorithm(), privateKeyDss);

            DSSDocument signedDocument = service.signDocument(documentToSign, parametersASiC, sign);

            byte[] signatureBytes = signedDocument.openStream().readAllBytes();

            File outFile = new File(outFilePath);
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                fos.write(signatureBytes);
            }
            System.out.println("File signed successfully.");
            System.out.println("File saved to: " + outFile.getAbsolutePath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static ASiCWithCAdESService getASiCWithCAdESService(String trustedDir) {
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
//        commonCertificateVerifier.setCheckRevocationForUntrustedChains(false);

        if(trustedDir != null) {
            File trustedDirFile = new File(trustedDir);
            if(trustedDirFile.isDirectory()) {
                CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
                for(File file: trustedDirFile.listFiles()) {
                    if(file.isFile() && file.getName().endsWith(".cer")) {
                        try (InputStream inStream = new FileInputStream(file)) {
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                            CertificateToken certificateToken = new CertificateToken(cert);
                            trustedCertificateSource.addCertificate(certificateToken);
                        } catch (Exception ignored) {}
                    }
                }
                commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);
            }
        }

        ASiCWithCAdESService service = new ASiCWithCAdESService(commonCertificateVerifier);

        OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
        onlineOCSPSource.setDataLoader(new OCSPDataLoader());
        onlineOCSPSource.setNonceSource(new SecureRandomNonceSource());
        commonCertificateVerifier.setOcspSource(onlineOCSPSource);

        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(new CommonsDataLoader());
        commonCertificateVerifier.setCrlSource(onlineCRLSource);

        commonCertificateVerifier.setRevocationFallback(true);

        String tspServer = "http://ca.diia.gov.ua/services/tsp/ecdsa/";
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        onlineTSPSource.setTspServer(tspServer);
        service.setTspSource(onlineTSPSource);

        return service;
    }
}
