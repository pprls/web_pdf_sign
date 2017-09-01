package hello.storage;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Service
public class PdfSigningService implements SigningService {

    private final Path rootLocation;

    @Autowired
    public PdfSigningService(StorageProperties properties) {
        this.rootLocation = Paths.get(properties.getLocation());
    }

    @Override
    public Resource sign(MultipartFile multipartFile) throws UnrecoverableKeyException {

        String pin = "";
        Certificate cert = null;
        X509Certificate x509cert = null;
        PrivateKey privateKey = null;
        try {
            Certificate[] certChain = null;

            KeyStore keystore = KeyStore.getInstance("Windows-MY");
            keystore.load(null, pin.toCharArray());

//            KeyStore.CallbackHandlerProtection chp =
//                    new KeyStore.CallbackHandlerProtection(new AthenaCallbackHandler());
//            KeyStore.Builder builder =
//                    KeyStore.Builder.newInstance("Windows-MY", null, chp);
//            KeyStore keystore = builder.getKeyStore();
            //    Key key = ks.getKey(alias, null);

            Enumeration<String> aliases = keystore.aliases();


            String alias;
            cert = null;
            while (aliases.hasMoreElements() && x509cert == null) {
                alias = aliases.nextElement();
                privateKey = (PrivateKey) keystore.getKey(alias, pin.toCharArray());
                certChain = keystore.getCertificateChain(alias);
                if (certChain == null) {
                    continue;
                }
                // setCertificateChain(certChain);
                cert = certChain[0];
                if (cert instanceof X509Certificate) {
                    // avoid expired certificate
                    ((X509Certificate) cert).checkValidity();
                    // x509cert  = (X509Certificate) cert;

                    boolean [] keyUsages = ((X509Certificate) cert).getKeyUsage();

                    if (keyUsages!=null && keyUsages.length>=2 && keyUsages[0] == true //digitalSignature
                            && keyUsages[1] == true) // nonRepudiation // )
                    {
                        x509cert  = (X509Certificate) cert;
                    }
                }
            }

            if (x509cert == null) {
                throw new IOException("Could not find certificate or no certificate found with appropriate usage");
            }
            File inFile = File.createTempFile("pdfToSign",".pdf");
            multipartFile.transferTo(inFile);
//            File inFile = new File("C:\\Users\\npetalidis.OPEKEPE\\Documents\\Test.pdf");
//
//            if (!inFile.exists()) {
//                throw new FileNotFoundException("File Test.pdf does not exist");
//            }

           // File outFile = new File("C:\\Users\\npetalidis.OPEKEPE\\Documents\\Test_signed.pdf");
            File outFile = null;

            try (PDDocument doc = PDDocument.load(inFile)) {
                outFile = File.createTempFile("signedPdf",".pdf");
                FileOutputStream fos = new FileOutputStream(outFile);

                PDSignature signature = new PDSignature();
                signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
                signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

                doc.addSignature(signature);
                ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(fos);

                List<Certificate> certList = new ArrayList<>();
                certList.addAll(Arrays.asList(certChain));
                Store certs = new JcaCertStore(certList);
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                org.bouncycastle.asn1.x509.Certificate cert1 = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());
                try {
                    ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1WithRSA").build(privateKey);
                    gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, new X509CertificateHolder(cert1)));

                    try {
                        gen.addCertificates(certs);
                    } catch (CMSException e) {
                        e.printStackTrace();
                    }
                    CMSProcessableInputStream msg = new CMSProcessableInputStream(externalSigning.getContent());
                    CMSSignedData signedData = gen.generate(msg, false);
                    externalSigning.setSignature(signedData.getEncoded());
                    doc.saveIncremental(fos);
                    fos.close();
                    return new FileSystemResource(outFile);

                } catch (OperatorCreationException e) {
                    e.printStackTrace();
                } catch (CMSException e) {
                    e.printStackTrace();
                }
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
     return null;
    }

    @Override
    public Stream<Path> loadAll() {
        try {
            return Files.walk(this.rootLocation, 1)
                    .filter(path -> !path.equals(this.rootLocation))
                    .map(path -> this.rootLocation.relativize(path));
        }
        catch (IOException e) {
            throw new StorageException("Failed to read stored files", e);
        }

    }

    @Override
    public Path load(String filename) {
        return rootLocation.resolve(filename);
    }

    @Override
    public Resource loadAsResource(String filename) {
        try {
            Path file = load(filename);
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            }
            else {
                throw new StorageFileNotFoundException(
                        "Could not read file: " + filename);

            }
        }
        catch (MalformedURLException e) {
            throw new StorageFileNotFoundException("Could not read file: " + filename, e);
        }
    }

    @Override
    public void deleteAll() {
        FileSystemUtils.deleteRecursively(rootLocation.toFile());
    }

    @Override
    public void init() {
        try {
            Files.createDirectories(rootLocation);
        }
        catch (IOException e) {
            throw new StorageException("Could not initialize storage", e);
        }
    }
}
