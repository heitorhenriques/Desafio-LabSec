package services;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, SignatureException, InvalidKeyException, CertificateException, CertificateEncodingException, IOException, CertIOException, OperatorCreationException, Exception {
        Authority ac = new Authority();
        X509Certificate rootCert = ac.makeCertificate();
        Signer sg = new Signer();
        sg.signCertificate(ac, rootCert);
    }

}
