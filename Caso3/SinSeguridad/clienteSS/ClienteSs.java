package clienteSS;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;

public class ClienteSs extends Thread {


    public final static String HOST = "localhost";
    public final static int PUERTO = 8080;

    //======================================
    // COMANDOS DE COMUNICACIÓN
    //======================================
    public final static String HOLA = "HOLA";
    public final static String ALGORITMOS = "ALGORITMOS";
    public final static String OK = "OK";
    public final static String ERROR = "ERROR";

    //======================================
    // ALGORITMOS
    //======================================
    public final static String AES = "AES";
    public final static String BLOWFISH = "Blowfish";
    public final static String RSA = "RSA";
    public final static String HMACSHA1 = "HMACSHA1";
    public final static String HMACSHA256 = "HMACSHA256";
    public final static String HMACSHA384 = "HMACSHA384";
    public final static String HMACSHA512 = "HMACSHA512";

    //======================================
    // ATRIBUTOS
    //======================================
    private Socket socket;
    private PrintWriter writer;
    private BufferedReader reader;

    private PublicKey publicKeyServidor;
    private PublicKey publicKeyCliente;
    private PrivateKey privateKeyCliente;
    private SecretKey llaveSimetrica;
    private String algoritmoSimetrico;
    private String algoritmoAsimetrico;
    private String algoritmoHMac;

    //======================================
    // CONSTRUCTOR
    //======================================
    
    public ClienteSs() {

        try {
            socket = new Socket(HOST, PUERTO);
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //========================================================
    // ETAPA 1
    //========================================================

    /*
     * seleccionar algoritmos e iniciar	sesi�n
     */
    public void etapa1() throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("Para iniciar, escriba HOLA");
//        String input = sc.next();
        String input = HOLA;

        if (input.equals(HOLA)) {
            //hablarle al servidor
            writer.println(HOLA);
        }
        String resp = reader.readLine();
        System.out.println(resp);
        if (resp.equals(OK)) {
            String mensajeAlgoritmos = ALGORITMOS + ":";

            //algoritmo simetrico
            System.out.println("Seleccione un algoritmo simetrico escribiendo el numero del deseado (ej: 1): \n" + "1.AES \n" + "2.Blowfish");
//            int algSim = sc.nextInt();
            int algSim = 1;
            if (algSim == 1) {
                mensajeAlgoritmos += AES + ":";
                algoritmoSimetrico = AES;
            } else if (algSim == 2) {
                mensajeAlgoritmos += BLOWFISH + ":";
                algoritmoSimetrico = BLOWFISH;
            } else {
                throw new Exception("No se especific� un algoritmo simetrico v�lido");
            }

            //algoritmo asimetrico
            System.out.println("Seleccione un algoritmo asimetrico escribiendo el numero del deseado (ej: 1): \n" + "1.RSA \n");
//            int algAsim = sc.nextInt();
            int algAsim = 1;
            if (algAsim == 1) {
                mensajeAlgoritmos += RSA + ":";
                algoritmoAsimetrico = RSA;
            } else {
                throw new Exception("No se especific� un algoritmo asimetrico v�lido");
            }

            //algoritmo HMAC
            System.out.println("Seleccione un algoritmo HMAC escribiendo el numero del deseado (ej: 1): \n" + "1.HmacSHA1 \n" + "2.HmacSHA256 \n" + "3.HmacSHA384 \n" + "4.HmacSHA512 \n");
//            int algHmac = sc.nextInt();
            int algHmac = 1;
            if (algHmac == 1) {
                mensajeAlgoritmos += HMACSHA1;
                algoritmoHMac = HMACSHA1;
            } else if (algHmac == 2) {
                mensajeAlgoritmos += HMACSHA256;
                algoritmoHMac = HMACSHA256;
            } else if (algHmac == 3) {
                mensajeAlgoritmos += HMACSHA384;
                algoritmoHMac = HMACSHA384;
            } else if (algHmac == 4) {
                mensajeAlgoritmos += HMACSHA512;
                algoritmoHMac = HMACSHA512;
            } else {
                throw new Exception("No se especific� un algoritmo simetrico v�lido");
            }

            writer.println(mensajeAlgoritmos);
            System.out.println(mensajeAlgoritmos);

            String resp2 = reader.readLine();
            System.out.println(resp2);

            if (resp2.equals(ERROR)) {
                throw new Exception("La cadena no es válida");
            }
        }
    }

    //========================================================
    // ETAPA 2
    //========================================================

    /*
    * Autenticaci�n cliente y servidor
    */
    public void etapa2() throws Exception {
    	
    	//Cliente
    	
    	KeyPairGenerator generator = KeyPairGenerator.getInstance(algoritmoAsimetrico);
    	generator.initialize(1024);
    	KeyPair keyPair = generator.generateKeyPair();
    	publicKeyCliente = keyPair.getPublic();
    	privateKeyCliente = keyPair.getPrivate();
    	
    	X509Certificate certificado = gc(keyPair);
    	byte[] certificadoEnBytes = certificado.getEncoded();
    	String certificadoEnString = DatatypeConverter.printBase64Binary(certificadoEnBytes);
    	writer.println(certificadoEnString);
    	
    	System.out.println("Se envia el certificado del cliente");
        
        // Servidor
    	
    	String resp3 = reader.readLine();
    	System.out.println(resp3);
    	
        String certificateString = reader.readLine();
        System.out.println("Se recibio el certificado del servidor");

        X509Certificate cert = this.darCertificadoAPartirDeString(certificateString);
        System.out.println(cert.toString());
        
        publicKeyServidor = cert.getPublicKey();
        
        writer.println(OK);
    }

    //========================================================
    // ETAPA 3
    //========================================================

    /*
    * Reporte y manejo de la autenticaci�n
    */
    public void etapa3() throws IOException {
    	Scanner sc = new Scanner(System.in);
    	
    	String resp4 = reader.readLine();
//    	byte[] resp4EnBytes = DatatypeConverter.parseBase64Binary(resp4);
//            
//        llaveSimetrica = new SecretKeySpec(resp4EnBytes, algoritmoSimetrico);
        
        String resp5 = reader.readLine();
       
        writer.println(resp5);
        
        String resp6 = reader.readLine();
        System.out.println(resp6);
        
        System.out.println("Escriba su ID de usuario:");
//        String idUsuario = sc.next();
        String idUsuario = "123";
        String idUsuarioMultiplo4 = darStringMultiplo4(idUsuario);
        writer.println(idUsuarioMultiplo4);
        
        String resp7 = reader.readLine();
   
        System.out.println("La hora de registro es: " + resp7);
        
        writer.println(OK);
        
    }
    
    //========================================================
    // Metodos Auxiliares
    //========================================================
    
    /*
     * Retorna el certificado a partir de un String
     */
    private X509Certificate darCertificadoAPartirDeString(String certificateString) throws CertificateException {
        System.out.print(certificateString);
        String certMultiplo4 = darStringMultiplo4(certificateString);
        byte[] cert64bytes = DatatypeConverter.parseBase64Binary(certMultiplo4);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(cert64bytes);
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
        return cert;
    }
    
    

    /*
     * Le a�ade ceros a la cadena si no es multiplo de 4
     */
    private String darStringMultiplo4(String original) {
       int certLenth = 4-(original.length()%4);

       if (certLenth != 0) {
            while (certLenth > 0) {
                original += "0";
                certLenth--;
            }
        }
        return original;
    }
    
    /*
     * Generando el certificado del cliente
     */
    public static X509Certificate gc(KeyPair keyPair) throws OperatorCreationException, CertificateException {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	Calendar endCalendar = Calendar.getInstance();
    	endCalendar.add(Calendar.YEAR, 10);
    	X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(new X500Name("CN=localhost"), BigInteger.valueOf(1), Calendar.getInstance().getTime(), endCalendar.getTime(), new X500Name("CN=localhost"), SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
    	ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate());
    	X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
    	return new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);
    }

    //========================================================
    // Ejecuci�n de la aplicaci�n
    //========================================================

    public void run(){
        try {
            etapa1();
            etapa2();
            etapa3();

            writer.close();
            reader.close();
            socket.close();
            System.out.print("Comunicaci�n finalizada");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        ClienteSs c = new ClienteSs();
        c.start();


    }
}
