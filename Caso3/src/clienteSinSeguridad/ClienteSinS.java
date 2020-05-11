package clienteSinSeguridad;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Scanner;

public class ClienteSinS extends Thread {


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
    private SecretKey llaveSimetrica;
    private String algoritmoSimetrico;
    private String algoritmoAsimetrico;
    private String algoritmoHMac;

    //======================================
    // CONSTRUCTOR
    //======================================
    public ClienteSinS() {

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
     * seleccionar algoritmos e iniciar	sesiÃ³n
     */
    public void etapa1() throws Exception {
        System.out.println("Salude con un HOLA");
        writer.println(HOLA);
		String resp = reader.readLine();
		System.out.print(resp + "\n");
        if (resp.equals(OK)) {
            String mensajeAlgoritmos = ALGORITMOS + ":";

            //algoritmo simetrico
            System.out.println("Seleccione un algoritmo simetrico escribiendo el numero del deseado (ej: 1): \n" + "1.AES \n" + "2.Blowfish");
            int algSim = (int) (Math.random() * 2) + 1;
            if (algSim == 1) {
                mensajeAlgoritmos += AES + ":";
                algoritmoSimetrico = AES;
            } else if (algSim == 2) {
                mensajeAlgoritmos += BLOWFISH + ":";
                algoritmoSimetrico = BLOWFISH;
            } else {
                throw new Exception("No se especificó un algoritmo simetrico válido");
            }

            //algoritmo asimetrico
            System.out.println("Seleccione un algoritmo asimetrico escribiendo el numero del deseado (ej: 1): \n" + "1.RSA \n");
            int algAsim = 1;
            if (algAsim == 1) {
                mensajeAlgoritmos += RSA + ":";
                algoritmoAsimetrico=RSA;
            } else {
                throw new Exception("No se especificó un algoritmo asimetrico válido");
            }

            //algoritmo HMAC
            System.out.println("Seleccione un algoritmo HMAC escribiendo el numero del deseado (ej: 1): \n" + "1.HmacSHA1 \n" + "2.HmacSHA256 \n" + "3.HmacSHA384 \n" + "4.HmacSHA512 \n");
            int algHmac =(int) (Math.random() *4) + 1;
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
                throw new Exception("No se especificó un algoritmo simetrico válido");
            }

            writer.println(mensajeAlgoritmos);
            System.out.println(mensajeAlgoritmos);

            String resp2 = reader.readLine();
            System.out.print(resp2 + "\n");

            if (resp2.equals(ERROR)) {
                throw new Exception("La cadena no es válida");
            }
        }
    }

    //========================================================
    // ETAPA 2
    //========================================================

    /*
    * Autenticación	del servidor
    */
    public void etapa2() throws Exception {

        String certificateString = reader.readLine();
        System.out.print("Se recibió el certificado del servidor\n");

        X509Certificate cert = this.darCertificadoAPartirDeString(certificateString);
        System.out.print(cert.toString());

        System.out.print("\nValidar certificado\n");

        boolean validado = this.validarCetificado(cert);
        if (validado) {
            writer.println(OK);
        } else {
            writer.println(ERROR);
            throw new Exception("No se autenticó correctamente el servidor");
        }

    }

    /*
     * Se encarga de validar el certificado que envía el servidor.
     * 1) La fecha del CD debe ser válida
     * 2) Obtiene la llave pública del servidor y envia una llave simetrica cifrada con la llave publica del servidor
     * 3) Envía una cadena
     * 4) El servidor envia la cadena cifrada con la llave simetrica
     * 5) El cliente decifra la cadena que envia el servidor, si es igual a la que envió originalmente
     *    entonces el servidor queda autenticado
     */
    private boolean validarCetificado(X509Certificate c) throws CertificateNotYetValidException, CertificateExpiredException, NoSuchAlgorithmException, IOException {
        boolean res = false;
        Date now = new Date();
        c.checkValidity(now); //Revisa que el certificado sea válido según la fecha

        publicKeyServidor = c.getPublicKey(); //Obtiene la llave publica del servidor

        //Generar llave simetrica para la comunicación
        KeyGenerator keyGen = KeyGenerator.getInstance(algoritmoSimetrico);
        keyGen.init(128);
        llaveSimetrica = keyGen.generateKey();
        System.out.print("Se genero la la llave simetrica\n");

        //Cifrar la llave simetrica con la llave publica del servidor
        byte[] bytesLlaveSimetrica = llaveSimetrica.getEncoded();
        System.out.print("KS\n");
        String mensajeLlave = DatatypeConverter.printBase64Binary(bytesLlaveSimetrica);
        writer.println(mensajeLlave);
        System.out.print("KS enviada\n");

        //Validar reto
        System.out.print("Ecriba el reto que desea enviar al servidor\n");
        String reto = String.valueOf((int) Math.random()*50000);
        String retoBase64 = DatatypeConverter.printBase64Binary(reto.getBytes());
        System.out.print("Reto enviado por el cliente: "+retoBase64 + "\n");
        writer.println(retoBase64);

        String resServidor = reader.readLine();
        byte[] resServidorBytes = DatatypeConverter.parseBase64Binary(resServidor);
        System.out.print(resServidorBytes);

        String mmm = DatatypeConverter.printBase64Binary(resServidorBytes);
        System.out.println("Reto del serivdor: " + mmm + "\n");

        if (mmm.equals(retoBase64)) {
            res = true;
        }
        return res;
    }

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
     * Le añade ceros a la cadena si no es multiplo de 4
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

    //========================================================
    // ETAPA 3
    //========================================================

    /*
    * Autenticación	del	cliente
    */
    public void etapa3() throws IOException {
        System.out.print("Ingrese la cedula\n");
        String cc = String.valueOf((int) Math.random()*5000);

        System.out.print("Ingrese la clave\n");
        String clave = String.valueOf((int) Math.random()*5000);

        String cc64 = DatatypeConverter.printBase64Binary(cc.getBytes());
        String clave64 = DatatypeConverter.printBase64Binary(clave.getBytes());


        byte[] ccBase64 = DatatypeConverter.parseBase64Binary(cc64);
        byte[] claveBase64 = DatatypeConverter.parseBase64Binary(clave64);

        String ccString = DatatypeConverter.printBase64Binary(ccBase64);
        String claveString = DatatypeConverter.printBase64Binary(claveBase64);

        writer.println(ccString);
        writer.println(claveString);
    }
  
    //========================================================
    // ETAPA 4
    //========================================================

    /*
    * solicitud	de	información	y validación de	la respuesta
    */
    public void etapa4() throws IOException {

    	//descifrar valor recibido
        String res = reader.readLine();
        System.out.print("Valor enviado por el servidor " + res + "\n");

        byte[] resEnBytesBase64 = DatatypeConverter.parseBase64Binary(res);

        
        //descifrar HMAC recibido
        String resHmac = reader.readLine();
        System.out.print("Valor del HMAC enviado por el servidor " + resHmac + "\n");

        
        //calcular HMAC y comparar
        String hmacCalculado = null;
        try {
			Mac hmac = Mac.getInstance(algoritmoHMac);
			hmac.init(llaveSimetrica);
			byte [] hmacData = hmac.doFinal(resEnBytesBase64);
			hmacCalculado = DatatypeConverter.printBase64Binary(hmacData);
			System.out.println("El Hmac calculado localmente seg�n el valor descifrado es: " + hmacCalculado + "\n");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
        
        if(resHmac.equals(hmacCalculado)) {
        	System.out.println("Los HMAC coinciden");
        	writer.println("OK");
        }
        else {
        	System.out.println("Los HMAC NO coinciden");
        	writer.println("ERROR");
        }
        	
        
    }

    public void run(){
        try {
            etapa1();
            etapa2();
            etapa3();
            etapa4();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        ClienteSinS c = new ClienteSinS();
        c.start();


    }
}
