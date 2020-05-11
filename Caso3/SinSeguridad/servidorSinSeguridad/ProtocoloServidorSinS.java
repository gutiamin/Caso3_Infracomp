package servidorSinSeguridad;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class ProtocoloServidorSinS extends Thread {

	public static final String RUTA_TIEMPO = "./data/logTiempoSinS.csv";


	public static final String OK = "OK";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String CERTSRV = "CERTSRV";
	public static final String CERCLNT = "CERCLNT";
	public static final String SEPARADOR = ":";
	public static final String HOLA = "HOLA";
	public static final String INICIO = "INICIO";
	public static final String ERROR = "ERROR";
	public static final String REC = "recibio-";
	public static final int numCadenas = 8;

	// Atributos
	private Socket socketCliente = null;
	private String dlg;
	private byte[] mybyte;
	private static File file;
	private static X509Certificate certSer;
	private static KeyPair keyPairServidor;

	public static void init(X509Certificate pCertSer, KeyPair pKeyPairServidor, File pFile) {
		certSer = pCertSer;
		keyPairServidor = pKeyPairServidor;
		file = pFile;
	}

	public ProtocoloServidorSinS (Socket csP, int idP) {
		socketCliente = csP;
		dlg = new String("delegado " + idP + ": ");
		try {
			mybyte = new byte[520]; 
			mybyte = certSer.getEncoded();
		} catch (Exception e) {
			System.out.println("Error creando encoded del certificado para el thread" + dlg);
			e.printStackTrace();
		}
	}

	private boolean validoAlgHMAC(String nombre) {
		return ((nombre.equals(Seguridad.HMACMD5) || 
				nombre.equals(Seguridad.HMACSHA1) ||
				nombre.equals(Seguridad.HMACSHA256) ||
				nombre.equals(Seguridad.HMACSHA384) ||
				nombre.equals(Seguridad.HMACSHA512)
				));
	}

	/*
	 * Generacion del archivo log. 
	 * Nota: 
	 * - Debe conservar el metodo como está. 
	 * - Es el único metodo permitido para escribir en el log.
	 */
	private void escribirMensaje(String pCadena) {

		try {
			FileWriter fw = new FileWriter(file,true);
			fw.write(pCadena);
			fw.write("\n");
			fw.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void run() {
		String[] cadenas;
		cadenas = new String[numCadenas];

		String linea;
		System.out.println(dlg + "Empezando atencion.");
		try {

			PrintWriter ac = new PrintWriter(socketCliente.getOutputStream() , true);
			BufferedReader dc = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));

			/***** Fase 1:  *****/
			linea = dc.readLine();
			cadenas[0] = "Fase1: ";
			if (!linea.equals(HOLA)) {
				ac.println(ERROR);
				socketCliente.close();
				throw new Exception(dlg + ERROR + REC + linea +"-terminando.");
			} else {
				ac.println(OK);
				cadenas[0] = dlg + REC + linea + "-continuando.";
				System.out.println(cadenas[0]);
			}

			/***** Fase 2:  *****/
			linea = dc.readLine();
			cadenas[1] = "Fase2: ";
			if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals(ALGORITMOS))) {
				ac.println(ERROR);
				socketCliente.close();
				throw new Exception(dlg + ERROR + REC + linea +"-terminando.");
			}

			String[] algoritmos = linea.split(SEPARADOR);
			if (!algoritmos[1].equals(Seguridad.DES) && !algoritmos[1].equals(Seguridad.AES) &&
					!algoritmos[1].equals(Seguridad.BLOWFISH) && !algoritmos[1].equals(Seguridad.RC4)){
				ac.println(ERROR);
				socketCliente.close();
				throw new Exception(dlg + ERROR + "Alg.Simetrico" + REC + algoritmos + "-terminando.");
			}
			if (!algoritmos[2].equals(Seguridad.RSA) ) {
				ac.println(ERROR);
				socketCliente.close();
				throw new Exception(dlg + ERROR + "Alg.Asimetrico." + REC + algoritmos + "-terminando.");
			}
			if (!validoAlgHMAC(algoritmos[3])) {
				ac.println(ERROR);
				socketCliente.close();
				throw new Exception(dlg + ERROR + "AlgHash." + REC + algoritmos + "-terminando.");
			}
			cadenas[1] = dlg + REC + linea + "-continuando.";
			System.out.println(cadenas[1]);
			ac.println(OK);

			/***** Fase 3:  *****/
			String testCert = toHexString(mybyte);
			ac.println(testCert);
			cadenas[2] = dlg + "envio certificado del servidor. continuando.";
			System.out.println(cadenas[2] + testCert);				

			/***** Fase 4: *****/ //TODO registrar tiempo LECTURA LLAVE SIMETRICA sin seg
			long tiempo1 = System.currentTimeMillis();
			cadenas[3] = "";
			linea = dc.readLine();
			byte[] llaveSimetrica = toByteArray(linea);
			SecretKey simetrica = new SecretKeySpec(llaveSimetrica, 0, llaveSimetrica.length, algoritmos[1]);
			cadenas[3] = dlg + "recibio y creo llave simetrica. continuando.";
			System.out.println(cadenas[3]);

			/***** Fase 5:  *****/
			cadenas[4]="";
			linea = dc.readLine();
			System.out.println(dlg + "Recibio reto del cliente:-" + linea + "-");
			byte[] retoByte = toByteArray(linea);
			ac.println(toHexString(retoByte));
			System.out.println(dlg + "envio reto al cliente. continuado.");

			linea = dc.readLine();
			if ((linea.equals(OK))) {
				cadenas[4] = dlg + "recibio confirmacion del cliente:"+ linea +"-continuado.";
				System.out.println(cadenas[4]);
			} else {
				socketCliente.close();
				throw new Exception(dlg + ERROR + "en confirmacion de llave simetrica." + REC + "-terminando.");
			}

			/***** Fase 6:  *****/
			linea = dc.readLine();				
			byte[] ccByte = toByteArray(linea);
			String cc = toHexString(ccByte);
			System.out.println(dlg + "recibio cc :-" + cc + "-continuado.");

			linea = dc.readLine();				
			byte[] claveByte = toByteArray(linea);
			String clave = toHexString(claveByte);
			System.out.println(dlg + "recibio clave :-" + clave + "-continuado.");
			cadenas[5] = dlg + "recibio cc y clave - continuando";

			Random rand = new Random(); 
			int valor = rand.nextInt(1000000);
			String strvalor = valor+"";
			while (strvalor.length()%4!=0) strvalor += 0;
			byte[] valorByte = toByteArray(strvalor);
			ac.println(toHexString(valorByte));
			cadenas[6] = dlg + "envio valor "+strvalor+" al cliente. continuado.";
			System.out.println(cadenas[6]);

			byte [] hmac = Seguridad.hdg(valorByte, simetrica, algoritmos[3]);
			ac.println(toHexString(hmac));
			System.out.println(dlg + "envio hmac. continuado.");

			//TODO registrar tiempo luego de enviar HMAC sin seg
			long tiempo2 = System.currentTimeMillis();
			logTime(tiempo1, tiempo2);


			cadenas[7] = "";
			linea = dc.readLine();	
			if (linea.equals(OK)) {
				cadenas[7] = dlg + "Terminando exitosamente." + linea;
				System.out.println(cadenas[7]);
			} else {
				cadenas[7] = dlg + "Terminando con error" + linea;
				System.out.println(cadenas[7]);
			}
			socketCliente.close();

			//TODO cambio para asegurarse de que la info de los delegados se imprima en bloques, sin seg
			String cadenaImprimir = "";
			for (int i=0;i<numCadenas;i++) {
				cadenaImprimir += cadenas[i] + "\n";
			}
			escribirMensaje(cadenaImprimir);
	
		
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String toHexString(byte[] array) {
		return DatatypeConverter.printBase64Binary(array);
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseBase64Binary(s);
	}

	//TODO metodo para registar los logs de tiempo, sin seg
	public void logTime(long t1, long t2) {
		try {
			File f = new File(RUTA_TIEMPO);
			FileWriter fwriter = new FileWriter(f,true);
			String value = String.valueOf(t2-t1);
			fwriter.append(value + "\n");
			fwriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
