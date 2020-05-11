package srv202010SS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import srv202010.Sss;

public class Css {
	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	private static X509Certificate certSer; /* acceso default */
	private static KeyPair keyPairServidor; /* acceso default */
	
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub

		System.out.println(MAESTRO + "Establezca puerto de conexion:");
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		int ip = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		System.out.println(MAESTRO + "Establezca el numero de threads");
		int threads = Integer.parseInt(br.readLine());
		ExecutorService executor = Executors.newFixedThreadPool(threads);
		System.out.println(MAESTRO + "Se establecio un pool de threads con " + threads + " threads");
		// Adiciona la libreria como un proveedor de seguridad.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		

		// Crea el archivo de log
		File file = null;
		keyPairServidor = Sss.grsa();
		certSer = Sss.gc(keyPairServidor);
		
		if(threads == 1) {
			String ruta = "./datosServidorSS/Servidor 1Pool, 400 transacciones, 20ms/10.txt" ;
			
			file  = new File(ruta);
			if(!file.exists()) {
				file.createNewFile();
			}
			FileWriter fw = new FileWriter(file);
			fw.close();
			
			Dss.init(certSer, keyPairServidor, file);
	        
			// Crea el socket que escucha en el puerto seleccionado.
			ss = new ServerSocket(ip);
			System.out.println(MAESTRO + "Socket creado.");
			
			CPUMonitorss monitorCPU = new CPUMonitorss();
			monitorCPU.start();
	        
			for (int i=0;true;i++) {
				try { 
					Socket sc = ss.accept();
					System.out.println(MAESTRO + "Cliente " + i + " aceptado.");
					Dss d = new Dss(sc,i);
					executor.execute(d);
				} catch (IOException e) {
					System.out.println(MAESTRO + "Error creando el socket cliente.");
					e.printStackTrace();
				}
			}
		}
		else if(threads == 2) {
			String ruta = "./datosServidorSS/Servidor 2Pool, 400 transacciones, 20ms/10.txt" ;
			
			file  = new File(ruta);
			if(!file.exists()) {
				file.createNewFile();
			}
			FileWriter fw = new FileWriter(file);
			fw.close();
			
			Dss.init(certSer, keyPairServidor, file);
	        
			// Crea el socket que escucha en el puerto seleccionado.
			ss = new ServerSocket(ip);
			System.out.println(MAESTRO + "Socket creado.");
			
			CPUMonitorss monitorCPU = new CPUMonitorss();
			monitorCPU.start();
	        
			for (int i=0;true;i++) {
				try { 
					Socket sc = ss.accept();
					System.out.println(MAESTRO + "Cliente " + i + " aceptado.");
					Dss d = new Dss(sc,i);
					executor.execute(d);
				} catch (IOException e) {
					System.out.println(MAESTRO + "Error creando el socket cliente.");
					e.printStackTrace();
				}
			}
		}     
	}
}
