package servidorConSeguridad;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.bouncycastle.operator.OperatorCreationException;

public class Coordinador {
	
	public static final String RUTA_TIEMPO_CON_S = "./data/logTiempoConS.csv";
	public static final String RUTA_CPU_CON_S = "./data/logCPUConS.csv";
	public static final String RUTA_PERDIDAS_CON_S = "./data/logPerdidasConS.csv";

	private static ServerSocket socketServidor;	
	private static final String MAESTRO = "MAESTRO: ";
	public static final int N_THREADS = 2;
	private static X509Certificate certSer; /* acceso default */
	private static KeyPair keyPairServidor; /* acceso default */
	private static ExecutorService pool;


	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		
		eliminarLogsViejos(); //TODO

		System.out.println(MAESTRO + "Establecer puerto de conexion: 8080"); 
		int ip = 8080; 

		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		// Adiciona la libreria como un proveedor de seguridad.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		

		// Crea el archivo de log
		File file = crearArchivoLog();

		//TODO cambios al servidor
		ProtocoloServidor.init(certSer, keyPairServidor, file);

		pool = Executors.newFixedThreadPool(N_THREADS);

		// Crea el socket que escucha en el puerto seleccionado.
		socketServidor = new ServerSocket(ip);
		System.out.println(MAESTRO + "Socket creado.");

		for (int i=0;true;i++) {
			try { 

	
				Socket socketCliente = socketServidor.accept();
				System.out.println(MAESTRO + "Cliente " + i + " aceptado.");
				pool.execute(new ProtocoloServidor(socketCliente, i));
				double cpuLoadActual = getSystemCpuLoad();

				logCpuLoad(cpuLoadActual); //TODO medir el uso de cpu con seguridad

			} catch (IOException e) {
				System.out.println(MAESTRO + "Error creando el socket cliente.");
				e.printStackTrace();
				
				//TODO registrar perdidas
				logPeticionesPerdidas(1);
			}
		}
		
		
	}

	public static void eliminarLogsViejos() {
		
		File f = new File (RUTA_CPU_CON_S);
		f.delete();
		
		File f2 = new File (RUTA_PERDIDAS_CON_S);
		f2.delete();

		File f3 = new File (RUTA_TIEMPO_CON_S);
		f3.delete();

		
	}

	private static File crearArchivoLog()
			throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
		File file = null;
		keyPairServidor = Seguridad.grsa();
		certSer = Seguridad.gc(keyPairServidor);

		//TODO ruta log con seguridad
		String ruta = "./data/logServidorConSeguridad.txt";

		file = new File(ruta);
		if (!file.exists()) {
			file.createNewFile();
		}
		FileWriter fw = new FileWriter(file);
		fw.close();
		return file;
	}


	public static double getSystemCpuLoad() throws Exception {
		MBeanServer mbs    = ManagementFactory.getPlatformMBeanServer();
		ObjectName name    = ObjectName.getInstance("java.lang:type=OperatingSystem");
		AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });
		if (list.isEmpty())     
			return Double.NaN;
		Attribute att = (Attribute)list.get(0);
		Double value  = (Double)att.getValue();// usually takes a couple of seconds before we get real values
		if (value == -1.0)      
			return Double.NaN;// returns a percentage value with 1 decimal point precision
		return ((int)(value * 1000) / 10.0);

	}


	public static void logCpuLoad(double cpu) {
		//TODO conSeguridad
		try {
			File f = new File(RUTA_CPU_CON_S);
			FileWriter fwriter = new FileWriter(f,true);
			String value = String.valueOf(cpu);
			fwriter.append(value+"\n");
			fwriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void logPeticionesPerdidas(int cpu) {

		//TODO conSeguridad
		try {
			File f = new File(RUTA_PERDIDAS_CON_S);
			FileWriter fwriter = new FileWriter(f,true);
			String value = String.valueOf(cpu);
			fwriter.append(value + "\n");
			fwriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
