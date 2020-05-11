package srv202010;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

public class CPUMonitor extends Thread{

	@Override
	public void run() {
		 //TODO Auto-generated method stub
		String ruta = "./cpuUsage.txt";
		File file;
		file = new File(ruta);
        if (!file.exists()) {
            try {
				file.createNewFile();
				FileWriter fw = new FileWriter(file);
		        fw.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				System.out.println(e.getMessage());
			}
        }
		while(true) {
			try {
				Thread.sleep(1000);
				escribirMensaje(getSystemCpuLoad().toString(), file);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				System.out.println(e.getMessage());
			}
		}
	}
	
	public Double getSystemCpuLoad() throws Exception {
		 MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		 ObjectName name = ObjectName.getInstance("java.lang:type=OperatingSystem");
		 AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });
		 if (list.isEmpty()) return Double.NaN;
		 Attribute att = (Attribute)list.get(0);
		 Double value = (Double) att.getValue();
		 // usually takes a couple of seconds before we get real values
		 if (value == -1.0) return Double.NaN;
		 // returns a percentage value with 1 decimal point precision
		 return ((int)(value * 1000) / 10.0);
		 }
	
private void escribirMensaje(String pCadena, File file) {
		
		try {
			FileWriter fw = new FileWriter(file,true);
			fw.write(pCadena + "\n");
			fw.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
