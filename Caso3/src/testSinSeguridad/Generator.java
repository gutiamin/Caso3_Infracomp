package testSinSeguridad;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private LoadGenerator generator;
	
	public Generator() {
		Task work = createTask();
		int numberOfTasks=400;
		int gap=20;	
		generator= new LoadGenerator("Cliente-Servidor load test", numberOfTasks, work, gap);
		generator.generate();
	}
	
	private Task createTask() {
		return new ClientServerTask2();
	}
	
	public static void main(String[] args) {
		@SuppressWarnings("unused")
		Generator gen = new Generator();
	}

}
