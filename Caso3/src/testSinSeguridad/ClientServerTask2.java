package testSinSeguridad;

import clienteSinSeguridad.ClienteSinS;
import uniandes.gload.core.Task;

public class ClientServerTask2 extends Task{

	@Override
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
		
	}

	@Override
	public void success() {
		System.out.println(Task.OK_MESSAGE);
		
	}

	@Override
	public void execute() {
		ClienteSinS cliente = new ClienteSinS();
		cliente.run();
	}

}
