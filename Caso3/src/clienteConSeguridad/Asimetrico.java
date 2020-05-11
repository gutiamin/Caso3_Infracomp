package clienteConSeguridad;
import javax.crypto.*;
import java.security.Key;

/*
 *Tomado del laboratorio 8 del curso Infraestructura Computacional
 */
public class Asimetrico {


	public static byte[] cifrar(Key llave, String algoritmo, byte[] textoClaro)
	{
		byte[] textoCifrado;
		
		try 
		{
			Cipher cifrador = Cipher.getInstance(algoritmo);
			//byte[] textoClaro =texto.getBytes();
			
			cifrador.init(Cipher.ENCRYPT_MODE, llave);
			textoCifrado = cifrador.doFinal(textoClaro);
			
			return textoCifrado;
		} 
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public static byte[] descifrar(Key llave, String algoritmo, byte[] texto)
	{
		byte[] textoClaro;
		
		try 
		{
			Cipher cifrador = Cipher.getInstance(algoritmo);
			cifrador.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrador.doFinal(texto);
		} 
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
		
		return textoClaro;
	}

}
