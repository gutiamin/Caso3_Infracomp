package clienteConSeguridad;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/*
 *Tomado del laboratorio 9 del curso Infraestructura Computacional
 */
public class Simetrico {

    private final static String PADDING = "AES/ECB/PKCS5Padding";
    private final static String AES = "AES";
    private final static String BLOWFISH = "Blowfish";

    private String pad;


    public byte[] cifrar(SecretKey llave, String algoritmo, byte[] textoClaro) {
    	
        if (algoritmo.equals(AES))
            pad = PADDING;

        if (algoritmo.equals(BLOWFISH))
            pad = BLOWFISH;

        byte[] textoCifrado;

        try {
            Cipher cifrador = Cipher.getInstance(pad);
            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);
            return textoCifrado;
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }

    public byte[] descifrar(SecretKey llave, String algoritmo, byte[] texto) {

        if (algoritmo.equals(AES))
            pad = PADDING;
        if (algoritmo.equals(BLOWFISH))
            pad = BLOWFISH;

        byte[] textoClaro;

        try {
            Cipher cifrador = Cipher.getInstance(pad);
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro = cifrador.doFinal(texto);
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
        return textoClaro;
    }

}
