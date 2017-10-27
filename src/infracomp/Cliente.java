package infracomp;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;

public class Cliente {

	boolean ejecutar = true;
	Socket sock = null;
	PrintWriter escritor = null;
	BufferedReader lector = null;

	public Cliente()
	{
		try {
			sock = new Socket("localhost", 8083);
			escritor = new PrintWriter(sock.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(
					sock.getInputStream()));
			comenzarComunicacion(lector, escritor);
		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
	}
	// cierre el socket y la entrada estándar

	public void comenzarComunicacion(BufferedReader lector, PrintWriter escritor) throws Exception
	{
		escritor.println("HOLA");
		String respuesta = lector.readLine();
		System.out.println(respuesta);
		if(respuesta.equals("OK"))
		{
			escritor.println("ALGORITMOS:AES:RSA:HMACMD5");
			respuesta = lector.readLine();
			System.out.println(respuesta);
			if(respuesta.equals("OK"))
			{
				escritor.println("CERTCLNT");
			}
		}
		
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		new Cliente();
	}

}
