package tarea6;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Programa mediante el cual encriptamos el contenido de un fichero guardando el resultado en otro fichero llamado encriptado.txt
 * 
 * @author  David Jiménez Riscardo
 * @version 1.0
 */
public class Encriptador {

    /**
     * Main del programa
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        String nombre_fichero, contrasenia;
        Boolean existe;

        //1. LEEMOS DE LA ENTRADA ESTANDAR EL NOMBRE DEL FICHERO Y LA CONTRASEÑA
        //El archivo a encriptar lo he llamado "archivo" (sin comillas ni extensión)
        try {

            //Leemos el nombre del fichero a cifrar  
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            do {
                System.out.print("Introduzca el nombre del archivo a encriptar(FIN para finalizar el programa): ");
                nombre_fichero = br.readLine();
                existe = existFile(nombre_fichero);
                if((nombre_fichero.toUpperCase()).equals("FIN")){
                    System.out.println("Programa terminado.");
                    System.exit(0);
                }
                if (!nombre_fichero.isEmpty() && !existe) {
                    System.out.println("El archivo indicado no existe.");
                }
                if(nombre_fichero.isEmpty()){
                    System.out.println("Debe de introducir un nombre.");
                }              
                
            } while ( !existe || (nombre_fichero.toUpperCase()).equals("FIN") );
            
            //Leemos la contraseña
            do {
                System.out.print("Introduzca una contraseña de cifrado(FIN para finalizar el programa): ");
                br = new BufferedReader(new InputStreamReader(System.in));
                contrasenia = br.readLine();
                if((contrasenia.toUpperCase()).equals("FIN")){
                    System.out.println("Programa terminado.");
                    System.exit(0);
                }
                 if(contrasenia.isEmpty()){
                    System.out.println("La contraseña no debe de estar vacía.");
                }   
            } while( contrasenia.isEmpty() || contrasenia.toUpperCase().equals("FIN") );

            br.close();

        //2. GENERAMOS LA CLAVE A PARTIR DE LA CONTRASEÑA
            SecretKey clave = generarClave(contrasenia, 128);
            
           
        //3. ENCRIPTAMOS EL CONTENIDO DEL FICHERO GENERANDO UN NUEVO FICHERO QUE LLAMAREMOS encriptado.txt
            if (clave != null) {
                boolean encriptado = encriptarFichero(nombre_fichero, clave);
                if (encriptado) {
                    System.out.println("Fichero encriptado correctamente.");
                } 
            }
        } catch (IOException ex) {
            System.out.println("Error de E/S. ERROR: " + ex.getMessage());
        }
        
    }//Fin del método main

    /**
     * Método para comprobar si un fichero existe
     *
     * @param filename Nombre del fichero
     * @return Devuelve true si existe, false en caso contrario
     */
    public static boolean existFile(String filename) {
        boolean b = false;
        File file = new File(filename);
        if (file.exists()) {
            b = true;
        }
        return b;
    }
    
    /**
     * Método para eliminar un archivo 
     * @param filename Nombre del fichero
     */
    public static void deleteFile(String filename) {        
        File file = new File(filename);
        if(file.exists()) {
            file.delete();             
        }
    }

    /**
     * Método para generar una clave a partir de una cadena de texto dada
     *
     * @param texto Cadena de texto a partir de la cual generaremos la clave
     * @param tamanio Tamaño que tendrá la clave
     * @return Clave generada, en el caso de no poderse generar devolvería NULL
     */
    public static SecretKey generarClave(String texto, int tamanio) {
        SecretKey sk = null;
        if ((tamanio == 128) || (tamanio == 192) || (tamanio == 256)) {
            try {
                byte[] datos = texto.getBytes("UTF-8");
                //Algoritmo Hash
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                //Aplicamos el algoritmo hash sobre los datos
                byte[] hash = md.digest(datos);
                //Extraemos tantos bytes como necesitamos para generar la clave
                byte[] clave = Arrays.copyOf(hash, 16);
                sk = new SecretKeySpec(clave, "AES");
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException ex) {
                System.out.println("Error en la configuración del algoritmo. ERROR: " + ex.getMessage());
            }
        }
        return sk;
    }//Fin del método generarClave

    /**
     * Método para encriptar un fichero
     *
     * @param fichero Nombre del fichero
     * @param clave Clave que utilizaremos para su encriptación
     * @return True si se realiza la encriptación, false en caso contrario
     * @throws java.io.IOException
     */
    public static boolean encriptarFichero(String fichero, SecretKey clave) throws IOException  {

        Cipher c = null;
        try {
            c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, clave);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            System.out.println("Error en la configuración del algoritmo. ERROR: " + ex.getMessage());
        }
        if(c!=null){
            int bytesLeidos;
            byte[] buffer = new byte[1000]; //array de bytes
            byte[] bufferCifrado;
            FileInputStream fe = null;
            FileOutputStream fs = null;
            try {
                fe = new FileInputStream(fichero); //objeto fichero de entrada
                fs = new FileOutputStream("encriptado.txt"); //fichero de salida
                //lee el fichero de 1k en 1k y pasa los fragmentos leidos al cifrador
                bytesLeidos = fe.read(buffer, 0, 1000);
                while (bytesLeidos != -1) {//mientras no se llegue al final del fichero
                    //pasa texto claro al cifrador y lo cifra, asignándolo a bufferCifrado
                    bufferCifrado = c.update(buffer, 0, bytesLeidos);
                    fs.write(bufferCifrado); //Graba el texto cifrado en fichero
                    bytesLeidos = fe.read(buffer, 0, 1000);
                }
                bufferCifrado = c.doFinal(); //Completa el cifrado
                fs.write(bufferCifrado); //Graba el final del texto cifrado, si lo hay
                //Cierra ficheros
                fe.close();
                fs.close();
            } catch (FileNotFoundException ex) {
                System.out.println("Archivo no encontrado. ERROR: " + ex.getMessage());
            } catch (IOException ex) {
                System.out.println("Error de E/S. ERROR: " + ex.getMessage());
            } catch (IllegalBlockSizeException | BadPaddingException ex){
                System.out.println("Error en el tamaño del bloque / relleno. ERROR: " + ex.getMessage());
                fe.close();
                //Debemos de cerrar el uso del fichero para poderlo eliminar
                fs.close();
                deleteFile("encriptado.txt");               
            }
        }                
        return existFile("encriptado.txt");
        
    }//Fin del método encriptarFichero

}//Fin de la clase
