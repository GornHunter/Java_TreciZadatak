package ftpserver;

import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

public class ConnectedFTPClient implements Runnable{
    
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";

    //atributi koji se koriste za komunikaciju sa klijentom
    private Socket socket;
    private InputStream is;
    private OutputStream os;
    
    //atributi koji se koriste za enkripciju/dekripciju
    
    private PublicKey publicKeyRSA;
    private PrivateKey privateKeyRSA;
    private SecretKey secretKeyAES;
    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private Cipher RSACipher;
    private Cipher AESCipher;
    private byte[] initializationVector;
    
    private String path;
    
    //getters and setters
    public InputStream getIs() {
        return is;
    }

    public void setIs(InputStream is) {
        this.is = is;
    }

    public OutputStream getOs() {
        return os;
    }

    public void setOs(OutputStream os) {
        this.os = os;
    }
    
    public String getPath(){
        return path;
    }
    
    //Konstruktor klase, prima kao argument socket kao vezu sa uspostavljenim klijentom
    public ConnectedFTPClient(Socket socket, String path){
        this.socket = socket;
        this.privateKeyRSA = null;
        this.publicKeyRSA = null;
        try {
            this.keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        //duzina RSA kljuca je 1024 bita
        this.keyGen.initialize(1024);
        try {
            this.RSACipher = Cipher.getInstance("RSA");
            this.AESCipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.initializationVector = null;        
        
        //iz socket-a preuzmi InputStream i OutputStream
        try {
            this.is = this.socket.getInputStream();
            this.os = this.socket.getOutputStream();
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        this.path = path;
        createKeys();
    }

    /**
     * Napravi javni i tajni kljuc za RSA enkripciju/dekripciju
     */
    public void createKeys() {
        //Koristite keyGen kako biste napravili par kljuceva
        pair = keyGen.generateKeyPair();
        
        //postavite privateKeyRSA da bude referenca na tajni kljuc, a
        privateKeyRSA = pair.getPrivate();
        
        //publicKeyRSA da bude referenca na javni kljuc
        publicKeyRSA = pair.getPublic();
    }

    /**
     * Dekriptuj primljeni AES tajni kljuc enkriptovan javnim RSA kljucem
     * Za dekripciju koristi tajni RSA kljuc
     * @param msg enkriptovan tajni AES kljuc
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public void decryptSecretKeyAES(byte[] msg) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        //Koristite metodu init na RSACipher objektu uz mod Cipher.DECRYPT_MODE i koristeci privateKeyRSA za dekripciju
        RSACipher.init(Cipher.DECRYPT_MODE, this.privateKeyRSA);
        
        //dekriptujte primljenu poruku
        byte[] keyBytes = RSACipher.doFinal(msg);
        
        // iz primljene poruke rekonstruisite privatni kljuc za AES
        secretKeyAES = new SecretKeySpec(keyBytes, "AES");        
    }    
    
    
    /**
     * Dekriptuj primljeni inicijalizacioni vektor enkriptovan javnim RSA kljucem
     * Za dekripciju koristi tajni RSA kljuc
     * @param msg enkriptovan tajni IV
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public void decryptInitializationVector(byte[] msg) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        //Koristite metodu init na RSACipher objektu uz mod Cipher.DECRYPT_MODE i koristeci privateKeyRSA za dekripciju
        RSACipher.init(Cipher.DECRYPT_MODE, this.privateKeyRSA);
        
        //dekriptujte primljenu poruku
        byte[] keyBytes = RSACipher.doFinal(msg);
        
        // iz primljene poruke rekonstruisite IV za AES
        initializationVector = keyBytes;        
    }    
    
    /**
     * Dekriptuje niz bajtova na ulazu koristeci skriveni AES kljuc
     * @param input niz bajtova koji su primljeni od servera 
     * @return dekriptovan niz bajtova (po potrebi morace se konvertovati u string)
     * @throws Exception 
     */
    public byte[] do_AESDecryption(byte[] input) throws Exception{        
        //Koristite objekat IvParameterSpec klase sa initializationVector atributom
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        
        //Inicijalizujte AESCipher u Cipher.DECRYPT_MODE modu sa secretKeyAES
        AESCipher.init(Cipher.DECRYPT_MODE, secretKeyAES, ivParameterSpec);
  
        //vrati dekriptovani ulaz koristeci prethodno inicijalizovan AESCipher
        return AESCipher.doFinal(input); //samo da se ne bi bunio kompajler
    }   
    
    /**
     * Enkriptuj ulazni niz bajtova koristeci skriveni AES kljuc
     * Kriptovani izlaz se salje serveru
     * @param input ulazni niz bajtova koji treba kriptovati
     * @return kriptovani izlaz spreman za slanje serveru
     * @throws Exception 
     */
    public byte[] do_AESEncryption(byte[] input) throws Exception{
        //Koristite instancu klase IvParameterSpec zajedno sa initializationVector atributom
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        
        //inicijalizujte AESCipher u modu Cipher.ENCRYPT_MODE, zajedno sa secretKeyAES kljucem
        AESCipher.init(Cipher.ENCRYPT_MODE, secretKeyAES, ivParameterSpec);
  
        //vrati enkriptovani ulaz koristeci prethodno inicijalizovan AESCipher
        return AESCipher.doFinal(input); //samo da se ne bi bunio kompajler
    }
           
    /**
     * Salje nekriptovani javni kljuc za RSA koristeci OutputStream dobijen iz klijent socket-a
     */
    public void sendPublicKeyRSA(){
        try {        
            this.os.write(this.publicKeyRSA.getEncoded());
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Prima niz bajtova od klijenta i dekriptuje ih koristeci tajni AES kljuc
     * @return dekriptovani niz bajtova
     */
    public byte[] receiveAndDecryptMessage(){
        byte[] ret = null;
        try {
            //cekaj dok nesto ne stigne
            while (this.is.available() <= 0);
            //proveri duzinu pristiglog niza i napravi niz odgovarajuce duzine
            int len = this.is.available();
            byte[] receivedBytes = new byte[len];
            //preuzmi pristigle podatke
            this.is.read(receivedBytes);
            //dekriptuj poruku koristeci tajni AES kljuc
            ret = do_AESDecryption(receivedBytes);
            
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        return ret;
    }
    
    /**
     * Kriptuje poruku i salje ka klijentu. Prilikom slanja se koristi OutputStream 
     * kao izlazna konekcija ka datom klijentu
     * @param plainMsg nekriptovana poruka koja treba da se salje
     */
    public void encryptAndSendMessage(byte[] plainMsg){
        try {
            byte[] encryptedMsg = do_AESEncryption(plainMsg);
            
            os.write(encryptedMsg);
        } catch (Exception ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        //posalji enkriptovanu poruku koristeci OutputStream os
    }
    
    @Override
    public void run() {
        //ispratite korake iz uputstva zadatka, hand-shake izmedju klijenta i servera 
        //kao i ostale poruke koje se salju/primaju u odgovarajucem redosledu
        String stanje = "KONEKCIJA";
        byte[] receivedBytes = new byte[1];
        int len;
        String ret = new String();
        while(true){
            if(!stanje.equals("PREUZMI_RSA_KLJUC") && !stanje.equals("KONEKCIJA") && !stanje.equals("TRAZI_TIP_DATOTEKE") && !stanje.equals("PREUZMI_FAJL") && !stanje.equals("") && !stanje.equals("1")){
                try{
                    while (this.is.available() <= 0);
                    len = this.is.available();
                    receivedBytes = new byte[len];
                    this.is.read(receivedBytes);
                }
                catch(Exception ex){}
            }
            
            if(stanje.equals("")){
                byte[] rcv = receiveAndDecryptMessage();
                ret = new String(rcv);
                if(ret.equals("Exit"))
                    stanje = "DISKONEKCIJA";
                else
                    stanje = "TRAZI_TIP_DATOTEKE";
            }
            
            if(stanje.equals("1"))
                break;
            
            switch(stanje){
                case "KONEKCIJA":
                    try{
                        /*File file = new File(getPath() + "/aj.jpg");
                        FileInputStream fis = new FileInputStream(getPath() + "/aj.jpg");
                        String m = file.length() + "";
                        byte[] b = new byte[Integer.parseInt(m)];
                        fis.read(b, 0, (int)file.length());
                        os.write(b);*/
                    }
                    catch(Exception ex){}
                    stanje = "PREUZMI_RSA_KLJUC";
                    break;
                case "PREUZMI_RSA_KLJUC":
                    try{
                        os.write(publicKeyRSA.getEncoded());
                    }
                    catch(Exception ex){
                        ex.printStackTrace();
                    }
                    stanje = "SALJI_AES_KLJUC_I_INIT_VECTOR";
                    break;
                case "SALJI_AES_KLJUC_I_INIT_VECTOR":
                    try{
                        decryptSecretKeyAES(receivedBytes);
                        os.write("Server: AESKey received!".getBytes());
                        
                        while (this.is.available() <= 0);
                        len = this.is.available();
                        receivedBytes = new byte[len];
                        this.is.read(receivedBytes);
                        
                        decryptInitializationVector(receivedBytes);
                        os.write("Server: InitializationVector received!".getBytes());
                    }
                    catch(Exception ex){
                        ex.printStackTrace();
                    }
                    stanje = "";
                    break;
                case "TRAZI_TIP_DATOTEKE":
                    try{
                        //byte[] msg = receiveAndDecryptMessage();
                        //String ext = new String(msg);
                        String ext = ret.split("=")[1];
                        File file = new File(getPath());
                        String[] names;
                        
                        if(!ext.equals("All")){
                            names = file.list(new FilenameFilter() {
                                @Override
                                public boolean accept(File dir, String name) {
                                    return name.endsWith("."+ext); //To change body of generated methods, choose Tools | Templates.
                                }
                            });
                        }
                        else
                            names = file.list();
                        
                        String m = new String();
                        for(int i = 0;i < names.length;i++){
                            if(i != names.length-1)
                                m += names[i] + "=";
                            else
                                m += names[i];
                        }
                        
                        String mm = names.length + "=" + m;
                        
                        encryptAndSendMessage(mm.getBytes());
                    }
                    catch(Exception ex){}
                    stanje = "PREUZMI_FAJL";
                    break;
                case "PREUZMI_FAJL":
                    try{
                        byte[] msg = receiveAndDecryptMessage();
                        String ext = new String(msg);
                        String fileName = ext.split("=")[1];
                        File file = new File(getPath() + "/" + fileName);
                        FileInputStream fis = new FileInputStream(getPath() + "/" + fileName);
                        String m = file.length() + "";
                        byte[] b = new byte[Integer.parseInt(m)];
                        fis.read(b, 0, (int)file.length());
                        Thread.sleep(100);
                        //os.write(b);
                        encryptAndSendMessage(b);
                        fis.close();
                    }
                    catch(Exception ex){}
                    stanje = "";
                    break;
                case "DISKONEKCIJA":
                    try{
                        is.close();
                        os.close();
                        socket.close();
                    }
                    catch(Exception ex){}
                    stanje = "1";
                    break;
                default:
            }
        }
        
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
