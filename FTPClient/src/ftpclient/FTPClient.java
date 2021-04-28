package ftpclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom; 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JOptionPane;
import javax.swing.text.BadLocationException;



/**
 *
 * @author pedja
 */
public class FTPClient extends javax.swing.JFrame {
    
    private ServerConfiguration serverConfiguration;
    
    //socket, is i os se koriste u komunikaciji sa serverom
    private Socket socket;
    private InputStream is;
    private OutputStream os;
    
    //atributi koji se koriste za enkripciju/dekripciju
    private SecretKey secretKeyAES;
    private byte[] initializationVector;
    private PublicKey serverPublicKeyRSA;
    private Cipher AESCipher;
    private Cipher RSACipher;

    /*
    Getters and setters
    */
    public PublicKey getServerPublicKeyRSA() {
        return serverPublicKeyRSA;
    }

    public void setServerPublicKeyRSA(PublicKey serverPublicKeyRSA) {
        this.serverPublicKeyRSA = serverPublicKeyRSA;
    }

   
    public SecretKey getSecretKeyAES() {
        return secretKeyAES;
    }

    public void setSecretKeyAES(SecretKey secretKeyAES) {
        this.secretKeyAES = secretKeyAES;
    }

    /**
     * Konstruktor FTPClient klase
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     */
    public FTPClient() {
        initComponents();
        serverConfiguration = new ServerConfiguration();
        serverConfiguration.setVisible(false);
        try {
            RSACipher = Cipher.getInstance("RSA");
            AESCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    /**
     * Funkcija generise tajni kljuc za AES enkripciju
     * @return generisani AES SecretKey 
     */
    public SecretKey createAESKey() throws Exception {
        //Koristite objekte SecureRandom i KeyGenerator klase
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        
        //kod init metode na objektu KeyGenerator klase postaviti da je duzina kljuca 128
        keyGenerator.init(128, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        
        return key;//samo da se ne bi bunio kompajler
    }
    
    /**
     * Napravi inicijalizacioni vektor potreban za simetricnu enkripciju
     * i dodali ga atributu initializationVector
     */
    public void createInitializationVector()
    {
        //Koristite objekat SecureRandom klase da bi generisali inicijalizacioni vektor
        initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        
        //postavite initializationVector kao referencu na generisani inicijalizacioni vektor
        secureRandom.nextBytes(initializationVector);
    }    
    
    /**
     * Na osnovu niza bajtova dobijenih od servera, napravi PublicKey za RSA
     * i dodeli ga atributu serverPublicRSAKey
     * @param keyBytes niz bajtova poslatih od strane servera
     */
    public void createServerPublicRSAKey(byte[] keyBytes) throws Exception{
        //Koristite klase X509EncodedKeySpec i KeyFactory kako biste iz keyBytes 
        //generisali serverPublicRSAKey
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        serverPublicKeyRSA = kf.generatePublic(spec);
    }
    
    /**
     * Enkriptuj skriveni kljuc za AES (prethodno kreiran) koristeci javni kljuc
     * za RSA dobijen od servera i vrati ga kao niz bajtova, 
     * kako bi se mogli proslediti serveru
     * @return enkriptovan skriveni kljuc za AES, kao niz bajtova
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException 
     */
    public byte[] encryptKeyRSA() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        //inicijalizuj RSACipher u modu Cipher.ENCRYPT_MODE koristeci publicKeyRSA
        RSACipher.init(Cipher.ENCRYPT_MODE, serverPublicKeyRSA);
        
        //vrati secretKeyAES enkriptovan pomocu RSACipher
        return RSACipher.doFinal(secretKeyAES.getEncoded());//samo da se ne bi bunio kompajler
    }    

    /**
     * Enkriptuj inicijalizacioni vektor za AES (prethodno kreiran) koristeci javni kljuc
     * za RSA dobijen od servera i vrati ga kao niz bajtova, kako bi se mogli proslediti serveru
     * Inicijalizacioni vektor bi se mogao slati i nekriptovan, ali kad vec imamo
     * javni RSA kljuc, koristicemo njega da kriptujemo i IV
     * @return enkriptovan inicijalizacioni vektor za AES, kao niz bajtova
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException 
     */
    
    public byte[] encryptInitializationVector() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException{     
        //inicijalizuj RSACipher u modu Cipher.ENCRYPT_MODE koristeci publicKeyRSA
        RSACipher.init(Cipher.ENCRYPT_MODE, serverPublicKeyRSA);
        
        //vrati initializationVector enkriptovan pomocu RSACipher  
        return RSACipher.doFinal(initializationVector);//samo da se ne bi bunio kompajler
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
        AESCipher.init(Cipher.ENCRYPT_MODE, secretKeyAES, ivParameterSpec);
  
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
     * Prima niz bajtova od servera i dekriptuje ih koristeci tajni AES kljuc
     * @return dekriptovani niz bajtova
     */
    public byte[] receiveAndDecryptMessage(){
        byte[] ret = null;
        try {
            //dodato
            is = socket.getInputStream();
            
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
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        return ret;
    }
    
    /**
     * Kriptuje poruku i salje ka serveru. Prilikom slanja se koristi OutputStream 
     * kao izlazna konekcija ka serveru
     * @param plainMsg nekriptovana poruka koja treba da se salje
     */
    public void encryptAndSendMessage(byte[] plainMsg){
        try {
            byte[] encryptedMsg = do_AESEncryption(plainMsg);
            
            os = socket.getOutputStream();
            os.write(encryptedMsg);
        } catch (Exception ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        //posalji enkriptovanu poruku koristeci OutputStream os
    }
    
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jMenuItem1 = new javax.swing.JMenuItem();
        jCheckBoxMenuItem1 = new javax.swing.JCheckBoxMenuItem();
        lDostupneDatoteke = new javax.swing.JLabel();
        spDatoteke = new javax.swing.JScrollPane();
        taDatoteke = new javax.swing.JTextArea();
        spSadrzajDatoteke = new javax.swing.JScrollPane();
        taSadrzajDatoteke = new javax.swing.JTextArea();
        lSadrzajDatoteke = new javax.swing.JLabel();
        cbTipoviDatoteka = new javax.swing.JComboBox<>();
        btnTraziDatoteke = new javax.swing.JButton();
        btnPreuzmiDatoteku = new javax.swing.JButton();
        lSacuvajNaPutanji = new javax.swing.JLabel();
        tfSacuvajNaPutanji = new javax.swing.JTextField();
        btnPretrazi = new javax.swing.JButton();
        btnKonekcija = new javax.swing.JButton();
        btnSaljiKljucIV = new javax.swing.JButton();
        btnPreuzmiKljuc = new javax.swing.JButton();
        btnDiskonekcija = new javax.swing.JButton();
        jMenuBar1 = new javax.swing.JMenuBar();
        mKonfiguracija = new javax.swing.JMenu();
        miServer = new javax.swing.JMenuItem();
        mOpcije = new javax.swing.JMenu();
        miPrikazDatoteke = new javax.swing.JCheckBoxMenuItem();
        miIzlaz = new javax.swing.JMenuItem();

        jMenuItem1.setText("jMenuItem1");

        jCheckBoxMenuItem1.setSelected(true);
        jCheckBoxMenuItem1.setText("jCheckBoxMenuItem1");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("FTP klijent");

        lDostupneDatoteke.setText("Spisak dostupnih datoteka:");
        lDostupneDatoteke.setEnabled(false);

        taDatoteke.setEditable(false);
        taDatoteke.setColumns(20);
        taDatoteke.setRows(5);
        taDatoteke.setEnabled(false);
        taDatoteke.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                taDatotekeMouseClicked(evt);
            }
        });
        spDatoteke.setViewportView(taDatoteke);

        taSadrzajDatoteke.setColumns(20);
        taSadrzajDatoteke.setRows(5);
        taSadrzajDatoteke.setEnabled(false);
        spSadrzajDatoteke.setViewportView(taSadrzajDatoteke);

        lSadrzajDatoteke.setText("Sadrzaj primljene datoteke:");
        lSadrzajDatoteke.setEnabled(false);

        cbTipoviDatoteka.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "All", "txt", "pdf", "jpeg" }));
        cbTipoviDatoteka.setEnabled(false);

        btnTraziDatoteke.setText("Trazi");
        btnTraziDatoteke.setEnabled(false);

        btnPreuzmiDatoteku.setText("Preuzmi datoteku");
        btnPreuzmiDatoteku.setEnabled(false);

        lSacuvajNaPutanji.setText("Sacuvaj na putanji:");
        lSacuvajNaPutanji.setEnabled(false);

        tfSacuvajNaPutanji.setEnabled(false);

        btnPretrazi.setText("Pretrazi");
        btnPretrazi.setEnabled(false);

        btnKonekcija.setText("Konektuj se");
        btnKonekcija.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnKonekcijaActionPerformed(evt);
            }
        });

        btnSaljiKljucIV.setText("Salji AES kljuc");
        btnSaljiKljucIV.setEnabled(false);
        btnSaljiKljucIV.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSaljiKljucIVActionPerformed(evt);
            }
        });

        btnPreuzmiKljuc.setText("Preuzmi RSA kljuc");
        btnPreuzmiKljuc.setEnabled(false);
        btnPreuzmiKljuc.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPreuzmiKljucActionPerformed(evt);
            }
        });

        btnDiskonekcija.setText("Diskonektuj se");
        btnDiskonekcija.setEnabled(false);

        mKonfiguracija.setText("Konfiguracija");

        miServer.setText("Server");
        miServer.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miServerActionPerformed(evt);
            }
        });
        mKonfiguracija.add(miServer);

        jMenuBar1.add(mKonfiguracija);

        mOpcije.setText("Opcije");

        miPrikazDatoteke.setSelected(true);
        miPrikazDatoteke.setText("Prikaz datoteke");
        mOpcije.add(miPrikazDatoteke);

        miIzlaz.setText("Izlaz");
        mOpcije.add(miIzlaz);

        jMenuBar1.add(mOpcije);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(spDatoteke, javax.swing.GroupLayout.PREFERRED_SIZE, 271, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(lDostupneDatoteke))
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(btnKonekcija)
                                .addComponent(btnTraziDatoteke, javax.swing.GroupLayout.PREFERRED_SIZE, 86, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(18, 18, 18)
                                    .addComponent(btnPreuzmiDatoteku, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(39, 39, 39)
                                    .addComponent(btnDiskonekcija)))))
                    .addComponent(cbTipoviDatoteka, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(spSadrzajDatoteke, javax.swing.GroupLayout.DEFAULT_SIZE, 454, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(lSacuvajNaPutanji)
                        .addGap(4, 4, 4)
                        .addComponent(tfSacuvajNaPutanji))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnPretrazi, javax.swing.GroupLayout.PREFERRED_SIZE, 142, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lSadrzajDatoteke)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(55, 55, 55)
                                .addComponent(btnPreuzmiKljuc)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(btnSaljiKljucIV)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lDostupneDatoteke)
                    .addComponent(lSadrzajDatoteke))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(spSadrzajDatoteke, javax.swing.GroupLayout.DEFAULT_SIZE, 278, Short.MAX_VALUE)
                    .addComponent(spDatoteke))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cbTipoviDatoteka, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lSacuvajNaPutanji)
                    .addComponent(tfSacuvajNaPutanji, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnTraziDatoteke)
                    .addComponent(btnPreuzmiDatoteku)
                    .addComponent(btnPretrazi))
                .addGap(34, 34, 34)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnKonekcija)
                    .addComponent(btnSaljiKljucIV)
                    .addComponent(btnPreuzmiKljuc)
                    .addComponent(btnDiskonekcija))
                .addContainerGap(34, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void miServerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miServerActionPerformed
        // TODO add your handling code here:
        //this.serverConfiguration.setIPAdresaServera("");
        //this.serverConfiguration.setPortServera(0);
        //this.serverConfiguration.resetTextFields();
        this.serverConfiguration.setVisible(true);
    }//GEN-LAST:event_miServerActionPerformed

    private void btnKonekcijaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnKonekcijaActionPerformed
        // TODO add your handling code here:
        if(serverConfiguration.getIPAdresaServera().equals("") && serverConfiguration.getPortServera() == 0){
            JOptionPane.showMessageDialog(this, "Polja IP adresa servera i port moraju biti popunjena da bi se povezali na server. Da bi uradili to trebate otici u meni Konfiguracija i izabrati opciju Server gde cete popuniti polja.");
        }
        else{
            try{
                socket = new Socket(serverConfiguration.getIPAdresaServera(), serverConfiguration.getPortServera());
                os = socket.getOutputStream();
                os.write("KONEKCIJA".getBytes());
                JOptionPane.showMessageDialog(this, "Uspesno ste se povezali na server.");
                this.btnPreuzmiKljuc.setEnabled(true);
            }
            catch(Exception ex){
                this.btnPreuzmiKljuc.setEnabled(false);
                JOptionPane.showMessageDialog(this, "Greska prilikom povezivanja na server!\nPorverite da li ste uneli dobru IP adresu ili port!");
            }
        }
    }//GEN-LAST:event_btnKonekcijaActionPerformed

    private void taDatotekeMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_taDatotekeMouseClicked
        // TODO add your handling code here:
        int pos = this.taDatoteke.getCaretPosition();
        int linenum = -1;
        int startIndex = -1;
        int endIndex = -1;
        try {
            linenum = this.taDatoteke.getLineOfOffset(pos);
        } catch (BadLocationException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            startIndex = this.taDatoteke.getLineStartOffset(linenum);
            endIndex = this.taDatoteke.getLineEndOffset(linenum);
        } catch (BadLocationException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.taDatoteke.select(startIndex, endIndex-1);
        //selektovani tekst mozete proveriti ako uklonite komentar ispod
        //JOptionPane.showMessageDialog(this, "Selected text: " + this.taDatoteke.getSelectedText());
    }//GEN-LAST:event_taDatotekeMouseClicked

    private void btnPreuzmiKljucActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPreuzmiKljucActionPerformed
        // TODO add your handling code here:
        try{
            //kod ovog je problem ako ne stavim ponovo socket nece psolati serveru ili server ne registruje
            //socket = new Socket(serverConfiguration.getIPAdresaServera(), serverConfiguration.getPortServera());
            os = socket.getOutputStream();
            os.write("PREUZMI_RSA_KLJUC".getBytes());
            
            is = socket.getInputStream();
            while (this.is.available() <= 0);
            int len = this.is.available();
            byte[] receivedBytes = new byte[len];
            this.is.read(receivedBytes);
            
            createServerPublicRSAKey(receivedBytes);
            JOptionPane.showMessageDialog(this, "Server Public RSA key primljen!");
            this.btnSaljiKljucIV.setEnabled(true);
        }
        catch(Exception ex){}
    }//GEN-LAST:event_btnPreuzmiKljucActionPerformed

    private void btnSaljiKljucIVActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSaljiKljucIVActionPerformed
        // TODO add your handling code here:
        /*try{
           socket = new Socket(serverConfiguration.getIPAdresaServera(), serverConfiguration.getPortServera());
           secretKeyAES = createAESKey();
           byte[] secretKey = encryptKeyRSA();
           os = socket.getOutputStream();
           os.write("SALJI_AES_KLJUC".getBytes());
           
           
           is = socket.getInputStream();
           while (this.is.available() <= 0);
           int len = this.is.available();
           byte[] receivedBytes = new byte[len];
           this.is.read(receivedBytes);
           
           //JOptionPane.showMessageDialog(this, "Server Public RSA key primljen!");
        }
        catch(Exception ex){}*/
    }//GEN-LAST:event_btnSaljiKljucIVActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new FTPClient().setVisible(true);
            }
        });
    }
    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnDiskonekcija;
    private javax.swing.JButton btnKonekcija;
    private javax.swing.JButton btnPretrazi;
    private javax.swing.JButton btnPreuzmiDatoteku;
    private javax.swing.JButton btnPreuzmiKljuc;
    private javax.swing.JButton btnSaljiKljucIV;
    private javax.swing.JButton btnTraziDatoteke;
    private javax.swing.JComboBox<String> cbTipoviDatoteka;
    private javax.swing.JCheckBoxMenuItem jCheckBoxMenuItem1;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JLabel lDostupneDatoteke;
    private javax.swing.JLabel lSacuvajNaPutanji;
    private javax.swing.JLabel lSadrzajDatoteke;
    private javax.swing.JMenu mKonfiguracija;
    private javax.swing.JMenu mOpcije;
    private javax.swing.JMenuItem miIzlaz;
    private javax.swing.JCheckBoxMenuItem miPrikazDatoteke;
    private javax.swing.JMenuItem miServer;
    private javax.swing.JScrollPane spDatoteke;
    private javax.swing.JScrollPane spSadrzajDatoteke;
    private javax.swing.JTextArea taDatoteke;
    private javax.swing.JTextArea taSadrzajDatoteke;
    private javax.swing.JTextField tfSacuvajNaPutanji;
    // End of variables declaration//GEN-END:variables
}
