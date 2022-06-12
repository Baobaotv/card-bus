/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package scard;
import java.math.BigInteger;
import java.util.List;
import javax.smartcardio.*;
import javax.swing.JOptionPane;
/**
 *
 * @author hoang
 */
public class theBus {

    /**
     * @param args the command line arguments
     */
    Card card;
    CardChannel channel;
    CommandAPDU cmndAPDU;
    ResponseAPDU resAPDU;
    List<CardTerminal> terminals;
    private TerminalFactory factory;
    private CardTerminal terminal;
    public static  final byte[] AID_APPLET = {(byte)0x99, (byte)0x88, (byte)0x77,(byte)0x66,(byte)0x55,(byte)0x00};
    
    
    public theBus(){
    }
    //ket noi
    public boolean connectApplet(){
        try{
            // hiển thị danh sách các thiết bị đầu cuối có sẵn
            TerminalFactory factory = TerminalFactory.getDefault();
            terminals = factory.terminals().list();
            System.out.println("Terminals: " + terminals);
            // lấy terminal đầu tiên
            CardTerminal terminal = terminals.get(0);
            // thiết lập kết nối với thẻ
            card = terminal.connect("T=0");
            System.out.println("card: " + card);
            //  lấy ATR
            ATR atr = card.getATR();
            byte[] baAtr = atr.getBytes();
            System.out.print("ATR = 0x");
            for(int i = 0; i < baAtr.length; i++ ){
                System.out.printf("%02X ",baAtr[i]);
            }
            channel = card.getBasicChannel();
//            if(channel == null){
//                return false;
//            }
//            resAPDU = channel.transmit(new CommandAPDU(0x00 ,(byte) 0xA4, 0x04, 0x00,AID_APPLET ));
//            String check = Integer.toHexString(resAPDU.getSW());
//            if(check.equals("9000")){
//                return true;
//            }else{
//                if(check.equals("6400")){
//                    System.out.println("The bi vo hieu hoa");
//                    return true;
//                }else{
//                     System.out.println("Loi");
//                    return false;
//                }
//            }
             return true;
//            return true;
        } catch (CardException e){
            e.printStackTrace();
            return false;
    }
    }
    public void sendAPDUtoApplet(byte[] cmnds,byte[] data){
        try {
            resAPDU = channel.transmit(new CommandAPDU(cmnds[0], cmnds[1], cmnds[2], cmnds[3], data));
        } catch (CardException e) {
            e.printStackTrace();
        }
    }
    public void sendAPDUtoApplet(byte[] cmnds){
        try {
            resAPDU = channel.transmit(new CommandAPDU(cmnds[0], cmnds[1], cmnds[2], cmnds[3]));
        } catch (CardException e) {
            e.printStackTrace();
        }
    }
    public boolean disconnectApplet(){
        try {
            card.disconnect(false);
            return true;
        } catch (CardException e) {
            e.printStackTrace();
            return false;
        }
    }
    public String byteToHex(byte data) {
        StringBuilder result = new StringBuilder();
            result.append(String.format("%02x", data));
        return result.toString();
    }
    public String shorttoHex(short data) {
        StringBuilder result = new StringBuilder();
            result.append(String.format("%02x", data));
        return result.toString();
    }
    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        System.out.println("len "+len);
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
     public BigInteger getModulusPubkey() {
        try {
            factory = TerminalFactory.getDefault();
            terminals = factory.terminals().list();
            terminal = terminals.get(1);
            card = terminal.connect("T=1");
            channel = card.getBasicChannel();
            resAPDU = channel.transmit(new CommandAPDU((byte) 0xA0, (byte) 0x22, (byte) 0x01, (byte) 0x01));
            
            BigInteger res = new BigInteger(1, resAPDU.getData());
            System.out.println("responseM "+ res);
            return res;
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e);
        }
        return null;
    }
     
    public BigInteger getExponentPubkey() {
        try {
            factory = TerminalFactory.getDefault();
            terminals = factory.terminals().list();
            terminal = terminals.get(1);
            card = terminal.connect("T=1");
            channel = card.getBasicChannel();
            resAPDU = channel.transmit(new CommandAPDU((byte) 0xA0, (byte) 0x22, (byte) 0x02, (byte) 0x01));
            
            BigInteger res = new BigInteger(1, resAPDU.getData());
            System.out.println("responseE "+ res);
            return res;
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e);
        }
        return null;
    }
}
