/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package scard;

import java.util.Arrays;
import javax.swing.JOptionPane;

/**
 *
 * @author Long
 */
public class updatePIN extends javax.swing.JFrame {
    private theBus thebus;
    /**
     * Creates new form updatePIN
     */
    public updatePIN() {
        this.thebus = BusForm.thebus;
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        txt_pinnow = new javax.swing.JPasswordField();
        txt_newpin = new javax.swing.JPasswordField();
        txt_checknewpin = new javax.swing.JPasswordField();
        btn_changePIN = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setResizable(false);

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        jLabel1.setText("Thay đổi mã PIN");

        jLabel2.setText("Mã PIN:");

        jLabel3.setText("Mã PIN mới:");

        btn_changePIN.setText("OK");
        btn_changePIN.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_changePINActionPerformed(evt);
            }
        });

        jLabel4.setText("Nhập lại mã PIN mới:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(43, 43, 43)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addGap(83, 83, 83)
                                .addComponent(txt_pinnow, javax.swing.GroupLayout.PREFERRED_SIZE, 188, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel3)
                                .addGap(62, 62, 62)
                                .addComponent(txt_newpin, javax.swing.GroupLayout.PREFERRED_SIZE, 188, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel4)
                                .addGap(18, 18, 18)
                                .addComponent(txt_checknewpin, javax.swing.GroupLayout.PREFERRED_SIZE, 188, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(132, 132, 132)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 134, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(146, 146, 146)
                        .addComponent(btn_changePIN, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(48, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(11, 11, 11)
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(27, 27, 27)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txt_pinnow, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txt_newpin, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addGap(26, 26, 26)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txt_checknewpin, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 28, Short.MAX_VALUE)
                .addComponent(btn_changePIN)
                .addGap(29, 29, 29))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btn_changePINActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_changePINActionPerformed
        String pin = Arrays.toString(txt_pinnow.getPassword());
        byte[] cmd = {(byte) 0xA0, (byte) 0x19, (byte) 0x00, (byte) 0x00};
        byte[] pindata = pin.getBytes();
        thebus.sendAPDUtoApplet(cmd, pindata);
        byte[] dataRes = thebus.resAPDU.getData();
        if(dataRes[0] == (byte)0x00) JOptionPane.showMessageDialog(this,"Mã PIN sai. Vui lòng nhập lại.");
        else if (dataRes[0] == (byte)0x01) {
            byte[] cmd2 = {(byte) 0xA0, (byte) 0x15, (byte) 0x00, (byte) 0x00};
            String newPIN = Arrays.toString(txt_newpin.getPassword());
            String checkpin = Arrays.toString(txt_checknewpin.getPassword());
            if(newPIN.equals(pin) == true) JOptionPane.showMessageDialog(this, "Mã PIN mới phải khác mã PIN cũ");
            else if (newPIN.length() <18 || newPIN.length() >44){
                JOptionPane.showMessageDialog(this, "độ dài PIN từ 6-32 ký tự.");
            }else if((newPIN.equals(checkpin)) != true) {
                JOptionPane.showMessageDialog(this, "Xác nhận mã pin sai");
            }else{
                byte[] data= newPIN.getBytes();
                thebus.sendAPDUtoApplet(cmd2,data);
                byte[] Res = thebus.resAPDU.getData();
                if(Res[0] == 0x01){
                    JOptionPane.showMessageDialog(this, "Thay đổi PIN thành công.");
                    txt_newpin.setText("");
                    txt_checknewpin.setText("");
                    txt_pinnow.setText("");
                    setVisible(false);
                }
                else JOptionPane.showMessageDialog(this, "Thay đổi PIN không thành công.");
            }
        }else JOptionPane.showMessageDialog(this, "Bạn đã nhập sai quá số lần cho phép. Thẻ đã bị khóa!");
    }//GEN-LAST:event_btn_changePINActionPerformed

    /**
     * @param args the command line arguments
     */
    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btn_changePIN;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPasswordField txt_checknewpin;
    private javax.swing.JPasswordField txt_newpin;
    private javax.swing.JPasswordField txt_pinnow;
    // End of variables declaration//GEN-END:variables
}
