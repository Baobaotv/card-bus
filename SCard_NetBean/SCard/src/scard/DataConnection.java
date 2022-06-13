/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package scard;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
/**
 *
 * @author Admin
 */
public class DataConnection {
    private static Connection con;

    private static String DB_URL = "jdbc:mysql://localhost:3306/buscard?useSSL=false";
    private static String USER_NAME = "root";
    private static String PASSWORD = "123456";
 
    public static void main(String args[]) {
        try {
            Connection conn = getConnection();
            // crate statement
            Long id ;
           StringBuilder sql=new StringBuilder("insert into info (hoten , ngaysinh, pin, avatar");
		sql.append(") values (?, ?, ?, ?)");
		id = insert(sql.toString(),  "Nguyen van ba","29/11/2001","123123",null);
                System.out.println("SAVE successfully!");
                 System.out.println(id);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    public static Long save(info info) {
        Long id ;
        String avatar = "";
        if (info.getAvatar()!= null && info.getAvatar().length != 0) {
            avatar = info.getAvatar().toString();
             System.out.println("CHUOI AVATER"+ avatar);
        }
           StringBuilder sql=new StringBuilder("insert into info (hoten , ngaysinh, pin, avatar");
		sql.append(") values (?, ?, ?, ?)");
		id = insert(sql.toString(),  info.getHoten(),info.getNgaysinh(),info.getPin(),avatar);
                System.out.println("SAVE successfully!"+ id);
        return id;
    }

    public static Connection getConnection() {
        Connection conn = null;
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection(DB_URL, USER_NAME, PASSWORD);
            System.out.println("connect successfully!");
        } catch (Exception ex) {
            System.out.println("connect failure!");
            ex.printStackTrace();
        }
        return conn;
    }
    
    public static Long insert(String sql, Object... parameter) {
		Connection connection = null;
		PreparedStatement statement = null;
		ResultSet resultSet = null;
		Long id = null;
		try {
			connection = getConnection();
			connection.setAutoCommit(false);
			statement = connection.prepareStatement(sql, statement.RETURN_GENERATED_KEYS);
			setParameter(statement, parameter);
			statement.executeUpdate();
			resultSet = statement.getGeneratedKeys();
			if (resultSet.next()) {
				id = resultSet.getLong(1);
			}
			connection.commit();
			return id;
		} catch (SQLException e) {
			try {
				connection.rollback();
				return null;
			} catch (SQLException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			// TODO: handle exception
		} finally {
			try { // đóng các hàm lại
				connection.close();
				resultSet.close();
				statement.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
    
    public static void setParameter(PreparedStatement statement, Object... parameters) {
		try {
			for (int i = 0; i < parameters.length; i++) {
				Object parameter = parameters[i];
				int index = i + 1;
				if (parameter instanceof Long)
					statement.setLong(index, (long) parameter);
				else {
					if (parameter instanceof String)
						statement.setString(index, (String) parameter);
					else if (parameter instanceof Integer)
						statement.setInt(index, (Integer) parameter);
					else if (parameter == null)
						statement.setNull(index, Types.NULL);
				}
			}
		} catch (Exception e) {
		}
	}
}
