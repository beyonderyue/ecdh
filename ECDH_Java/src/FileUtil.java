import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;


public class FileUtil {
	private static String keyPath = null;

	public static boolean IsKeyExist(String keyPath) {
		File file = new File(keyPath);
		return file.exists();
	}

	/** * 对称加密-产生密钥 */
	public static void generatorKey(KeyPair key, String keyPath) {
		
		try { 
			// 构造输出文件,这里的目录是动态的,根据用户名称来构造目录
			ObjectOutputStream keyFile = new ObjectOutputStream(new FileOutputStream(keyPath));
			keyFile.writeObject(key);
			keyFile.close();
		} catch (IOException e4) {
			e4.printStackTrace();
			System.exit(0);
		}
	}

	/** * 对称加密-读取密钥. */
	public static KeyPair getSecretKey(String keyPath) {
		// 从密钥文件中读密钥
		KeyPair key = null;
		try {
			ObjectInputStream keyFile = new ObjectInputStream(new FileInputStream(keyPath));
			key = (KeyPair) keyFile.readObject();
			keyFile.close();
		} catch (FileNotFoundException ey1) {
			ey1.printStackTrace();
			System.exit(0);
		} catch (Exception ey2) {
			ey2.printStackTrace();
		}
		return key;
	}
}
