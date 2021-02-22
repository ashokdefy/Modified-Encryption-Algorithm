import java.math.BigInteger;

public class ModifiedBlowfishVerifier {

    public static void main(String[] args) {
            ModifiedBlowfish blowfish = new ModifiedBlowfish("12345");
            System.out.println(blowfish.encryptString(""));
            System.out.println(blowfish.encryptString("abcde"));
            System.out.println(blowfish.encryptString("abcdefghij"));
            System.out.println(blowfish.encryptString("abcdefghijklmno"));
            System.out.println(blowfish.encryptString("abcdefghijklmnopqrst"));
            System.out.println(blowfish.encryptString("abcdefghijklmnopqrstuvwxy"));

    }

}
