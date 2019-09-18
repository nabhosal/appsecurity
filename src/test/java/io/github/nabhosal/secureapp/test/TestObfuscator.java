package io.github.nabhosal.secureapp.test;

import io.github.nabhosal.secureapp.utils.Obfuscator;
import org.junit.Test;

public class TestObfuscator {

    @Test
    public void basicWorking(){
        String originalString = "You important data stuffs";
        String obfuscatedCode = Obfuscator.getObfuscatedCode(originalString);
        System.out.println("obfuscatedCode "+obfuscatedCode);
        System.out.println((new Object() {int t;public String toString() {byte[] buf = new byte[25];t = 1798417526;buf[0] = (byte) (t >>> 21);t = -1469090647;buf[1] = (byte) (t >>> 16);t = 647452009;buf[2] = (byte) (t >>> 12);t = 1305598083;buf[3] = (byte) (t >>> 2);t = 1887902320;buf[4] = (byte) (t >>> 6);t = 2092346784;buf[5] = (byte) (t >>> 15);t = 461827047;buf[6] = (byte) (t >>> 19);t = -893923851;buf[7] = (byte) (t >>> 15);t = 1036931249;buf[8] = (byte) (t >>> 13);t = 1679626480;buf[9] = (byte) (t >>> 14);t = -793421756;buf[10] = (byte) (t >>> 6);t = -1516605780;buf[11] = (byte) (t >>> 8);t = -1794732407;buf[12] = (byte) (t >>> 5);t = -1810751407;buf[13] = (byte) (t >>> 8);t = -1504918460;buf[14] = (byte) (t >>> 20);t = -983341539;buf[15] = (byte) (t >>> 4);t = 1956087314;buf[16] = (byte) (t >>> 24);t = 1573347680;buf[17] = (byte) (t >>> 8);t = 1208807218;buf[18] = (byte) (t >>> 22);t = -2140243865;buf[19] = (byte) (t >>> 13);t = 2126139430;buf[20] = (byte) (t >>> 15);t = -581337316;buf[21] = (byte) (t >>> 22);t = 1715615834;buf[22] = (byte) (t >>> 24);t = -1285320308;buf[23] = (byte) (t >>> 23);t = 1936102500;buf[24] = (byte) (t >>> 24);return new String(buf);}}.toString()));

    }
}
