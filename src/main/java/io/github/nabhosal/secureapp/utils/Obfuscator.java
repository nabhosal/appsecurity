package io.github.nabhosal.secureapp.utils;

import java.util.Random;

public final class Obfuscator {

    public static String getObfuscatedCode(String string){
        Random r = new Random(System.currentTimeMillis());
        byte[] b = string.getBytes();
        int c = b.length;
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("(new Object() {");
        stringBuilder.append("int t;");
        stringBuilder.append("public String toString() {");
        stringBuilder.append("byte[] buf = new byte[");
        stringBuilder.append(c);
        stringBuilder.append("];");

        for (int i = 0; i < c; ++i) {
            int t = r.nextInt();
            int f = r.nextInt(24) + 1;

            t = (t & ~(0xff << f)) | (b[i] << f);

            stringBuilder.append("t = ");
            stringBuilder.append(t);
            stringBuilder.append(";");
            stringBuilder.append("buf[");
            stringBuilder.append(i);
            stringBuilder.append("] = (byte) (t >>> ");
            stringBuilder.append(f);
            stringBuilder.append(");");
        }

        stringBuilder.append("return new String(buf);");
        stringBuilder.append("}}.toString())");
        stringBuilder.append("\n");
        return stringBuilder.toString();
    }

}
