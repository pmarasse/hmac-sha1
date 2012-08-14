package fr.chpoitiers.crypto.hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Classe permettant de calculer une signature de message (HMAC) en utilisant le
 * condensé SHA-1, d'une manière compatible avec la fonction hash_hmac de PHP.
 * 
 * @author Philippe MARASSE
 * @version SVN: $Id$
 * 
 */
public class HmacShaOne {

    public static final String algorithm = "HmacSHA1";

    private SecretKey          secretKey;

    /**
     * Convertit un tableau d'octets en chaine hexa affichable
     * 
     * @param bytes
     *            [] le tableau à convertir
     * @return String la chaîne convertie en héxadécimal, en minuscules.
     */
    protected String getHexString(byte[] bytes) {

        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Fixe la clé secrète à partir de la chaîne de caractères fournie
     * 
     * @param in_secret
     *            clé secrète
     */
    public void setSecretKey(String in_secret) {

        secretKey = new SecretKeySpec(in_secret.getBytes(), algorithm);
    }

    public String computeHmac(String in_message) {

        Mac hmac;
        try {
            hmac = Mac.getInstance("HmacSHA1");
            hmac.init(secretKey);
            return getHexString(hmac.doFinal(in_message.getBytes()));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
        return null;
    }

}
