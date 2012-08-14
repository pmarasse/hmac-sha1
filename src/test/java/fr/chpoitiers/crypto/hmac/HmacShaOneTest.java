package fr.chpoitiers.crypto.hmac;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class HmacShaOneTest extends TestCase {

    private final String cle  = "mon-secret-a-personne";

    private final String cle2 = "ma clé à accents";

    private final String msg1 = "message à caractère informatif";

    private final String msg2 = "2011-01-10|username|code";

    public HmacShaOneTest(String testName) {

        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {

        return new TestSuite(HmacShaOneTest.class);
    }

    private boolean testHmac(final String in_cle, final String in_message, final String in_attendu) {

        HmacShaOne hmac = new HmacShaOne();
        hmac.setSecretKey(in_cle);
        String mac = hmac.computeHmac(in_message);

        return in_attendu.equals(mac);
    }

    /**
     * Test de la classe par rapport à des clés connues, résultats calculés depuis PHP 5.3
     */

    public void testHmacShaOne() {

        assertTrue("clé1 - msg1", testHmac(cle, msg1, "bb9ae731bb360e1baa0d651f0340a5736d022898"));
        assertTrue("clé2 - msg1", testHmac(cle2, msg1, "74cf67c53e5984e2c0bc4a35bf4dd6c79776d0e8"));
        assertTrue("clé1 - msg2", testHmac(cle, msg2, "f8d1bdc741c886df2c09020dc40433efdde937ac"));
        assertTrue("clé2 - msg2", testHmac(cle2, msg2, "6e7b87551b9b40421324134e4e3cc71cec0c0d71"));
    }

}
