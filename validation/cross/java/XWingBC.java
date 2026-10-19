import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

/**
 * Lado Bouncy Castle da validação cruzada do X-Wing.
 *
 * Uso:
 *   XWingBC keygen <chave pública (saída)> <chave privada (saída)>
 *   XWingBC encaps <chave pública> <texto cifrado (saída)> <segredo (saída)>
 *   XWingBC decaps <chave privada> <texto cifrado> <segredo (saída)>
 *
 * A chave pública, o texto cifrado e o segredo usam as mesmas codificações
 * brutas do SoftHSM (draft-connolly-cfrg-xwing-kem-10). A chave privada é a
 * semente de 32 bytes da especificação; ao contrário do SoftHSM, aqui ela
 * precisa ser gravada em arquivo para ser usada no decaps.
 *
 * Código de saída: 0 = operação concluída, 2 = erro.
 */
public class XWingBC {
    static final int RESULT_OK = 0;
    static final int RESULT_ERROR = 2;

    public static void main(String[] args) {
        try {
            if (args.length == 3 && args[0].equals("keygen")) {
                keygen(Path.of(args[1]), Path.of(args[2]));
            } else if (args.length == 4 && args[0].equals("encaps")) {
                encaps(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]));
            } else if (args.length == 4 && args[0].equals("decaps")) {
                decaps(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]));
            } else {
                System.err.println("Uso: XWingBC keygen <chave pública (saída)> <chave privada (saída)>");
                System.err.println("     XWingBC encaps <chave pública> <texto cifrado (saída)> <segredo (saída)>");
                System.err.println("     XWingBC decaps <chave privada> <texto cifrado> <segredo (saída)>");
                System.exit(RESULT_ERROR);
            }
            System.exit(RESULT_OK);
        } catch (Exception e) {
            System.err.println("ERRO: " + e.getMessage());
            System.exit(RESULT_ERROR);
        }
    }

    static void keygen(Path publicKeyPath, Path privateKeyPath) throws Exception {
        XWingKeyPairGenerator generator = new XWingKeyPairGenerator();
        generator.init(new XWingKeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        XWingPublicKeyParameters publicKey = (XWingPublicKeyParameters) keyPair.getPublic();
        XWingPrivateKeyParameters privateKey = (XWingPrivateKeyParameters) keyPair.getPrivate();
        Files.write(publicKeyPath, publicKey.getEncoded());
        Files.write(privateKeyPath, privateKey.getSeed());
    }

    static void encaps(Path publicKeyPath, Path ciphertextPath, Path secretPath) throws Exception {
        XWingPublicKeyParameters publicKey =
            new XWingPublicKeyParameters(Files.readAllBytes(publicKeyPath));

        XWingKEMGenerator generator = new XWingKEMGenerator(new SecureRandom());
        SecretWithEncapsulation result = generator.generateEncapsulated(publicKey);

        Files.write(ciphertextPath, result.getEncapsulation());
        Files.write(secretPath, result.getSecret());
    }

    static void decaps(Path privateKeyPath, Path ciphertextPath, Path secretPath) throws Exception {
        XWingPrivateKeyParameters privateKey =
            new XWingPrivateKeyParameters(Files.readAllBytes(privateKeyPath));

        XWingKEMExtractor extractor = new XWingKEMExtractor(privateKey);
        byte[] secret = extractor.extractSecret(Files.readAllBytes(ciphertextPath));

        Files.write(secretPath, secret);
    }
}
