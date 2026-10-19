import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;

/**
 * Lado Bouncy Castle da validação cruzada do Falcon.
 *
 * Uso:
 *   FalconBC sign   <512|1024> <mensagem> <chave pública (saída)> <assinatura (saída)>
 *   FalconBC verify <512|1024> <mensagem> <chave pública> <assinatura>
 *
 * Os comandos e os códigos de saída são os mesmos de falcon_softhsm:
 * 0 = operação concluída ou assinatura válida, 1 = assinatura rejeitada, 2 = erro.
 */
public class FalconBC {
    static final int RESULT_OK = 0;
    static final int RESULT_INVALID = 1;
    static final int RESULT_ERROR = 2;

    public static void main(String[] args) {
        if (args.length != 5 || !(args[0].equals("sign") || args[0].equals("verify"))) {
            System.err.println("Uso: FalconBC sign   <512|1024> <mensagem> <chave pública (saída)> <assinatura (saída)>");
            System.err.println("     FalconBC verify <512|1024> <mensagem> <chave pública> <assinatura>");
            System.exit(RESULT_ERROR);
        }
        try {
            FalconParameters parameters = parseParameters(args[1]);
            Path message = Path.of(args[2]);
            Path publicKey = Path.of(args[3]);
            Path signature = Path.of(args[4]);

            if (args[0].equals("sign")) {
                sign(parameters, message, publicKey, signature);
                System.exit(RESULT_OK);
            } else {
                boolean valid = verify(parameters, message, publicKey, signature);
                System.exit(valid ? RESULT_OK : RESULT_INVALID);
            }
        } catch (Exception e) {
            System.err.println("ERRO: " + e.getMessage());
            System.exit(RESULT_ERROR);
        }
    }

    static FalconParameters parseParameters(String variant) {
        switch (variant) {
            case "512":  return FalconParameters.falcon_512;
            case "1024": return FalconParameters.falcon_1024;
            default: throw new IllegalArgumentException("use 512 ou 1024, não " + variant);
        }
    }

    static void sign(FalconParameters parameters, Path messagePath,
                     Path publicKeyPath, Path signaturePath) throws Exception {
        FalconKeyPairGenerator generator = new FalconKeyPairGenerator();
        generator.init(new FalconKeyGenerationParameters(new SecureRandom(), parameters));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        FalconSigner signer = new FalconSigner();
        signer.init(true, new ParametersWithRandom(keyPair.getPrivate(), new SecureRandom()));
        byte[] signature = signer.generateSignature(Files.readAllBytes(messagePath));

        FalconPublicKeyParameters publicKey = (FalconPublicKeyParameters) keyPair.getPublic();
        Files.write(publicKeyPath, encodePublicKey(parameters, publicKey));
        Files.write(signaturePath, signature);
    }

    static boolean verify(FalconParameters parameters, Path messagePath,
                          Path publicKeyPath, Path signaturePath) throws Exception {
        FalconPublicKeyParameters publicKey =
            decodePublicKey(parameters, Files.readAllBytes(publicKeyPath));

        FalconSigner verifier = new FalconSigner();
        verifier.init(false, publicKey);
        return verifier.verifySignature(Files.readAllBytes(messagePath),
                                        Files.readAllBytes(signaturePath));
    }

    /*
     * A chave pública do Falcon é codificada como um byte de cabeçalho
     * (0x00 + logN) seguido do polinômio h. Esse é o formato exportado pelo
     * SoftHSM; o Bouncy Castle guarda apenas h, sem o cabeçalho.
     */
    static byte header(FalconParameters parameters) {
        return (byte) parameters.getLogN();
    }

    static byte[] encodePublicKey(FalconParameters parameters, FalconPublicKeyParameters publicKey) {
        byte[] h = publicKey.getH();
        byte[] encoded = new byte[1 + h.length];
        encoded[0] = header(parameters);
        System.arraycopy(h, 0, encoded, 1, h.length);
        return encoded;
    }

    static FalconPublicKeyParameters decodePublicKey(FalconParameters parameters, byte[] encoded) {
        if (encoded.length == 0 || encoded[0] != header(parameters)) {
            throw new IllegalArgumentException("cabeçalho da chave pública não corresponde a " + parameters.getName());
        }
        return new FalconPublicKeyParameters(parameters, Arrays.copyOfRange(encoded, 1, encoded.length));
    }
}
