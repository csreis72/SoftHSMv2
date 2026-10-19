/*****************************************************************************
 xwing_softhsm.c

 Lado SoftHSM da validação cruzada do X-Wing.

 Uso:
   xwing_softhsm keygen <chave pública (saída)>
   xwing_softhsm encaps <chave pública> <texto cifrado (saída)> <segredo (saída)>
   xwing_softhsm decaps <texto cifrado> <segredo (saída)>

 keygen: gera um par de chaves persistente no token e exporta a chave pública.
         A chave privada nunca sai do token.
 encaps: importa a chave pública gerada pelo Bouncy Castle e encapsula um
         segredo para ela.
 decaps: decapsula o texto cifrado com a chave privada criada por keygen.

 Os arquivos usam as codificações brutas de draft-connolly-cfrg-xwing-kem-10:
 chave pública de 1216 bytes, texto cifrado de 1120 bytes e segredo de 32 bytes.
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include "p11.h"

#define X_WING_PUBLIC_KEY_LENGTH 1216
#define X_WING_CIPHERTEXT_LENGTH 1120
#define X_WING_SECRET_LENGTH     32

static CK_MECHANISM xwingMechanism = { CKM_X_WING, NULL_PTR, 0 };
static CK_BBOOL yes = CK_TRUE;
static CK_BBOOL no = CK_FALSE;

/* Modelo do objeto que recebe o segredo compartilhado. Ele é criado
   extraível e não sensível somente para que o segredo possa ser comparado
   com o do Bouncy Castle; em uso real o segredo ficaria protegido no token. */
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE secretType = CKK_GENERIC_SECRET;
static CK_ULONG secretLength = X_WING_SECRET_LENGTH;
static CK_ATTRIBUTE secretTemplate[] = {
	{ CKA_CLASS, &secretClass, sizeof(secretClass) },
	{ CKA_KEY_TYPE, &secretType, sizeof(secretType) },
	{ CKA_VALUE_LEN, &secretLength, sizeof(secretLength) },
	{ CKA_SENSITIVE, &no, sizeof(no) },
	{ CKA_EXTRACTABLE, &yes, sizeof(yes) }
};
#define SECRET_TEMPLATE_SIZE (sizeof(secretTemplate) / sizeof(CK_ATTRIBUTE))

/* Lê o valor do segredo compartilhado e grava em arquivo. */
static int save_secret(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE secretKey,
	const char* secretPath)
{
	CK_BYTE secret[X_WING_SECRET_LENGTH];
	CK_ATTRIBUTE value = { CKA_VALUE, secret, sizeof(secret) };

	if (!p11_check("C_GetAttributeValue", p11->C_GetAttributeValue(session,
		secretKey, &value, 1)))
		return 0;
	return write_file(secretPath, secret, value.ulValueLen);
}

static int keygen(CK_SESSION_HANDLE session, const char* publicKeyPath)
{
	CK_MECHANISM keyGenMechanism = { CKM_X_WING_KEY_PAIR_GEN, NULL_PTR, 0 };
	/* Objetos de token: a chave privada precisa existir até o decaps,
	   que é executado em outro processo. */
	CK_ATTRIBUTE publicTemplate[] = {
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_ENCAPSULATE, &yes, sizeof(yes) }
	};
	CK_ATTRIBUTE privateTemplate[] = {
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_DECAPSULATE, &yes, sizeof(yes) }
	};
	CK_OBJECT_HANDLE publicKey;
	CK_OBJECT_HANDLE privateKey;
	CK_BYTE publicValue[X_WING_PUBLIC_KEY_LENGTH];
	CK_ATTRIBUTE publicValueAttribute = { CKA_VALUE, publicValue, sizeof(publicValue) };

	if (!p11_check("C_GenerateKeyPair", p11->C_GenerateKeyPair(session,
		&keyGenMechanism,
		publicTemplate, sizeof(publicTemplate) / sizeof(CK_ATTRIBUTE),
		privateTemplate, sizeof(privateTemplate) / sizeof(CK_ATTRIBUTE),
		&publicKey, &privateKey)))
		return RESULT_ERROR;

	if (!p11_check("C_GetAttributeValue", p11->C_GetAttributeValue(session,
		publicKey, &publicValueAttribute, 1)))
		return RESULT_ERROR;

	if (!write_file(publicKeyPath, publicValue, publicValueAttribute.ulValueLen))
		return RESULT_ERROR;
	return RESULT_OK;
}

static int encaps(CK_SESSION_HANDLE session, const char* publicKeyPath,
	const char* ciphertextPath, const char* secretPath)
{
	CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_X_WING;
	CK_BYTE publicValue[X_WING_PUBLIC_KEY_LENGTH];
	CK_ULONG publicValueLength;
	CK_OBJECT_HANDLE publicKey;
	CK_BYTE ciphertext[X_WING_CIPHERTEXT_LENGTH];
	CK_ULONG ciphertextLength = sizeof(ciphertext);
	CK_OBJECT_HANDLE secretKey;

	if (!read_file(publicKeyPath, publicValue, sizeof(publicValue), &publicValueLength))
		return RESULT_ERROR;

	/* Importa a chave pública do Bouncy Castle como objeto de sessão. */
	CK_ATTRIBUTE publicTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_ENCAPSULATE, &yes, sizeof(yes) },
		{ CKA_VALUE, publicValue, publicValueLength }
	};
	if (!p11_check("C_CreateObject", p11->C_CreateObject(session,
		publicTemplate, sizeof(publicTemplate) / sizeof(CK_ATTRIBUTE),
		&publicKey)))
		return RESULT_ERROR;

	if (!p11_check("C_EncapsulateKey", p11->C_EncapsulateKey(session,
		&xwingMechanism, publicKey, secretTemplate, SECRET_TEMPLATE_SIZE,
		ciphertext, &ciphertextLength, &secretKey)))
		return RESULT_ERROR;

	if (!write_file(ciphertextPath, ciphertext, ciphertextLength) ||
		!save_secret(session, secretKey, secretPath))
		return RESULT_ERROR;
	return RESULT_OK;
}

/* Localiza a chave privada X-Wing criada por keygen. O token de teste é
   novo a cada execução, portanto existe apenas uma. */
static int find_private_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* privateKey)
{
	CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_X_WING;
	CK_ATTRIBUTE searchTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_ULONG count = 0;

	if (!p11_check("C_FindObjectsInit", p11->C_FindObjectsInit(session,
		searchTemplate, sizeof(searchTemplate) / sizeof(CK_ATTRIBUTE))) ||
		!p11_check("C_FindObjects", p11->C_FindObjects(session, privateKey, 1, &count)) ||
		!p11_check("C_FindObjectsFinal", p11->C_FindObjectsFinal(session)))
		return 0;
	if (count == 0)
	{
		fprintf(stderr, "ERRO: nenhuma chave privada X-Wing no token; execute keygen antes\n");
		return 0;
	}
	return 1;
}

static int decaps(CK_SESSION_HANDLE session, const char* ciphertextPath,
	const char* secretPath)
{
	CK_OBJECT_HANDLE privateKey;
	CK_BYTE ciphertext[X_WING_CIPHERTEXT_LENGTH];
	CK_ULONG ciphertextLength;
	CK_OBJECT_HANDLE secretKey;

	if (!read_file(ciphertextPath, ciphertext, sizeof(ciphertext), &ciphertextLength) ||
		!find_private_key(session, &privateKey))
		return RESULT_ERROR;

	if (!p11_check("C_DecapsulateKey", p11->C_DecapsulateKey(session,
		&xwingMechanism, privateKey, secretTemplate, SECRET_TEMPLATE_SIZE,
		ciphertext, ciphertextLength, &secretKey)))
		return RESULT_ERROR;

	if (!save_secret(session, secretKey, secretPath))
		return RESULT_ERROR;
	return RESULT_OK;
}

int main(int argc, char* argv[])
{
	CK_SESSION_HANDLE session;
	int result;
	int isKeygen = argc == 3 && strcmp(argv[1], "keygen") == 0;
	int isEncaps = argc == 5 && strcmp(argv[1], "encaps") == 0;
	int isDecaps = argc == 4 && strcmp(argv[1], "decaps") == 0;

	if (!isKeygen && !isEncaps && !isDecaps)
	{
		fprintf(stderr,
			"Uso: %s keygen <chave pública (saída)>\n"
			"     %s encaps <chave pública> <texto cifrado (saída)> <segredo (saída)>\n"
			"     %s decaps <texto cifrado> <segredo (saída)>\n",
			argv[0], argv[0], argv[0]);
		return RESULT_ERROR;
	}

	session = p11_open_session();
	if (session == CK_INVALID_HANDLE)
		return RESULT_ERROR;

	if (isKeygen)
		result = keygen(session, argv[2]);
	else if (isEncaps)
		result = encaps(session, argv[2], argv[3], argv[4]);
	else
		result = decaps(session, argv[2], argv[3]);

	p11_close_session(session);
	return result;
}
