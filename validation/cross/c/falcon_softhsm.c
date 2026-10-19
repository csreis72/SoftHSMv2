/*****************************************************************************
 falcon_softhsm.c

 Lado SoftHSM da validação cruzada do Falcon.

 Uso:
   falcon_softhsm sign   <512|1024> <mensagem> <chave pública (saída)> <assinatura (saída)>
   falcon_softhsm verify <512|1024> <mensagem> <chave pública> <assinatura>

 sign:   gera um par de chaves no token, assina a mensagem e exporta a chave
         pública e a assinatura.
 verify: importa a chave pública gerada pelo Bouncy Castle e verifica a
         assinatura. Retorna RESULT_OK se ela for válida e RESULT_INVALID se
         for rejeitada.

 Os arquivos usam os formatos brutos da especificação do Falcon: chave
 pública de 897 ou 1793 bytes e assinatura compactada de tamanho variável.
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include "p11.h"

#define MAX_MESSAGE_LENGTH    4096
#define MAX_PUBLIC_KEY_LENGTH 1793  /* Falcon-1024 */
#define MAX_SIGNATURE_LENGTH  1462  /* Falcon-1024 */

static int parse_parameter_set(const char* variant, CK_ULONG* parameterSet)
{
	if (strcmp(variant, "512") == 0)
		*parameterSet = CKP_FALCON_512;
	else if (strcmp(variant, "1024") == 0)
		*parameterSet = CKP_FALCON_1024;
	else
		return 0;
	return 1;
}

static int sign(CK_SESSION_HANDLE session, CK_ULONG parameterSet,
	const char* messagePath, const char* publicKeyPath, const char* signaturePath)
{
	CK_MECHANISM keyGenMechanism = { CKM_FALCON_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_MECHANISM signMechanism = { CKM_FALCON, NULL_PTR, 0 };
	CK_BBOOL yes = CK_TRUE;
	CK_ATTRIBUTE publicTemplate[] = {
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) }
	};
	CK_ATTRIBUTE privateTemplate[] = {
		{ CKA_SIGN, &yes, sizeof(yes) }
	};
	CK_OBJECT_HANDLE publicKey;
	CK_OBJECT_HANDLE privateKey;
	CK_BYTE message[MAX_MESSAGE_LENGTH];
	CK_ULONG messageLength;
	CK_BYTE signature[MAX_SIGNATURE_LENGTH];
	CK_ULONG signatureLength = sizeof(signature);
	CK_BYTE publicValue[MAX_PUBLIC_KEY_LENGTH];
	CK_ATTRIBUTE publicValueAttribute = { CKA_VALUE, publicValue, sizeof(publicValue) };

	if (!read_file(messagePath, message, sizeof(message), &messageLength))
		return RESULT_ERROR;

	/* As chaves são objetos de sessão: deixam de existir ao fechar a sessão. */
	if (!p11_check("C_GenerateKeyPair", p11->C_GenerateKeyPair(session,
		&keyGenMechanism,
		publicTemplate, sizeof(publicTemplate) / sizeof(CK_ATTRIBUTE),
		privateTemplate, sizeof(privateTemplate) / sizeof(CK_ATTRIBUTE),
		&publicKey, &privateKey)))
		return RESULT_ERROR;

	if (!p11_check("C_SignInit", p11->C_SignInit(session, &signMechanism, privateKey)) ||
		!p11_check("C_Sign", p11->C_Sign(session, message, messageLength,
			signature, &signatureLength)))
		return RESULT_ERROR;

	if (!p11_check("C_GetAttributeValue", p11->C_GetAttributeValue(session,
		publicKey, &publicValueAttribute, 1)))
		return RESULT_ERROR;

	if (!write_file(publicKeyPath, publicValue, publicValueAttribute.ulValueLen) ||
		!write_file(signaturePath, signature, signatureLength))
		return RESULT_ERROR;
	return RESULT_OK;
}

static int verify(CK_SESSION_HANDLE session, CK_ULONG parameterSet,
	const char* messagePath, const char* publicKeyPath, const char* signaturePath)
{
	CK_MECHANISM verifyMechanism = { CKM_FALCON, NULL_PTR, 0 };
	CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_FALCON;
	CK_BBOOL yes = CK_TRUE;
	CK_BYTE publicValue[MAX_PUBLIC_KEY_LENGTH];
	CK_ULONG publicValueLength;
	CK_BYTE message[MAX_MESSAGE_LENGTH];
	CK_ULONG messageLength;
	CK_BYTE signature[MAX_SIGNATURE_LENGTH];
	CK_ULONG signatureLength;
	CK_OBJECT_HANDLE publicKey;
	CK_RV rv;

	if (!read_file(messagePath, message, sizeof(message), &messageLength) ||
		!read_file(publicKeyPath, publicValue, sizeof(publicValue), &publicValueLength) ||
		!read_file(signaturePath, signature, sizeof(signature), &signatureLength))
		return RESULT_ERROR;

	/* Importa a chave pública do Bouncy Castle como objeto de sessão. */
	CK_ATTRIBUTE publicTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_VALUE, publicValue, publicValueLength }
	};
	if (!p11_check("C_CreateObject", p11->C_CreateObject(session,
		publicTemplate, sizeof(publicTemplate) / sizeof(CK_ATTRIBUTE),
		&publicKey)))
		return RESULT_ERROR;

	if (!p11_check("C_VerifyInit", p11->C_VerifyInit(session, &verifyMechanism, publicKey)))
		return RESULT_ERROR;
	rv = p11->C_Verify(session, message, messageLength, signature, signatureLength);
	if (rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE)
		return RESULT_INVALID;
	if (!p11_check("C_Verify", rv))
		return RESULT_ERROR;
	return RESULT_OK;
}

int main(int argc, char* argv[])
{
	CK_ULONG parameterSet;
	CK_SESSION_HANDLE session;
	int result;

	if (argc != 6 ||
		(strcmp(argv[1], "sign") != 0 && strcmp(argv[1], "verify") != 0) ||
		!parse_parameter_set(argv[2], &parameterSet))
	{
		fprintf(stderr,
			"Uso: %s sign   <512|1024> <mensagem> <chave pública (saída)> <assinatura (saída)>\n"
			"     %s verify <512|1024> <mensagem> <chave pública> <assinatura>\n",
			argv[0], argv[0]);
		return RESULT_ERROR;
	}

	session = p11_open_session();
	if (session == CK_INVALID_HANDLE)
		return RESULT_ERROR;

	if (strcmp(argv[1], "sign") == 0)
		result = sign(session, parameterSet, argv[3], argv[4], argv[5]);
	else
		result = verify(session, parameterSet, argv[3], argv[4], argv[5]);

	p11_close_session(session);
	return result;
}
