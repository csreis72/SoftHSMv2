/*****************************************************************************
 p11.c

 Implementação das funções comuns descritas em p11.h.
 *****************************************************************************/

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"

#define MAX_SLOTS 16

CK_FUNCTION_LIST_3_2_PTR p11 = NULL_PTR;
static void* module = NULL;

int p11_check(const char* function, CK_RV rv)
{
	if (rv == CKR_OK) return 1;
	fprintf(stderr, "ERRO: %s falhou: rv = 0x%08lX\n", function, rv);
	return 0;
}

static const char* require_env(const char* name)
{
	const char* value = getenv(name);

	if (value == NULL || value[0] == '\0')
	{
		fprintf(stderr, "ERRO: defina a variável de ambiente %s\n", name);
		return NULL;
	}
	return value;
}

/* Carrega o módulo e obtém a interface PKCS#11 3.2, que inclui as
   funções de encapsulamento usadas pelo X-Wing. */
static int load_module(const char* path)
{
	CK_C_GetInterface getInterface;
	CK_INTERFACE_PTR interface = NULL_PTR;
	CK_VERSION version = { 3, 2 };

	module = dlopen(path, RTLD_NOW);
	if (module == NULL)
	{
		fprintf(stderr, "ERRO: não foi possível carregar %s: %s\n", path, dlerror());
		return 0;
	}
	getInterface = (CK_C_GetInterface)dlsym(module, "C_GetInterface");
	if (getInterface == NULL)
	{
		fprintf(stderr, "ERRO: o módulo não exporta C_GetInterface\n");
		return 0;
	}
	if (!p11_check("C_GetInterface",
		getInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface, 0)))
		return 0;
	p11 = (CK_FUNCTION_LIST_3_2_PTR)interface->pFunctionList;
	return 1;
}

/* Procura o slot cujo token tem o rótulo informado. No PKCS#11 o rótulo
   ocupa 32 bytes e é completado com espaços. */
static int find_slot(const char* label, CK_SLOT_ID* slot)
{
	CK_SLOT_ID slots[MAX_SLOTS];
	CK_ULONG count = MAX_SLOTS;
	CK_TOKEN_INFO info;
	char paddedLabel[sizeof(info.label)];
	size_t labelLength = strlen(label);
	CK_ULONG i;

	if (labelLength > sizeof(paddedLabel))
	{
		fprintf(stderr, "ERRO: rótulo do token com mais de 32 bytes\n");
		return 0;
	}
	memset(paddedLabel, ' ', sizeof(paddedLabel));
	memcpy(paddedLabel, label, labelLength);

	if (!p11_check("C_GetSlotList", p11->C_GetSlotList(CK_TRUE, slots, &count)))
		return 0;
	for (i = 0; i < count; i++)
	{
		if (!p11_check("C_GetTokenInfo", p11->C_GetTokenInfo(slots[i], &info)))
			return 0;
		if (memcmp(info.label, paddedLabel, sizeof(paddedLabel)) == 0)
		{
			*slot = slots[i];
			return 1;
		}
	}
	fprintf(stderr, "ERRO: token \"%s\" não encontrado\n", label);
	return 0;
}

CK_SESSION_HANDLE p11_open_session(void)
{
	const char* modulePath = require_env("SOFTHSM_MODULE");
	const char* tokenLabel = require_env("TOKEN_LABEL");
	const char* pin = require_env("USER_PIN");
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	if (modulePath == NULL || tokenLabel == NULL || pin == NULL)
		return CK_INVALID_HANDLE;
	if (!load_module(modulePath) ||
		!p11_check("C_Initialize", p11->C_Initialize(NULL_PTR)) ||
		!find_slot(tokenLabel, &slot) ||
		!p11_check("C_OpenSession", p11->C_OpenSession(slot,
			CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session)) ||
		!p11_check("C_Login", p11->C_Login(session, CKU_USER,
			(CK_UTF8CHAR_PTR)pin, strlen(pin))))
		return CK_INVALID_HANDLE;
	return session;
}

void p11_close_session(CK_SESSION_HANDLE session)
{
	/* Os objetos de sessão criados pelos clientes são destruídos aqui. */
	p11->C_Logout(session);
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL_PTR);
	dlclose(module);
}

int read_file(const char* path, CK_BYTE* buffer, CK_ULONG capacity,
	CK_ULONG* length)
{
	FILE* file = fopen(path, "rb");
	int extra;

	if (file == NULL)
	{
		fprintf(stderr, "ERRO: não foi possível abrir %s\n", path);
		return 0;
	}
	*length = fread(buffer, 1, capacity, file);
	extra = fgetc(file);
	fclose(file);
	if (extra != EOF)
	{
		fprintf(stderr, "ERRO: %s tem mais de %lu bytes\n", path, capacity);
		return 0;
	}
	return 1;
}

int write_file(const char* path, const CK_BYTE* data, CK_ULONG length)
{
	FILE* file = fopen(path, "wb");
	int ok;

	if (file == NULL)
	{
		fprintf(stderr, "ERRO: não foi possível criar %s\n", path);
		return 0;
	}
	ok = fwrite(data, 1, length, file) == length;
	if (fclose(file) != 0) ok = 0;
	if (!ok) fprintf(stderr, "ERRO: falha ao gravar %s\n", path);
	return ok;
}
