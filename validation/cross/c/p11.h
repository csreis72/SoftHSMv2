/*****************************************************************************
 p11.h

 Funções comuns aos clientes PKCS#11 da validação cruzada: carregar o
 módulo do SoftHSM, abrir uma sessão autenticada no token de teste e ler ou
 gravar os arquivos trocados com o Bouncy Castle.

 O token é escolhido pelas variáveis de ambiente definidas em common.sh:
   SOFTHSM_MODULE  caminho da biblioteca libsofthsm2.so
   TOKEN_LABEL     rótulo do token de teste
   USER_PIN        PIN do usuário do token
 *****************************************************************************/

#ifndef P11_H
#define P11_H

#include "cryptoki.h"

/* Códigos de saída usados pelos clientes C e pelos programas Java. */
#define RESULT_OK      0  /* operação concluída ou assinatura válida */
#define RESULT_INVALID 1  /* assinatura rejeitada */
#define RESULT_ERROR   2  /* erro de uso, de arquivo ou do PKCS#11 */

/* Lista de funções PKCS#11 3.2, preenchida por p11_open_session(). */
extern CK_FUNCTION_LIST_3_2_PTR p11;

/* Retorna 1 se rv == CKR_OK; caso contrário, imprime o erro e retorna 0. */
int p11_check(const char* function, CK_RV rv);

/* Abre uma sessão de leitura e escrita autenticada como usuário.
   Retorna CK_INVALID_HANDLE em caso de erro. */
CK_SESSION_HANDLE p11_open_session(void);

void p11_close_session(CK_SESSION_HANDLE session);

/* Lê o arquivo inteiro em buffer. Retorna 0 se ele não couber. */
int read_file(const char* path, CK_BYTE* buffer, CK_ULONG capacity,
	CK_ULONG* length);

int write_file(const char* path, const CK_BYTE* data, CK_ULONG length);

#endif /* !P11_H */
