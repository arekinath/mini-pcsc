/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, University of Queensland
 * Author: Alex Wilson <alex@cooperi.net>
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "errf.h"
#include "iso7816.h"
#include "ccid-driver.h"
#include "wintypes.h"
#include "pcsclite.h"
#include "winscard.h"

struct context {
	struct context *ctx_next;
	struct context *ctx_prev;
	SCARDCONTEXT ctx_id;
	struct ccid_dev_table *ctx_dev_table;
	size_t ctx_ndevs;
	struct reader_context *ctx_readers;
	LONG ctx_next_reader;
};
static struct context *pcsc_ctx_first;
static LONG pcsc_ctx_next = 0x7001;
static int pcsc_atexit = 0;

struct reader_context {
	struct reader_context *rctx_next;
	struct reader_context *rctx_prev;
	struct context *rctx_ctx;
	SCARDHANDLE rctx_id;
	int rctx_index;
	ccid_driver_t rctx_drv;
	char *rctx_name;
	unsigned char rctx_atr[256];
	size_t rctx_atrlen;
};

const SCARD_IO_REQUEST g_rgSCardT0Pci, g_rgSCardT1Pci, g_rgSCardRawPci;

static struct context *
pcsc_ctx_get(SCARDCONTEXT id)
{
	struct context *ctx = pcsc_ctx_first;
	while (ctx != NULL) {
		if (ctx->ctx_id == id)
			break;
		ctx = ctx->ctx_next;
	}
	if (ctx != NULL && ctx->ctx_id == id)
		return (ctx);
	return (NULL);
}

static struct reader_context *
pcsc_rdr_get(SCARDHANDLE id)
{
	const LONG ctxid = (id >> 16) & 0xFFFF;
	struct context *ctx = pcsc_ctx_get(ctxid);
	if (ctx == NULL)
		return (NULL);
	struct reader_context *rctx = ctx->ctx_readers;
	while (rctx != NULL) {
		if (rctx->rctx_id == id)
			break;
		rctx = rctx->rctx_next;
	}
	if (rctx != NULL && rctx->rctx_id == id)
		return (rctx);
	return (NULL);
}

static void
pcsc_atexit_handler(void)
{
	struct context *ctx;
	struct reader_context *rctx;

	ctx = pcsc_ctx_first;
	while (ctx != NULL) {
		rctx = ctx->ctx_readers;
		while (rctx != NULL) {
			ccid_close_reader(rctx->rctx_drv);
			rctx = rctx->rctx_next;
		}
		ctx = ctx->ctx_next;
	}
}

PCSC_API LONG
SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2,
    LPSCARDCONTEXT phContext)
{
	errf_t *err;
	struct context *ctx;
	int count;

	if (dwScope != SCARD_SCOPE_SYSTEM)
		return (SCARD_E_NO_SERVICE);
	ctx = calloc(1, sizeof (struct context));
	if (ctx == NULL)
		return (SCARD_E_NO_MEMORY);

	ctx->ctx_id = ++pcsc_ctx_next;
	ctx->ctx_next_reader = ctx->ctx_id << 16;

	err = ccid_dev_scan(&count, &ctx->ctx_dev_table);
	if (err)
		return (SCARD_E_NO_SERVICE);
	ctx->ctx_ndevs = count;

	ctx->ctx_next = pcsc_ctx_first;
	pcsc_ctx_first = ctx;
	*phContext = ctx->ctx_id;

	if (pcsc_atexit == 0) {
		pcsc_atexit = 1;
		atexit(pcsc_atexit_handler);
	}

	return (SCARD_S_SUCCESS);
}

PCSC_API LONG
SCardReleaseContext(SCARDCONTEXT hContext)
{
	struct context *ctx = pcsc_ctx_get(hContext);
	struct reader_context *rctx, *nrctx;
	if (ctx == NULL)
		return (SCARD_E_INVALID_HANDLE);

	nrctx = ctx->ctx_readers;
	while ((rctx = nrctx) != NULL) {
		nrctx = rctx->rctx_next;
		ccid_close_reader(rctx->rctx_drv);
		free(rctx);
	}

	if (ctx->ctx_prev == NULL)
		pcsc_ctx_first = ctx->ctx_next;
	else
		ctx->ctx_prev->ctx_next = ctx->ctx_next;
	if (ctx->ctx_next != NULL)
		ctx->ctx_next->ctx_prev = ctx->ctx_prev;

	ccid_dev_scan_finish(ctx->ctx_dev_table, ctx->ctx_ndevs);

	free(ctx);

	return (SCARD_S_SUCCESS);
}

PCSC_API LONG
SCardConnect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
    DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
	struct context *ctx = pcsc_ctx_get(hContext);
	struct reader_context *rctx;
	int i, index = -1, rc;
	if (ctx == NULL)
		return (SCARD_E_INVALID_HANDLE);

	for (i = 0; i < ctx->ctx_ndevs; ++i) {
		const char *name = ccid_dev_name(ctx->ctx_dev_table, i);
		if (strcmp(szReader, name) == 0) {
			index = i;
			break;
		}
	}
	if (index == -1)
		return (SCARD_E_UNKNOWN_READER);

	rctx = calloc(1, sizeof (struct reader_context));
	rctx->rctx_id = ++ctx->ctx_next_reader;
	rctx->rctx_ctx = ctx;

	rctx->rctx_index = index;
	rc = ccid_open_reader(NULL, index, ctx->ctx_dev_table,
	    &rctx->rctx_drv, &rctx->rctx_name);
	switch (rc) {
	case 0:
		break;
	case CCID_DRIVER_ERR_BUSY:
		free(rctx);
		return (SCARD_E_SHARING_VIOLATION);
	case CCID_DRIVER_ERR_NOT_SUPPORTED:
	case CCID_DRIVER_ERR_NO_READER:
		free(rctx);
		return (SCARD_E_UNKNOWN_READER);
	case CCID_DRIVER_ERR_CARD_IO_ERROR:
		free(rctx);
		return (SCARD_F_COMM_ERROR);
	default:
		fprintf(stderr, "returned %d\n", rc);
		free(rctx);
		return (SCARD_E_READER_UNAVAILABLE);
	}

	rctx->rctx_next = ctx->ctx_readers;
	if (ctx->ctx_readers != NULL)
		ctx->ctx_readers->rctx_prev = rctx;
	ctx->ctx_readers = rctx;

	*phCard = rctx->rctx_id;
	*pdwActiveProtocol = SCARD_PROTOCOL_T1;

	return (SCARD_S_SUCCESS);
}

PCSC_API LONG
SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols,
    DWORD dwInitialization, LPDWORD pdwActiveProtocol)
{
	return (SCARD_E_NO_SERVICE);
}

PCSC_API LONG
SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
{
	struct reader_context *rctx;
	rctx = pcsc_rdr_get(hCard);
	if (rctx == NULL)
		return (SCARD_E_INVALID_HANDLE);
	ccid_close_reader(rctx->rctx_drv);
	if (rctx->rctx_prev == NULL)
		rctx->rctx_ctx->ctx_readers = rctx->rctx_next;
	else
		rctx->rctx_prev->rctx_next = rctx->rctx_next;
	if (rctx->rctx_next != NULL)
		rctx->rctx_next->rctx_prev = rctx->rctx_prev;
	free(rctx);
	return (SCARD_S_SUCCESS);
}

PCSC_API LONG
SCardBeginTransaction(SCARDHANDLE hCard)
{
	struct reader_context *rctx;
	int rc;
	size_t len;

	rctx = pcsc_rdr_get(hCard);
	if (rctx == NULL)
		return (SCARD_E_INVALID_HANDLE);

	len = sizeof (rctx->rctx_atr);
	rc = ccid_get_atr(rctx->rctx_drv, rctx->rctx_atr, len, &len);
	if (rc)
		return (SCARD_E_READER_UNAVAILABLE);

	return (SCARD_S_SUCCESS);
}

PCSC_API LONG
SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
{
	struct reader_context *rctx;
	rctx = pcsc_rdr_get(hCard);
	if (rctx == NULL)
		return (SCARD_E_INVALID_HANDLE);
	return (SCARD_S_SUCCESS);
}

PCSC_API LONG
SCardListReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders,
    LPDWORD pcchReaders)
{
	struct context *ctx;
	size_t buflen;
	int i;
	char *buf, *p;

	ctx = pcsc_ctx_get(hContext);
	if (ctx == NULL)
		return (SCARD_E_INVALID_HANDLE);

	buflen = 1;
	for (i = 0; i < ctx->ctx_ndevs; ++i) {
		buflen += strlen(ccid_dev_name(ctx->ctx_dev_table, i)) + 1;
	}

	if (mszReaders == NULL) {
		*pcchReaders = buflen;
		return (SCARD_S_SUCCESS);
	}

	buf = mszReaders;
	if (*pcchReaders < buflen)
		return (SCARD_E_INVALID_PARAMETER);
	
	p = buf;
	*p = '\0';
	for (i = 0; i < ctx->ctx_ndevs; ++i) {
		const char *name = ccid_dev_name(ctx->ctx_dev_table, i);
		strcpy(p, name);
		p += strlen(name) + 1;
	}
	*p = '\0';

	*pcchReaders = buflen;

	return (SCARD_S_SUCCESS);
}

PCSC_API LONG
SCardTransmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
    LPCBYTE pbSendBuffer, DWORD cbSendLength, SCARD_IO_REQUEST *pioRecvPci,
    LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
{
	struct reader_context *rctx;
	size_t recvlen;
	int rc;
	rctx = pcsc_rdr_get(hCard);
	if (rctx == NULL)
		return (SCARD_E_INVALID_HANDLE);

	recvlen = *pcbRecvLength;

	rc = ccid_transceive(rctx->rctx_drv, pbSendBuffer, cbSendLength,
	    pbRecvBuffer, recvlen, &recvlen);
	switch (rc) {
	case 0:
		break;
	case CCID_DRIVER_ERR_OUT_OF_CORE:
		return (SCARD_E_NO_MEMORY);
	case CCID_DRIVER_ERR_INCOMPLETE_CARD_RESPONSE:
		return (SCARD_E_UNEXPECTED);
	case CCID_DRIVER_ERR_NO_CARD:
		return (SCARD_E_NO_SMARTCARD);
	case CCID_DRIVER_ERR_CARD_IO_ERROR:
		return (SCARD_F_COMM_ERROR);
	case CCID_DRIVER_ERR_GENERAL_ERROR:
		return (SCARD_F_INTERNAL_ERROR);
	case CCID_DRIVER_ERR_INV_VALUE:
		return (SCARD_E_PCI_TOO_SMALL);
	default:
		return (SCARD_F_COMM_ERROR);
	}
	if (recvlen >= *pcbRecvLength)
		return (SCARD_E_NO_MEMORY);
	*pcbRecvLength = recvlen;

	return (SCARD_S_SUCCESS);
}

const char *
pcsc_stringify_error(const LONG err)
{
	switch (err) {
	case SCARD_E_BAD_SEEK: return ("SCARD_E_BAD_SEEK");
	case SCARD_E_CANCELLED: return ("SCARD_E_CANCELLED");
	case SCARD_E_CANT_DISPOSE: return ("SCARD_E_CANT_DISPOSE");
	case SCARD_E_CARD_UNSUPPORTED: return ("SCARD_E_CARD_UNSUPPORTED");
	case SCARD_E_CERTIFICATE_UNAVAILABLE: return ("SCARD_E_CERTIFICATE_UNAVAILABLE");
	case SCARD_E_COMM_DATA_LOST: return ("SCARD_E_COMM_DATA_LOST");
	case SCARD_E_DIR_NOT_FOUND: return ("SCARD_E_DIR_NOT_FOUND");
	case SCARD_E_DUPLICATE_READER: return ("SCARD_E_DUPLICATE_READER");
	case SCARD_E_FILE_NOT_FOUND: return ("SCARD_E_FILE_NOT_FOUND");
	case SCARD_E_ICC_CREATEORDER: return ("SCARD_E_ICC_CREATEORDER");
	case SCARD_E_ICC_INSTALLATION: return ("SCARD_E_ICC_INSTALLATION");
	case SCARD_E_INSUFFICIENT_BUFFER: return ("SCARD_E_INSUFFICIENT_BUFFER");
	case SCARD_E_INVALID_ATR: return ("SCARD_E_INVALID_ATR");
	case SCARD_E_INVALID_CHV: return ("SCARD_E_INVALID_CHV");
	case SCARD_E_INVALID_HANDLE: return ("SCARD_E_INVALID_HANDLE");
	case SCARD_E_INVALID_PARAMETER: return ("SCARD_E_INVALID_PARAMETER");
	case SCARD_E_INVALID_TARGET: return ("SCARD_E_INVALID_TARGET");
	case SCARD_E_INVALID_VALUE: return ("SCARD_E_INVALID_VALUE");
	case SCARD_E_NO_ACCESS: return ("SCARD_E_NO_ACCESS");
	case SCARD_E_NO_DIR: return ("SCARD_E_NO_DIR");
	case SCARD_E_NO_FILE: return ("SCARD_E_NO_FILE");
	case SCARD_E_NO_KEY_CONTAINER: return ("SCARD_E_NO_KEY_CONTAINER");
	case SCARD_E_NO_MEMORY: return ("SCARD_E_NO_MEMORY");
	case SCARD_E_NO_READERS_AVAILABLE: return ("SCARD_E_NO_READERS_AVAILABLE");
	case SCARD_E_NO_SERVICE: return ("SCARD_E_NO_SERVICE");
	case SCARD_E_NO_SMARTCARD: return ("SCARD_E_NO_SMARTCARD");
	case SCARD_E_NO_SUCH_CERTIFICATE: return ("SCARD_E_NO_SUCH_CERTIFICATE");
	case SCARD_E_NOT_READY: return ("SCARD_E_NOT_READY");
	case SCARD_E_NOT_TRANSACTED: return ("SCARD_E_NOT_TRANSACTED");
	case SCARD_E_PCI_TOO_SMALL: return ("SCARD_E_PCI_TOO_SMALL");
	case SCARD_E_PROTO_MISMATCH: return ("SCARD_E_PROTO_MISMATCH");
	case SCARD_E_READER_UNAVAILABLE: return ("SCARD_E_READER_UNAVAILABLE");
	case SCARD_E_READER_UNSUPPORTED: return ("SCARD_E_READER_UNSUPPORTED");
	case SCARD_E_SERVER_TOO_BUSY: return ("SCARD_E_SERVER_TOO_BUSY");
	case SCARD_E_SERVICE_STOPPED: return ("SCARD_E_SERVICE_STOPPED");
	case SCARD_E_SHARING_VIOLATION: return ("SCARD_E_SHARING_VIOLATION");
	case SCARD_E_SYSTEM_CANCELLED: return ("SCARD_E_SYSTEM_CANCELLED");
	case SCARD_E_TIMEOUT: return ("SCARD_E_TIMEOUT");
	case SCARD_E_UNEXPECTED: return ("SCARD_E_UNEXPECTED");
	case SCARD_E_UNKNOWN_CARD: return ("SCARD_E_UNKNOWN_CARD");
	case SCARD_E_UNKNOWN_READER: return ("SCARD_E_UNKNOWN_READER");
	case SCARD_E_UNKNOWN_RES_MNG: return ("SCARD_E_UNKNOWN_RES_MNG");
	case SCARD_E_WRITE_TOO_MANY: return ("SCARD_E_WRITE_TOO_MANY");
	case SCARD_F_COMM_ERROR: return ("SCARD_F_COMM_ERROR");
	case SCARD_F_INTERNAL_ERROR: return ("SCARD_F_INTERNAL_ERROR");
	case SCARD_F_UNKNOWN_ERROR: return ("SCARD_F_UNKNOWN_ERROR");
	case SCARD_F_WAITED_TOO_LONG: return ("SCARD_F_WAITED_TOO_LONG");
	case SCARD_P_SHUTDOWN: return ("SCARD_P_SHUTDOWN");
	case SCARD_S_SUCCESS: return ("SCARD_S_SUCCESS");
	case SCARD_W_CANCELLED_BY_USER: return ("SCARD_W_CANCELLED_BY_USER");
	case SCARD_W_CARD_NOT_AUTHENTICATED: return ("SCARD_W_CARD_NOT_AUTHENTICATED");
	case SCARD_W_CHV_BLOCKED: return ("SCARD_W_CHV_BLOCKED");
	case SCARD_W_EOF: return ("SCARD_W_EOF");
	case SCARD_W_REMOVED_CARD: return ("SCARD_W_REMOVED_CARD");
	case SCARD_W_RESET_CARD: return ("SCARD_W_RESET_CARD");
	case SCARD_W_SECURITY_VIOLATION: return ("SCARD_W_SECURITY_VIOLATION");
	case SCARD_W_UNPOWERED_CARD: return ("SCARD_W_UNPOWERED_CARD");
	case SCARD_W_UNRESPONSIVE_CARD: return ("SCARD_W_UNRESPONSIVE_CARD");
	case SCARD_W_UNSUPPORTED_CARD: return ("SCARD_W_UNSUPPORTED_CARD");
	case SCARD_W_WRONG_CHV: return ("SCARD_W_WRONG_CHV");
	default: return ("UNKNOWN_ERROR");
	}
}
