
/* Created by Michael Morris, released into the Public Domain */

/* Notes: */
/* This module sends the certificate chain of a connection to the
 connected client so that the client can display this information
 in a user friendly dialog. */
/* As-is customary, the chain starts with the peer certificate and
 and ends with the root certificate authority certificate. */
/* The certificate chain is sent using the BATCH command. */
/* Each certificate is surrounded in its own nested BATCH within
 a single global BATCH for the whole session. */

/* Example response:

	>> :znc.in BATCH +1f5fddff8c009efe8b852ac2eb352591 znc.in/certinfo
	>> @batch=1f5fddff8c009efe8b852ac2eb352591 :znc.in BATCH +6f7a1a33eb6b948693cc7b89b3c3ba35 znc.in/certinfo
	>> @batch=6f7a1a33eb6b948693cc7b89b3c3ba35 :znc.in CERTINFO ExampleUser :-----BEGIN CERTIFICATE-----
	>> @batch=6f7a1a33eb6b948693cc7b89b3c3ba35 :znc.in CERTINFO ExampleUser :...
	>> @batch=6f7a1a33eb6b948693cc7b89b3c3ba35 :znc.in CERTINFO ExampleUser :-----END CERTIFICATE-----
	>> @batch=1f5fddff8c009efe8b852ac2eb352591 :znc.in BATCH -6f7a1a33eb6b948693cc7b89b3c3ba35
	>> @batch=1f5fddff8c009efe8b852ac2eb352591 :znc.in BATCH +31fbfc94b95ccfa3664cd71833c4f571 znc.in/certinfo
	>> @batch=31fbfc94b95ccfa3664cd71833c4f571 :znc.in CERTINFO ExampleUser :-----BEGIN CERTIFICATE-----
	>> @batch=31fbfc94b95ccfa3664cd71833c4f571 :znc.in CERTINFO ExampleUser :...
	>> @batch=31fbfc94b95ccfa3664cd71833c4f571 :znc.in CERTINFO ExampleUser :-----END CERTIFICATE-----
	>> @batch=1f5fddff8c009efe8b852ac2eb352591 :znc.in BATCH -31fbfc94b95ccfa3664cd71833c4f571
	>> :znc.in BATCH -1f5fddff8c009efe8b852ac2eb352591
 */

#include <znc/Modules.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>

/* Vendor flag appended to BATCH command so that the client knows
 what to expect when receiving the data. */
static const char *CertInfoBatchCap = "znc.in/certinfo";

class CCertInfoMod : public CModule
{
public:
	MODCONSTRUCTOR(CCertInfoMod) {
		AddHelpCommand();
		AddCommand("Send", static_cast<CModCommand::ModCmdFunc>(&CCertInfoMod::SendCertificateCommand), "", "Send certificate information to client");
	}

	void OnClientCapLs(CClient *client, SCString &caps) override
	{
		caps.insert(CertInfoBatchCap);
	}

	bool IsClientCapSupported(CClient *client, const CString &cap, bool state) override
	{
		return cap.Equals(CertInfoBatchCap);
	}

	void SendCertificateCommand(const CString &line)
	{
		CClient *client = GetClient();

		if (client == nullptr) {
			PutModule("Error: GetClient() returned nullptr");

			return;
		}

		/* Ensure that the connected client opted for the CAP */
		if (client->IsCapEnabled(CertInfoBatchCap) == false) {
			PutModule("Error: Client does not support appropriate capacity");

			return;
		}

		/* Ensure that the connected client supports the BATCH command */
		if (client->HasBatch() == false) {
			PutModule("Error: Client does not support BATCH command");

			return;
		}

		/* Check whether we are connected and whether SSL is in use. */
		CIRCNetwork *network = client->GetNetwork();

		CIRCSock *socket = network->GetIRCSock();

		if (socket == nullptr) {
			PutModule("Error: network->GetIRCSock() returned nullptr");

			return;
		}

		if (socket->GetSSL() == false) {
			PutModule("Error: Client is not connected using SSL/TLS");

			return;
		}

		/* Ask the socket for the SSL context object */
		SSL *sslContext = socket->GetSSLObject();

		if (sslContext == nullptr) {
			PutModule("Error: socket->GetSSLObject() returned nullptr");

			return;
		}

		/* Obtain list of certificates from SSL context object */
		STACK_OF(X509) *certCollection = SSL_get_peer_cert_chain(sslContext);

		if (certCollection == NULL) {
			PutModule("Error: SSL_get_peer_cert_chain() returned nullptr");

			return;
		}

		/* Send batch command opening to client */
		CString sBatchName = CString::RandomString(10).MD5();

		CString nickname = client->GetNick();

		client->PutClient(":znc.in BATCH +" + sBatchName + " " + CertInfoBatchCap);

		/* The certificates are converted into PEM format, then each line
		 is sent as a separate value to client. */
		for (size_t i = 0; i < sk_X509_num(certCollection); i++)
		{
			/* Convert certificate into PEM format in a BIO buffer */
			X509 *cert = sk_X509_value(certCollection, i);

			BIO *bio_out = BIO_new(BIO_s_mem());

			PEM_write_bio_X509(bio_out, cert);

			BUF_MEM *bio_buf;
			BIO_get_mem_ptr(bio_out, &bio_buf);

			/* Create string from the BIO buffer,  the data up into
			 lines by newline, and send the result to the client. */
			CString pemDataString = CString(bio_buf->data, bio_buf->length);

			VCString pemDataLines;
			pemDataString.Split("\n", pemDataLines, false);

			CString pemBatchName = CString::RandomString(10).MD5();

			client->PutClient("@batch=" + sBatchName + " :znc.in BATCH +" + pemBatchName + " " + CertInfoBatchCap);

			for (const CString& pemData : pemDataLines) {
				client->PutClient("@batch=" + pemBatchName + " :znc.in CERTINFO " + nickname + " :" + pemData);
			}

			client->PutClient("@batch=" + sBatchName + " :znc.in BATCH -" + pemBatchName);

			/* Cleanup memory allocation */
			BIO_free(bio_out);
		}

		/* Send batch command closing to client */
		client->PutClient(":znc.in BATCH -" + sBatchName);
	}
};

GLOBALMODULEDEFS(CCertInfoMod, "A module for sending certificate information to client")
