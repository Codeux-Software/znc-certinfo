
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
 
	>> :znc.in BATCH +1f5fddff8c009efe8b852ac2eb352591 znc.in/certinfo_v1
	>> @batch=1f5fddff8c009efe8b852ac2eb352591 :znc.in BATCH +6f7a1a33eb6b948693cc7b89b3c3ba35 znc.in/certinfo_v1
	>> @batch=6f7a1a33eb6b948693cc7b89b3c3ba35 :znc.in CERTINFO ExampleUser :-----BEGIN CERTIFICATE-----
	>> @batch=6f7a1a33eb6b948693cc7b89b3c3ba35 :znc.in CERTINFO ExampleUser :...
	>> @batch=6f7a1a33eb6b948693cc7b89b3c3ba35 :znc.in CERTINFO ExampleUser :-----END CERTIFICATE-----
	>> @batch=1f5fddff8c009efe8b852ac2eb352591 :znc.in BATCH -6f7a1a33eb6b948693cc7b89b3c3ba35
	>> @batch=1f5fddff8c009efe8b852ac2eb352591 :znc.in BATCH +31fbfc94b95ccfa3664cd71833c4f571
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
static const char *CertInfoBatchCap = "znc.in/certinfo_v1";

class CCertInfoMod : public CModule
{
public:
	MODCONSTRUCTOR(CCertInfoMod) {}

	void OnIRCConnected() override {
		sendCertificate();
	}

	void OnClientLogin() override {
		sendCertificate();
	}

private:
	void sendCertificate()
	{
		CIRCNetwork *network = GetNetwork();

		/* Check whether there is at least one connected client */
		if (network->GetClients().size() < 1) {
			return;
		}

		/* Check whether we are connected and whether SSL is in use. */
		CIRCSock *socket = network->GetIRCSock();

		if (socket == nullptr) {
			return;
		}

		if (socket->GetSSL() == false) {
			return;
		}

		/* Ensure that the connected client supports the BATCH command */
		CClient *client = GetClient();
		
		if (client == nullptr) {
			return;
		}

		if (client->HasBatch() == false) {
			return;
		}

		/* Ask the socket for the SSL context object */
		SSL *sslContext = socket->GetSSLObject();

		if (sslContext == nullptr) {
			return;
		}

		/* Obtain list of certificates from SSL context object */
		STACK_OF(X509) *certCollection = SSL_get_peer_cert_chain(sslContext);

		if (certCollection == NULL) {
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

NETWORKMODULEDEFS(CCertInfoMod, "A module for sending certificate information to client")
