
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

	>> :znc.in BATCH +1f5fdd znc.in/certinfo
	>> @batch=1f5fdd :znc.in BATCH +6f7a1a znc.in/certinfo-certificate
	>> @batch=6f7a1a :znc.in CERTINFO ExampleUser :-----BEGIN CERTIFICATE-----
	>> @batch=6f7a1a :znc.in CERTINFO ExampleUser :...
	>> @batch=6f7a1a :znc.in CERTINFO ExampleUser :-----END CERTIFICATE-----
	>> @batch=1f5fdd :znc.in BATCH -6f7a1a
	>> @batch=1f5fdd :znc.in BATCH +31fbfc znc.in/certinfo-certificate
	>> @batch=31fbfc :znc.in CERTINFO ExampleUser :-----BEGIN CERTIFICATE-----
	>> @batch=31fbfc :znc.in CERTINFO ExampleUser :...
	>> @batch=31fbfc :znc.in CERTINFO ExampleUser :-----END CERTIFICATE-----
	>> @batch=1f5fdd :znc.in BATCH -31fbfc
	>> :znc.in BATCH -1f5fdd
 */

#include <znc/Modules.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>

static const char *CertInfoCap = "znc.in/certinfo";

static const char *CertInfoBatchGlobalType = "znc.in/certinfo";
static const char *CertInfoBatchChildType = "znc.in/certinfo-certificate";

class CCertInfoMod : public CModule
{
public:
	MODCONSTRUCTOR(CCertInfoMod) {
		AddHelpCommand();
		AddCommand("Send", static_cast<CModCommand::ModCmdFunc>(&CCertInfoMod::SendCertificateCommand), "[details]", "Send certificate information to client. Append 'details' to the 'send' command ('send details') to include the entire certificate chain in output.");
	}

	void OnClientCapLs(CClient *mClient, SCString &mCaps) override
	{
		mCaps.insert(CertInfoCap);
	}

	bool IsClientCapSupported(CClient *mClient, const CString &mCap, bool mState) override
	{
		return mCap.Equals(CertInfoCap);
	}

	void SendCertificateCommand(const CString &mLine)
	{
#ifndef HAVE_LIBSSL
		PutModule("Error: Module built against install of ZNC that lacks SSL support.");
#else
		CClient *mClient = GetClient();

		if (mClient == nullptr) {
			PutModule("Error: GetClient() returned nullptr");

			return;
		}

		/* Check whether client supports capacity. */
		bool mPrintCertificates = false;
		bool mPrintCertificateParents = false;

		if (mClient->IsCapEnabled(CertInfoCap) == false ||
			mClient->HasBatch() == false)
		{
			mPrintCertificates = true;
		}

		/* If certificates will be printed, then check whether we should
		 print the entire certificate chain as well. When sending raw data,
		 the entire chain is sent no matter what. */
		if (mPrintCertificates) {
			CString sCmd = mLine.Token(1);

			if (sCmd.Equals("details")) {
				mPrintCertificateParents = true;
			}
		}

		/* Check whether we are connected and whether SSL is in use. */
		CIRCNetwork *mNetwork = mClient->GetNetwork();

		CIRCSock *mSocket = mNetwork->GetIRCSock();

		if (mSocket == nullptr) {
			PutModule("Error: mNetwork->GetIRCSock() returned nullptr");

			return;
		}

		if (mSocket->GetSSL() == false) {
			PutModule("Error: Client is not connected using SSL/TLS");

			return;
		}

		/* Ask the socket for the SSL context object */
		SSL *sslContext = mSocket->GetSSLObject();

		if (sslContext == nullptr) {
			PutModule("Error: mSocket->GetSSLObject() returned nullptr");

			return;
		}

		/* Obtain list of certificates from SSL context object */
		STACK_OF(X509) *certCollection = SSL_get_peer_cert_chain(sslContext);

		if (certCollection == NULL) {
			PutModule("Error: SSL_get_peer_cert_chain() returned nullptr");

			return;
		}

		if (mPrintCertificates) {
			PrintCertificateChainToQuery(mClient, certCollection, mPrintCertificateParents);
		} else {
			SendCertificateChain(mClient, certCollection);
		}

#endif
	}

private:

#ifdef HAVE_LIBSSL
	void SendCertificateChain(CClient *mClient, STACK_OF(X509) *mCertificateChain)
	{
		/* Send batch command opening to client */
		CString mBatchName = CString::RandomString(10).MD5();

		CString mNickname = mClient->GetNick();

		mClient->PutClient(":znc.in BATCH +" + mBatchName + " " + CertInfoBatchGlobalType);

		/* The certificates are converted into PEM format, then each line
		 is sent as a separate value to client. */
		for (size_t i = 0; i < sk_X509_num(mCertificateChain); i++)
		{
			/* Convert certificate into PEM format in a BIO buffer */
			X509 *certificate = sk_X509_value(mCertificateChain, i);

			BIO *bio_out = BIO_new(BIO_s_mem());

			PEM_write_bio_X509(bio_out, certificate);

			BUF_MEM *bio_buf;
			BIO_get_mem_ptr(bio_out, &bio_buf);

			/* Create string from the BIO buffer,  the data up into
			 lines by newline, and send the result to the client. */
			CString pemDataString = CString(bio_buf->data, bio_buf->length);

			VCString pemDataStringSplit;
			pemDataString.Split("\n", pemDataStringSplit, false);

			CString pemBatchName = CString::RandomString(10).MD5();

			mClient->PutClient("@batch=" + mBatchName + " :znc.in BATCH +" + pemBatchName + " " + CertInfoBatchChildType);

			for (const CString& s : pemDataStringSplit) {
				mClient->PutClient("@batch=" + pemBatchName + " :znc.in CERTINFO " + mNickname + " :" + s);
			}

			mClient->PutClient("@batch=" + mBatchName + " :znc.in BATCH -" + CertInfoBatchChildType);

			/* Cleanup memory allocation */
			BIO_free(bio_out);
		}

		/* Send batch command closing to client */
		mClient->PutClient(":znc.in BATCH -" + mBatchName);
	}

	void PrintCertificateChainToQuery(CClient *mClient, STACK_OF(X509) *mCertificateChain, bool mPrintEntireChain = false)
	{
		/* Print certificate chain */
		for (size_t i = 0; i < sk_X509_num(mCertificateChain); i++)
		{
			/* Convert printed result into a single string. */
			X509 *certificate = sk_X509_value(mCertificateChain, i);

			BIO *bio_out = BIO_new(BIO_s_mem());

			X509_print(bio_out, certificate);

			BUF_MEM *bio_buf;
			BIO_get_mem_ptr(bio_out, &bio_buf);

			CString certificateString = CString(bio_buf->data, bio_buf->length);

			/* Split string into newlines and escape each line similar to how ZNC
			 does it when presenting a certificate for fingerprinting. */
			CString certificateNumber = CString(i + 1);

			if (i == 0) {
				PutModule("| ---- Certificate #" + certificateNumber + " (Peer Certificate) Start ---- |");
			} else {
				PutModule("| ---- Certificate #" + certificateNumber + " Start ---- |");
			}

			VCString certificateStringSplit;

			certificateString.Split("\n", certificateStringSplit);

			for (const CString& s : certificateStringSplit) {
				PutModule("| " + s.Escape_n(CString::EDEBUG));
			}

			PutModule("| ---- Certificate #" + certificateNumber + " End ---- |");

			/* Cleanup memory allocation */
			BIO_free(bio_out);

			/* First certificate is the peer certificate so if we do not
			 need the rest of the chain, then break the loop here. */
			if (mPrintEntireChain == false) {
				break;
			}
		}
	}
#endif
	
};

GLOBALMODULEDEFS(CCertInfoMod, "A module for sending certificate information to client")
