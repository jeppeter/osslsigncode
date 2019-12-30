#include <openssl/opensslv.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>

typedef struct {
	int type;
	union {
		ASN1_BMPSTRING *unicode;
		ASN1_IA5STRING *ascii;
	} value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString)

ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING , 0),
	ASN1_IMP_OPT(SpcString, value.ascii,   ASN1_IA5STRING,	1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)
#ifdef __cplusplus
extern "C" {
#endif

EVP_MD_CTX* EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX* md);

#ifdef __cplusplus
};
#endif
int main(int argc,char* argv[])
{
	SpcString* sp = NULL;
	EVP_MD_CTX *mdctx=NULL;
	sp = SpcString_new();
	if (sp != NULL) {
		sp->value.ascii = ASN1_IA5STRING_new();
	}
	mdctx = EVP_MD_CTX_new();

	if (mdctx) {
		EVP_MD_CTX_free(mdctx);
	}
	return 0;
}