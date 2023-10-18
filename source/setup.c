#include "../hedder/codetimer.h"
#include "../hedder/dark_compiler.h"

//////////////////

int KeyGen_Class_setup( _struct_pp_* pp, const int lamda, const int logD)
{
	BIGNUM* bn_pk = BN_new();
	BIGNUM* bn_p = BN_new();
	BIGNUM* bn_q = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	
	pp->security_level = lamda;
	// RSA MODULUS SIZE = 128   -> 512로 수정 
	do{
	 	BN_generate_prime_ex(bn_p, lamda>>1, 1, NULL, NULL, NULL);
	 	BN_generate_prime_ex(bn_q, lamda>>1, 1, NULL, NULL, NULL);
		BN_mul(bn_pk,bn_p,bn_q, ctx);
		fmpz_set_str(pp->G, BN_bn2hex(bn_pk), 16);
	}while(BN_num_bits(bn_pk) != lamda);

    do{        
        BN_generate_prime_ex(bn_p, lamda/2, 0, NULL, NULL, NULL);
		fmpz_set_str(pp->g, BN_bn2hex(bn_p), 16);
    }while (0); 

	// 128 -> evaluation 할 때 mod p 할 때 사용되는 p의 size 
	BN_generate_prime_ex(bn_p,128,0,NULL,NULL,NULL);
	fmpz_set_str(pp->p, BN_bn2hex(bn_p), 16);

	fmpz_init_set_ui(pp->q, 0);
	fmpz_setbit(pp->q, 128*(6+ceil(log2(logD))+2*logD)+32*logD*logD+5); 

	BN_free(bn_pk);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_CTX_free(ctx);

	return 1;
}

int pp_init(_struct_pp_* pp)
{
	fmpz_init(pp->G);
	fmpz_init(pp->q);
	fmpz_init(pp->p);
	fmpz_init(pp->g);

	return 1;
}

int pp_clear(_struct_pp_* pp)
{
	fmpz_clear(pp->G);
	fmpz_clear(pp->q);
	fmpz_clear(pp->p);
	fmpz_clear(pp->g);

	return 1;
}
