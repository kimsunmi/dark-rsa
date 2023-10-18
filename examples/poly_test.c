#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

#include <flint/fft_tuning.h>
//#include "flint.h"
#include <flint/fmpz.h>
#include <flint/fft.h>
#include <flint/fmpz_poly.h>
#include <flint/ulong_extras.h>

#include "../hedder/codetimer.h"
int main()
{
    BIGNUM* bn_pk = BN_new();
	BIGNUM* bn_p = BN_new();
	BIGNUM* bn_q = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	
    int i, j, k;

    fmpz_poly_t t_poly1;
    fmpz_poly_t t_poly2;
    fmpz_poly_t t_poly3;
    
    fmpz_t mpz_tmp, mpz_tmp1, mpz_tmp2, mpz_tmp3;

    fmpz_init(mpz_tmp);
    fmpz_init(mpz_tmp1);
    fmpz_init_set_ui(mpz_tmp2, 65535);
    fmpz_init_set_ui(mpz_tmp3, 65535);
    fmpz_poly_init(t_poly1);
    fmpz_poly_init(t_poly2);
    fmpz_poly_init(t_poly3);


	do{
	 	BN_generate_prime_ex(bn_p, 2048>>1, 1, NULL, NULL, NULL);
	 	BN_generate_prime_ex(bn_q, 2048>>1, 1, NULL, NULL, NULL);
		BN_mul(bn_pk,bn_p,bn_q, ctx);
		fmpz_set_str(mpz_tmp2, BN_bn2hex(bn_pk), 16);
	}while(BN_num_bits(bn_pk) != 2048);

	BN_generate_prime_ex(bn_p,128,0,NULL,NULL,NULL);
	fmpz_set_str(mpz_tmp3, BN_bn2hex(bn_p), 16);

    TimerOn();
    for(i=0; i<(1<<10); i++)
    {
        fmpz_set_ui(mpz_tmp,i+1);
        fmpz_poly_set_coeff_fmpz(t_poly1, i, mpz_tmp);

        fmpz_set_ui(mpz_tmp,i+1);
        fmpz_poly_set_coeff_fmpz(t_poly2, i, mpz_tmp);
    }
    printf("1 : %12llu\r\n", TimerOff());

    TimerOn();
    fmpz_set_ui(mpz_tmp,100);
    fmpz_poly_mul_SS(t_poly3, t_poly2, t_poly1);
    printf("2 : %12llu\r\n", TimerOff());

    //fmpz_poly_print(t_poly1);   printf("\r\n");
    //fmpz_poly_print(t_poly3);   printf("\r\n");

    //fmpz_poly_scalar_mul_fmpz(t_poly3, t_poly3, mpz_tmp);
    //fmpz_poly_print(t_poly3);   printf("\r\n");

    TimerOn();
    fmpz_setbit(mpz_tmp, 8000);
    fmpz_poly_evaluate_divconquer_fmpz(mpz_tmp1, t_poly3, mpz_tmp);
    printf("3 : %12llu\r\n", TimerOff());
    printf("\n -> %d\r\n", (int)fmpz_bits(mpz_tmp1));
    //fmpz_print(mpz_tmp1);printf("\r\n");
    
    TimerOn();
    fmpz_powm(mpz_tmp, mpz_tmp3, mpz_tmp1, mpz_tmp2);
    printf("4 : %12llu\r\n", TimerOff());
    printf("\n ->");
    fmpz_print(mpz_tmp);printf("\r\n");

	return 0;
}
