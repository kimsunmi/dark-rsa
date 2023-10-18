#include "../hedder/codetimer.h"
#include "../hedder/poe.h"
#include <flint/fmpz_poly.h>
#include <omp.h>

extern fmpz_t** fmpz_pre;
extern int fmpz_pre_d;

unsigned long long int RunTime_poe1 = 0;
unsigned long long int RunTime_poe2 = 0;
unsigned long long int RunTime_poe3 = 0;
unsigned long long int RunTime_poe4 = 0;
unsigned long long int RunTime_poe5 = 0;


struct timeval before1[10]={0}, after1[10] = {0};
unsigned long long int RunTime1[10] = {0};

int HG_func(BIGNUM *output, const BIGNUM *input)
{
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};
    unsigned char *tmp_str = BN_bn2hex(input);
   
   	//BN_copy(output,input);
     SHA256(tmp_str, strlen(tmp_str), digest);   
	 BN_zero(output);
	 for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	 BN_hex2bn(&output, mdString);

	//printf("HG len : %d\n", BN_num_bits(output));
	//printf("HG input : %s\n", BN_bn2hex(input));
	//printf("HG : %s\n", mdString);
	//printf("HG : %s\n", BN_bn2hex(output));

	free(tmp_str);
    return 1;
}

int Hprime_func(fmpz_t output, const fmpz_t in1, const fmpz_t in2)
{
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};
	
    char *str_in1 = fmpz_get_str(NULL, 16, in1);
    char *str_in2 = fmpz_get_str(NULL, 16, in2);
	char *str_concat = calloc(strlen(str_in1) + strlen(str_in2) + 1, sizeof(char));
	//char *output_string;
	int concat_len = 0;

	memcpy(str_concat + concat_len, str_in1, sizeof(char) * strlen(str_in1));	concat_len += strlen(str_in1);
	memcpy(str_concat + concat_len, str_in2, sizeof(char) * strlen(str_in2));	concat_len += strlen(str_in2);

	SHA256(str_concat, strlen(str_concat), digest);   
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	mpz_t u, w;
	mpz_init_set_str(u,(char*)mdString,16);
	mpz_init(w);
	mpz_nextprime(w,u);	
	fmpz_set_mpz(output, w);

    //printf(">>"); fmpz_print(output); printf("\n");

	mpz_clear(u);
	mpz_clear(w);
	free(str_in1);
	free(str_in2);
	free(str_concat);

    return 1;
}

//(const BIGNUM *pf, const BIGNUM *w, const BIGNUM *u, const BIGNUM *x_pow, const BIGNUM *x, const BIGNUM *pk)
int verify_pk(fmpz_t pf, fmpz_t w, fmpz_t u, _struct_pp_ *pp, const int d, _struct_verify_timer_* ver_runtime, int rnd)
{	// pf^l * u^r = w ?

	// TimerOn();
	int i, flag = 1;
	int num = (int)fmpz_bits(pp->q);
	unsigned int t = (num - 1) * (d);

	fmpz_t g, fmpz_tmp1, fmpz_tmp2;
	fmpz_t l, x, tmp, r;

	fmpz_init(g);
	fmpz_init(fmpz_tmp1);
	fmpz_init(fmpz_tmp2);
	fmpz_init(x);
	fmpz_init(l);
	fmpz_init(r);
	fmpz_init(tmp);

	//flag &= HG_func(g,u);		
	fmpz_set(g, u);
	Hprime_func(l, u, w);	
	// int POE_init = TimerOff();
	// ver_runtime->POE_total[rnd] += POE_init;


	TimerOn();
	//TimerOn2(&before1[1]);
	fmpz_setbit(x, t);
	fmpz_mod(r, x, l);
	//RunTime1[2] = TimerOff2(&before1[2], &after1[2]);
	int POE_r = TimerOff();
	ver_runtime->POE_total[rnd] += POE_r;
	ver_runtime->POE_r[rnd] += POE_r;

	//TimerOn2(&before1[3]);
	TimerOn();
	fmpz_powm(fmpz_tmp1, pf, l, pp->G);
	int pf_l = TimerOff();
	ver_runtime->POE_total[rnd] += pf_l;
	ver_runtime->POE_pf_l[rnd] += pf_l;
	// printf("POE_pf^l time: %d deg: %d\n", pf_l, d);

	TimerOn();
	fmpz_powm(fmpz_tmp2, g, r, pp->G);
	int g_r = TimerOff();
	ver_runtime->POE_total[rnd] += g_r;
	ver_runtime->POE_g_r[rnd] += g_r;
	// printf("POE_g^r time: %d deg: %d\n", g_r, d);

	
	TimerOn();
	fmpz_mul(fmpz_tmp1, fmpz_tmp1, fmpz_tmp2);
	fmpz_mod(fmpz_tmp1, fmpz_tmp1, pp->G);

	if( fmpz_equal(fmpz_tmp1,w) == 1)
		flag = 1;
	else
		flag = 0;

	ver_runtime->POE_total[rnd] += TimerOff();
	ver_runtime->total += ver_runtime->POE_total[rnd];
	ver_runtime->POE += ver_runtime->POE_total[rnd];

	fmpz_clear(g);
	fmpz_clear(fmpz_tmp1);
	fmpz_clear(fmpz_tmp2);
	fmpz_clear(x);
	fmpz_clear(l);
	fmpz_clear(tmp);

	return (flag);
}

int getblock( fmpz_t l, int in1, int in2)
{
	int result;
	fmpz_t tmp1, tmp2; 
	fmpz_init_set_ui(tmp1, (1<<in1));
	fmpz_init_set_ui(tmp2, 2);

	fmpz_powm_ui(tmp2, tmp2, in2, l);
	fmpz_mul(tmp1, tmp1, tmp2);

	fmpz_tdiv_qr(tmp1, tmp2, tmp1, l);

	result = fmpz_get_ui(tmp1);
	fmpz_clear(tmp1);
	fmpz_clear(tmp2);

	return result;
}

int eval_pk_precomputed(fmpz_t pf, fmpz_t w,  fmpz_t u, _struct_poly_* fR, _struct_pp_ *pp, const int d)
{	
	TimerOn2(&before1[0]);
	TimerOn2(&before1[1]);
	static int isprecomputed = 0;
	int num = (int)fmpz_bits(pp->q) - 1;
	int t = (num) * (d);
	int ktmp = (int)((log(t)/log(2))/3);
	int k = ktmp;
	int gamma = (int)(sqrt((double)t));

	int min = 0x8FFFFFF, offset = 1, spd ;
	// for(int i=1; i<20; i++)
	// {
	// 	spd = t/i + gamma*(1<<(i+1));
	// 	if(min > spd)
	// 	{
	// 		min = spd;
	// 		offset = i;
	// 	}
	// }
	//k =offset;
	//printf("%d ", gamma);
	k = 8;
	gamma = 16;
	// offset = 0;
	// for(int i = gamma; i > 0; i>>=1)
	// 	offset++;

	//gamma = 1<<(offset-1);
	// while(t%(k*gamma) != 0)
	// 	gamma /= 2;
	//printf("%d %d\n", gamma, t%(k*gamma));
	//printf("%d %d\n", gamma, k);
	int step = gamma/16;
	int poe_block = num/(gamma*k);
	int k1 = k/2;
	int k0 = k - k1;
	fmpz_t prime_l;
	fmpz_t x, z, g, fmpz_tmp;
	fmpz_t fmod;
	fmpz_t* Ci;
	fmpz_t* yb;
	int Ci_num = ceil((double)t/((double)gamma*k));
	int yb_num = (1<<k);
	Ci = (fmpz_t*)malloc(sizeof(fmpz_t)* Ci_num);
	yb = (fmpz_t*)malloc(sizeof(fmpz_t)* yb_num);
	//printf("Ci_num : %d\n",Ci_num);
	fmpz_init_set(g, u);	//BN_copy(g,u);			
	Hprime_func(prime_l, u, w);	

	for(int i = 0; i< yb_num; i++)
		fmpz_init(yb[i]);
		
	fmpz_init(z);
	fmpz_init_set_ui(x, 1);

	RunTime1[1] += TimerOff2(&before1[1], &after1[1]);	
	TimerOn2(&before1[2]);
	
	//omp_set_num_threads(2);
	int num_threads =  1;//(int)omp_get_max_threads();
	fmpz_t* parallel_tmp1 = (fmpz_t*)malloc(sizeof(fmpz_t) * num_threads);
	fmpz_t* parallel_tmp2 = (fmpz_t*)malloc(sizeof(fmpz_t) * num_threads);
	fmpz_t** parallel_yb = (fmpz_t**)malloc(sizeof(fmpz_t*) * num_threads);


	//#pragma omp parallel for
	for(int i = 0; i< Ci_num; i++)
	  	fmpz_init(Ci[i]);


	//#pragma omp parallel for
	for(int i = 0; i<num_threads; i++)
	{
		fmpz_init(parallel_tmp1[i]);		
		fmpz_init(parallel_tmp2[i]);
		parallel_yb[i] = (fmpz_t*)malloc(sizeof(fmpz_t) * yb_num);
		for(int j = 0; j < yb_num; j++)
			fmpz_init(parallel_yb[i][j]);
	}
	RunTime1[2] += TimerOff2(&before1[2], &after1[2]);
	/////////////////////////////////////////////////////////////////////////////////////////
	TimerOn2(&before1[3]);
	// fmpz_set(Ci[0], g);
	// fmpz_mod(Ci[0], Ci[0], pp->G);
	// fmpz_init(fmpz_tmp);
	// fmpz_setbit(fmpz_tmp, k*gamma);
	// for(int i = 1; i< Ci_num; i++){		
	// 	fmpz_powm(Ci[i], Ci[i-1], fmpz_tmp, pp->G);
	// }
	// RunTime1[3] += TimerOff2(&before1[3], &after1[3]);
			/////////////////////////////////////////////////////////////////////////////////////////

	fmpz_set(Ci[0], g);
	fmpz_mod(Ci[0], Ci[0], pp->G);
	// #pragma omp parallel for 
	for(int i = 1; i< Ci_num; i++)
	{
		fmpz_one(Ci[i]);
		for(int j = fR->d - 1; j >= 0; j--)
		{
			int th = 1;
			if(fmpz_is_zero(fR->Fx[j]) == 0)
			{
				fmpz_powm(parallel_tmp1[th], fmpz_pre[j + (step*i)/poe_block][(step*i)%poe_block], fR->Fx[j], pp->G);
				fmpz_mul(parallel_tmp1[th], Ci[i], parallel_tmp1[th]);
				fmpz_mod(Ci[i], parallel_tmp1[th], pp->G);
			}
		}
	}
	RunTime1[3] += TimerOff2(&before1[3], &after1[3]);

	fmpz_init_set_ui(fmod, 2); 
	fmpz_powm_ui(fmod, fmod, k*gamma, prime_l);
	fmpz_invmod(fmod, fmod, prime_l);
	
	/////////////////////////////////////////////////////////////////////////////////////////
	TimerOn2(&before1[4]);
	for(int j = gamma-1; j >= 0; j--){
	TimerOn2(&before1[5]);
		fmpz_set_ui(fmpz_tmp, 1<<k);
		fmpz_powm(x, x, fmpz_tmp, pp->G);
		
		for(int i=0; i < yb_num; i++){
			fmpz_one(yb[i]);
		}

		// #pragma omp parallel for 
		for(int i = 0; i < num_threads; i++)
			for(int j = 0; j< yb_num; j++)
				fmpz_one(parallel_yb[i][j]);


	RunTime1[5] += TimerOff2(&before1[5], &after1[5]);
	TimerOn2(&before1[6]);
		//for(int i = 0; i <= Ci_num-1; i++){
		// #pragma omp parallel for
		for(int th = 0; th < num_threads ; th++ )
		{		
			int isfirst = 0, idx = 0;
			for(int i = (int)(0.5+(th)*(Ci_num/(float)num_threads)); i < (int)(0.5+(th+1)*Ci_num/((float)num_threads)); i++)
			{
				if(t-k*(i*gamma+j+1)<0)
				{
					//printf("ERROR %d %d\r\n", i, Ci_num);
					continue;
				}
				if(isfirst == 0)
				{
					//printf("%d %d\r\n", gamma*k, t-k*(i*gamma+j+1));
					fmpz_set_ui(parallel_tmp1[th], (1<<k));
					fmpz_set_ui(parallel_tmp2[th], 2);
					fmpz_powm_ui(parallel_tmp2[th], parallel_tmp2[th], t-k*(i*gamma+j+1), prime_l);
					fmpz_mul(parallel_tmp1[th], parallel_tmp1[th], parallel_tmp2[th]);
					fmpz_tdiv_q(parallel_tmp1[th], parallel_tmp1[th], prime_l);
					idx = fmpz_get_ui(parallel_tmp1[th]);
					isfirst = 1;
				}
				else{
					fmpz_set_ui(parallel_tmp1[th], (1<<k));
					fmpz_mul(parallel_tmp2[th], parallel_tmp2[th], fmod);
					fmpz_mod(parallel_tmp2[th], parallel_tmp2[th], prime_l);
					fmpz_mul(parallel_tmp1[th], parallel_tmp1[th], parallel_tmp2[th]);
					fmpz_tdiv_q(parallel_tmp1[th], parallel_tmp1[th], prime_l);
					idx = fmpz_get_ui(parallel_tmp1[th]);
				}

				//int idx =  getblock(prime_l, k, t-k*(i*gamma+j+1));
				fmpz_mul(parallel_yb[th][idx], parallel_yb[th][idx], Ci[i]);
				fmpz_mod(parallel_yb[th][idx], parallel_yb[th][idx], pp->G);
				//fmpz_mul(yb[idx], yb[idx], Ci[i]);
				//fmpz_mod(yb[idx], yb[idx], pp->G);
								
			}
		}

		// #pragma omp parallel for
		for(int i = 0; i< yb_num; i++)
		{
			for(int th = 0; th < num_threads ; th++ )
			{
				fmpz_mul(yb[i], parallel_yb[th][i], yb[i]);
				fmpz_mod(yb[i], yb[i], pp->G);
			}
		}
	RunTime1[6] += TimerOff2(&before1[6], &after1[6]);
	TimerOn2(&before1[7]);
	// #pragma omp parallel for
	for(int th = 0; th < num_threads ; th++ )
	{
		fmpz_one(parallel_tmp1[th]);
		fmpz_one(parallel_tmp2[th]);
	}

	// #pragma omp parallel for
	for(int b1 = 0; b1 < (1<<k1); b1++){
		int th = 1;
		fmpz_one(parallel_tmp1[th]);
		for(int b0 = 0; b0 < (1<<k0); b0++){
			fmpz_mul(parallel_tmp1[th], parallel_tmp1[th], yb[(b1<<k0)+b0]);
			fmpz_mod(parallel_tmp1[th], parallel_tmp1[th], pp->G);
		}
		fmpz_powm_ui(parallel_tmp1[th],parallel_tmp1[th],(b1<<k0),pp->G);
		fmpz_mul(parallel_tmp2[th],parallel_tmp2[th],parallel_tmp1[th]);
		fmpz_mod(parallel_tmp2[th],parallel_tmp2[th],pp->G);
	}

	for(int th = 0; th < num_threads ; th++ )
	{
		fmpz_mul(x,parallel_tmp2[th],x);
		fmpz_mod(x,x,pp->G);
	}

	RunTime1[7] += TimerOff2(&before1[7], &after1[7]);	
	TimerOn2(&before1[8]);
	// #pragma omp parallel for
	for(int th = 0; th < num_threads ; th++ )
	{
		fmpz_one(parallel_tmp1[th]);
		fmpz_one(parallel_tmp2[th]);
	}

	// #pragma omp parallel for
	for(int b0 = 0; b0 < (1<<k0); b0++){
		int th = 1;
		fmpz_set_ui(parallel_tmp1[th],1);
		for(int b1 = 0; b1 < (1<<k1); b1++){
			fmpz_mul(parallel_tmp1[th], parallel_tmp1[th], yb[(b1<<k0)+b0]);				
			fmpz_mod(parallel_tmp1[th], parallel_tmp1[th], pp->G);
		}
		fmpz_powm_ui(parallel_tmp1[th], parallel_tmp1[th],b0,pp->G);
		fmpz_mul(parallel_tmp2[th], parallel_tmp2[th], parallel_tmp1[th]);
		fmpz_mod(parallel_tmp2[th], parallel_tmp2[th], pp->G);			
	}
	
	for(int th = 0; th < num_threads ; th++ )
	{
		fmpz_mul(x,parallel_tmp2[th],x);
		fmpz_mod(x,x,pp->G);
	}

	RunTime1[8] += TimerOff2(&before1[8], &after1[8]);

	}
	fmpz_set(pf, x);
	RunTime1[4] += TimerOff2(&before1[4], &after1[4]);
	/////////
	for(int i = 0; i< yb_num; i++){
		fmpz_clear(yb[i]);
	}
	free(yb);
	for(int i = 0; i< Ci_num; i++){
		fmpz_clear(Ci[i]);
	}
	free(Ci);

	fmpz_clear(prime_l);
	fmpz_clear(fmpz_tmp);
	fmpz_clear(x);
	fmpz_clear(z);
	fmpz_clear(g);
	fmpz_clear(fmod);

	//#pragma omp parallel for
	for(int i = 0; i<num_threads; i++)
	{
		fmpz_clear(parallel_tmp1[i]);		
		fmpz_clear(parallel_tmp2[i]);
		for(int j = 0; j < yb_num; j++){
			fmpz_clear(parallel_yb[i][j]);
		}
		free(parallel_yb[i]);
	}
	free(parallel_tmp1);
	free(parallel_tmp2);

	RunTime1[0] += TimerOff2(&before1[0], &after1[0]);

	if(d==1){
		// printf("[0] %12llu\n", RunTime1[0]);
		// printf("[1] %12llu\n", RunTime1[1]);
		// printf("[2] %12llu\n", RunTime1[2]);
		// printf("[3] %12llu\n", RunTime1[3]);
		// printf("[4] %12llu\n", RunTime1[4]);
		// printf("[5] %12llu\n", RunTime1[5]);
		// printf("[6] %12llu\n", RunTime1[6]);
		// printf("[7] %12llu\n", RunTime1[7]);
		// printf("[8] %12llu\n", RunTime1[8]);
	}

}

int eval_pk_test(fmpz_t pf, fmpz_t w,  fmpz_t u, _struct_poly_* fR, _struct_pp_ *pp, const int d)
{	//eval_pk(POE_proof, poe_w, poe_u, poe_x, d_+1, pp->G, NULL);								
	// u^x mod G = w mod G
	TimerOn2(&before1[0]);
	int i, flag = 1;
	int num = (int)fmpz_bits(pp->q) - 1;
	unsigned int t = (num) * d;
	int cnt = 0;

	fmpz_t g, l, x, r;
	fmpz_t tmp, tmp_1, tmp_2;	
	_struct_poly_ f_out;
	_struct_commit_ cm;
	fmpz_poly_t t_poly1, t_poly2, t_poly3;
	//fmpz_t bn_tmp1, bn_tmp2;
	
	fmpz_init(g);
	fmpz_init(x);
	fmpz_init(l);
	fmpz_init(tmp);
	fmpz_init(r);
	
	//  u^x = w --> CR^(q^d'+1)  = C/CL
	// pf^l * u^r = w ?	-->		CR^r
	//flag &= HG_func(g,u);		
	fmpz_set(g, u);	//BN_copy(g,u);			
	Hprime_func(l, u, w);	
	//printf("t: %d\n", t);
	//printf("	poe eval l : %s\n", BN_bn2hex(l));// 	Hprime( g || w ) -> l
	//printf("l : %s\n", BN_bn2hex(l));
	
	//TimerOn();
	fmpz_setbit(x, t);
	fmpz_tdiv_qr(tmp, r, x, l);
	///////////////////////////////////////////////////////////////
	//fmpz_print(l);printf("\n");

	fmpz_poly_init(t_poly1);
    fmpz_poly_init(t_poly2);
    fmpz_poly_init(t_poly3);
	//f_in = (fmpz_t*)calloc(sizeof(fmpz_t), d);
	//f_out.d = 2*d - 1;
	//f_out.Fx = (fmpz_t*)calloc(sizeof(fmpz_t), f_out.d);
	//for(int i = 0; i < f_out.d; i++)
	//	fmpz_init(f_out.Fx[i]);

	fmpz_t f_q;
	fmpz_init(f_q);
	fmpz_zero(f_q);

	for(i = fR->d-1; i >= 0; i--)
	{
		fmpz_mul_2exp(f_q, f_q, num);
		fmpz_add(f_q, f_q, fR->Fx[i]);
		// fmpz_mod(open->r, open->r, l);
	}

	fmpz_init_set(tmp_1, tmp);
	fmpz_mul(tmp_1, f_q, tmp_1);
	fmpz_init(tmp_2);
	cnt = 0;
	RunTime1[0] += TimerOff2(&before1[0], &after1[0]);	
	TimerOn2(&before1[1]);
	//printf("poe set f'\r\n");
	while(fmpz_bits(tmp_1) > cnt*num)
	{
		fmpz_zero(tmp_2);
		for(int i = 0 ; i<num; i++)
		{
			if(fmpz_tstbit(tmp_1, i + cnt*(num)) == 1)
				fmpz_setbit(tmp_2, i);
		}
		//fmpz_tdiv_qr(tmp_1, tmp_2, tmp_1, pp->q);		
		fmpz_poly_set_coeff_fmpz(t_poly2, cnt, tmp_2);
		cnt++;
	}
	RunTime1[1] += TimerOff2(&before1[1], &after1[1]);	
	TimerOn2(&before1[2]);

	// ///////////////////////////////////////////////////////////////////////////////
	// //fmpz_poly_print(t_poly2); printf("\n");
	// // cnt = 0;
	// // while(!fmpz_is_zero(tmp_1)){
	// // 	fmpz_tdiv_qr(tmp_1, tmp_2, tmp_1, pp->q);
	// // 	fmpz_poly_set_coeff_fmpz(t_poly2, cnt, tmp_2);
	// // 	cnt++;
	// // }
	// // fmpz_poly_print(t_poly2); printf("\n");
	// ///////////////////////////////////////////////////////////////////////////////

	// //printf("poe set f\r\n");
	// for(int i=0; i< fR->d; i++)
	// 	fmpz_poly_set_coeff_fmpz(t_poly1, i, fR->Fx[i]);
	// RunTime1[2] += TimerOff2(&before1[2], &after1[2]);	
	// TimerOn2(&before1[3]);

	// //printf("poe set f* coeff\r\n");
	// //fmpz_poly_scalar_mul_fmpz(t_poly3, t_poly1, tmp_1);

	// //printf("poe f*f'\r\n");
	// fmpz_poly_mul_SS(t_poly3, t_poly2, t_poly1);
	
	// RunTime1[3] += TimerOff2(&before1[3], &after1[3]);	
	// TimerOn2(&before1[4]);
	
	f_out.d = cnt;	
	f_out.Fx = (fmpz_t*)calloc(f_out.d + 1, sizeof(fmpz_t));

	// RunTime1[4] += TimerOff2(&before1[4], &after1[4]);	
	// TimerOn2(&before1[5]);

	//printf("poe poly -> fmpz_t'\r\n");
	fmpz_zero(tmp_1);
	for(int i=0; i< f_out.d; i++){
		fmpz_init(f_out.Fx[i]);
		fmpz_poly_get_coeff_fmpz(f_out.Fx[i], t_poly2, i);
		fmpz_add(f_out.Fx[i], f_out.Fx[i], tmp_1);
		fmpz_tdiv_qr(tmp_1, f_out.Fx[i], f_out.Fx[i], pp->q);
	}

	if(fmpz_is_zero(tmp_1) == 0)
	{
		fmpz_init(f_out.Fx[f_out.d]);
		fmpz_set(f_out.Fx[f_out.d], tmp_1);
		f_out.d++;		
	}
	
	// RunTime1[5] += TimerOff2(&before1[5], &after1[5]);	
	// TimerOn2(&before1[6]);

	// fmpz_poly_clear(t_poly1);
	// fmpz_poly_clear(t_poly2);
	// fmpz_poly_clear(t_poly3);

	//printf("poe commit\r\n");
	// poly2를 바로 넣기 
	commit_init(&cm);
	commit_new(&cm, *pp, f_out);
	fmpz_set(pf,cm.C);

	for(int i=0; i< f_out.d; i++)
		fmpz_clear(f_out.Fx[i]);
	free(f_out.Fx);

	RunTime1[6] += TimerOff2(&before1[6], &after1[6]);	

	//printf("poe end\r\n");
	commit_clear(&cm);
	fmpz_clear(g);
	fmpz_clear(x);
	fmpz_clear(r);
	fmpz_clear(l);
	fmpz_clear(tmp);
	fmpz_clear(tmp_1);
	fmpz_clear(tmp_2);

	if(d==1){
		// printf("[0] %12llu\n", RunTime1[0]);
		// printf("[1] %12llu\n", RunTime1[1]);
		// printf("[2] %12llu\n", RunTime1[2]);
		// printf("[3] %12llu\n", RunTime1[3]);
		// printf("[4] %12llu\n", RunTime1[4]);
		// printf("[5] %12llu\n", RunTime1[5]);
		// printf("[6] %12llu\n", RunTime1[6]);
		// printf("[7] %12llu\n", RunTime1[7]);
		// printf("[8] %12llu\n", RunTime1[8]);
	}


	return flag;
}


int eval_pk(fmpz_t pf, fmpz_t w, fmpz_t u, _struct_pp_ *pp, const int d)
{	//eval_pk(POE_proof, poe_w, poe_u, poe_x, d_+1, pp->G, NULL);								
	// u^x mod G = w mod G
	int i, flag = 1;
	int num = (int)fmpz_bits(pp->q);
	int t = (num - 1) * d;

	fmpz_t g;
	fmpz_t l, x, tmp, r;
	//fmpz_t bn_tmp1, bn_tmp2;
	
	fmpz_init(g);
	fmpz_init(x);
	fmpz_init(l);
	fmpz_init(tmp);
	fmpz_init(r);
	
	//  u^x = w --> CR^(q^d'+1)  = C/CL
	// pf^l * u^r = w ?	-->		CR^r

	//flag &= HG_func(g,u);		
	fmpz_set(g, u);	//BN_copy(g,u);			
	Hprime_func(l, u, w);	
	
	//printf("t: %d\n", t);
	//printf("	poe eval l : %s\n", BN_bn2hex(l));// 	Hprime( g || w ) -> l
	//printf("l : %s\n", BN_bn2hex(l));
	
	//TimerOn();
	fmpz_setbit(x, t);
	fmpz_tdiv_qr(tmp, r, x, l);

	fmpz_powm(pf, g, tmp, pp->G);

	//RunTime_poe1 = TimerOff();
	//RunTime_poe1 += TimerOff();
	//printf("%s ", BN_bn2hex(pf));

	fmpz_clear(g);
	fmpz_clear(x);
	fmpz_clear(l);
	fmpz_clear(tmp);
	return flag;
}