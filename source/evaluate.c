#include "../hedder/codetimer.h"
#include "../hedder/dark_compiler.h"
#include "../hedder/poe.h"
#include "../hedder/util.h"

int get_alpha_SHA256( fmpz_t output, fmpz_t p, fmpz_t yL, fmpz_t yR, fmpz_t CL, fmpz_t CR, int lambda )
{

	fmpz_t tmp;
	fmpz_init(tmp);
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};

	char* str_yL = fmpz_get_str(NULL, 16, yL);
	char* str_yR = fmpz_get_str(NULL, 16, yR);
	char *str_CL = fmpz_get_str(NULL, 16, CL);
	char *str_CR = fmpz_get_str(NULL, 16, CR);

	char *str_concat = calloc( strlen(str_yL) + strlen(str_yR)
								+ strlen(str_CL) + strlen(str_CR) + 1, sizeof(char));
	int concat_len = 0;

	memcpy(str_concat + concat_len, str_yL, sizeof(char) * (strlen(str_yL)));	concat_len += strlen(str_yL);
	memcpy(str_concat + concat_len, str_yR, sizeof(char) * (strlen(str_yR)));	concat_len += strlen(str_yR);	
	memcpy(str_concat + concat_len, str_CL, sizeof(char) * (strlen(str_CL)));	concat_len += strlen(str_CL);
	memcpy(str_concat + concat_len, str_CR, sizeof(char) * (strlen(str_CR)));	concat_len += strlen(str_CR);

	SHA256(str_concat, concat_len, digest);  
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	
	fmpz_set_str(output, mdString, 16);

	fmpz_set_d_2exp(tmp, 1, lambda);
	fmpz_sub_ui(tmp, tmp, 1);
	fmpz_mod(output, output, tmp);
	// fmpz_mod(output, output, p);
	fmpz_tdiv_q_2exp(output,output,2);

	free(str_yL);
	free(str_yR);
	free(str_CL);
	free(str_CR);
	free(str_concat);

    return 1;
}


int EvalBounded_origin_prover(_struct_pp_ *pp, fmpz_t* C, const fmpz_t z, fmpz_t* y, fmpz_t* b, _struct_poly_* poly, int testbit, _struct_prover_timer_* p_runtime) 
{
	static struct timeval before1[10]={0}, after1[10] = {0};
	static unsigned long long int RunTime1[10] = {0};
	static int isfirst = 0, firstd = 0;
	//static BN_CTX* ctx;
	static _struct_proof_ pf;
	static fmpz_t z_tmp;
	static fmpz_t y_tmp;
	static _struct_poly_ fL, fR;
	static fmpz_t poe_w;
	static fmpz_t poe_u;
	static fmpz_t poe_x;

	//proof size
	static fmpz_t pf_yl;
	static fmpz_t pf_yr;
	static fmpz_t pf_cl;
	static fmpz_t pf_cr;
	static fmpz_t pf_q;

	TimerOn();

	if(isfirst == 0)
	{
		//printf("d : %d\n", poly->d);
		//TimerOn();
		pf_init(&pf);
		fmpz_init(y_tmp);
		fmpz_init(z_tmp);
		fmpz_init(poe_w);
		fmpz_init(poe_u);
		fmpz_init(poe_x);

		fmpz_init(pf_yr);
		fmpz_init(pf_yl);
		fmpz_init(pf_cr);
		fmpz_init(pf_cl);
		fmpz_init(pf_q);

		firstd = (poly->d);
		fL.Fx = (fmpz_t*)calloc((poly->d), sizeof(fmpz_t));
		fR.Fx = (fmpz_t*)calloc((poly->d), sizeof(fmpz_t));
		
		isfirst = 1;
		//RunTime_eval += TimerOff();
	}
	p_runtime->prover_total += TimerOff();

	if(poly->d == 1)
	{	
		FILE *fp2 = fopen("record_0119.txt", "a+");
		fprintf(fp2,"-------proof Size(final round)----------\n");
		fprintf(fp2,"yL: %d \n", (int)fmpz_bits(pf_yl));
		fprintf(fp2,"yR: %d \n", (int)fmpz_bits(pf_yr));
		fprintf(fp2,"CL: %d \n", (int)fmpz_bits(pf_cl));
		fprintf(fp2,"CR: %d \n", (int)fmpz_bits(pf_cr));
		fprintf(fp2,"Q: %d \n", (int)fmpz_bits(pf_q));
		fprintf(fp2,"f_hat: %d \n",(int) fmpz_bits(poly->Fx[-1]));
		fprintf(fp2,"mu: %d \n",poly->mu);
		fprintf(fp2,"proof size n*(|yL|+|yR|+|CL|+|CR|+|Q|+f_hat[-1]): %d \n", poly->mu*((int) fmpz_bits(pf_yl)+(int)fmpz_bits(pf_yr)+(int)fmpz_bits(pf_cr)+(int)fmpz_bits(pf_cl)+(int)fmpz_bits(pf_q))+(int) fmpz_bits(poly->Fx[-1]));
		fprintf(fp2,"proof size(comm opt) n*(|yR|+|CR|+|Q|)+f_hat[-1]: %d \n", poly->mu*((int)fmpz_bits(pf_yr)+(int)fmpz_bits(pf_cr)+(int)fmpz_bits(pf_q))+(int) fmpz_bits(poly->Fx[-1]));
		fprintf(fp2,"-------------------------------------\n");
		fclose(fp2);

		//printf("d is 1... record f\n");
		//TimerOn();
		FILE *fp = fopen("./Txt/proof.txt", "a+");

		fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, poly->Fx[0]));
		fseek(fp, 0, SEEK_SET); 
		fclose(fp);

		free(fL.Fx);
		free(fR.Fx);
		//RunTime_file_IO += TimerOff();
		//printf("\r\n");
		// printf("<0> %12llu\n", RunTime1[0]);
		// printf("<1> %12llu\n", RunTime1[1]);
		// printf("<2> %12llu\n", RunTime1[2]);
		// printf("<3> %12llu\n", RunTime1[3]);
		// printf("<4> %12llu\n", RunTime1[4]);
		// printf("<5> %12llu\n", RunTime1[5]);
		// printf("<6> %12llu\n", RunTime1[6]);
		// printf("<7> %12llu\n", RunTime1[7]);
		// printf("<8> %12llu\n", RunTime1[8]);
		isfirst = 0;
		poly->d = firstd;
		// Proof size: yL, yR, cL, cR, Q
		pf_clear(&pf);
		fmpz_clear(z_tmp);
		fmpz_clear(y_tmp);
		fmpz_clear(poe_w);
		fmpz_clear(poe_u);
		fmpz_clear(poe_x);
	}	
	else if( ((poly->d)%2) == 1 )
	{
		//printf("d+1 is odd  [d : %d -> d' : %d]\n", poly->d, poly->d + 1);
		TimerOn();
		fmpz_powm(*C, *C, pp->q, pp->G);

		fmpz_mul(*y, *y, z);
		fmpz_mod(*y, *y, pp->p);	// y=y*z mod p
		fmpz_set_ui(y_tmp, poly->d);
		fmpz_mul(*b, *b, y_tmp);	// b =  bd
		
		poly->d = poly->d + 1;				//d = d + 1		
		fmpz_init(poly->Fx[poly->d]);
	
		for(int i = poly->d-1; i >= 0; i--){// f'(X) = Xf(X);
			fmpz_set(poly->Fx[i+1], poly->Fx[i]);
		}
		fmpz_zero(poly->Fx[0]);	

		p_runtime->prover_total += TimerOff();
		EvalBounded_origin_prover(pp, C, z, y, b, poly, testbit, p_runtime);
	}
	else
	{
		TimerOn();
		int i;
		int d_ = ((poly->d) /2); //*d = ((*d+1)>>1)-1;		// P,V compute
		//printf("d+1 is even [d : %d -> d' : %d]\n", poly->d, d_);
		//TimerOn();

		//printf("P computes fL\n");
		TimerOn2(&before1[1]);
		for(i = 0; i < d_; i++){	//fL.Fx[i] = poly->Fx[i];
			fmpz_init(fL.Fx[i]);// = BN_new();
			fmpz_set(fL.Fx[i], poly->Fx[i]);
		}
		fL.d = d_;

		//printf("P computes fR\n");
		for(i = 0; i < d_; i++){	//fR.Fx[i] = poly->Fx[d_ + i + 1];
			fmpz_init(fR.Fx[i]);
			fmpz_set(fR.Fx[i] , poly->Fx[d_ + i]);
		}
		fR.d = d_;
		RunTime1[1] += TimerOff2(&before1[1], &after1[1]);	// 14
		
		//printf("P computes yL\n");	
		TimerOn2(&before1[2]);	
		fmpz_one(z_tmp);
		fmpz_zero(y_tmp);
		fmpz_zero(pf.yL);
		i=0;
		do{
			fmpz_mul(y_tmp, fL.Fx[i], z_tmp);
			fmpz_mod(y_tmp, y_tmp, pp->p);

			fmpz_add(pf.yL, pf.yL, y_tmp);
			fmpz_mod(pf.yL, pf.yL, pp->p);

			fmpz_mul(z_tmp, z_tmp, z);
			fmpz_mod(z_tmp, z_tmp, pp->p);	
			i++;
		}while(i< fL.d);
		// printf("yL : "); fmpz_print(pf.yL); printf("\n");

		//printf("P computes yR\n");	
		fmpz_one(z_tmp);
		fmpz_zero(y_tmp);
		fmpz_zero(pf.yR);
		i=0;
		do{
			fmpz_mul(y_tmp, fR.Fx[i], z_tmp);
			fmpz_mod(y_tmp, y_tmp, pp->p);

			fmpz_add(pf.yR, pf.yR, y_tmp);
			fmpz_mod(pf.yR, pf.yR, pp->p);

			fmpz_mul(z_tmp, z_tmp, z);
			fmpz_mod(z_tmp, z_tmp, pp->p);	
			i++;
		}while(i< fR.d);
		//printf("yR : "); fmpz_print(pf.yR); //printf("\n");
		RunTime1[2] += TimerOff2(&before1[2], &after1[2]);	// 14
		p_runtime->prover_total += TimerOff();

		//printf("P computes CL\n");
		TimerOn2(&before1[3]);
		TimerOn();
		commit_new(&pf.CL, *pp, fL);
		int prover_cl_time =  TimerOff();
		p_runtime->prover_total += prover_cl_time;
		p_runtime->prover_CL += prover_cl_time;
	
		//printf("P computes CR\n");
		TimerOn();
		commit_new(&pf.CR, *pp, fR);
		RunTime1[3] += TimerOff2(&before1[3], &after1[3]);	// 15
		int prover_cr_time =  TimerOff();
		p_runtime->prover_total += prover_cr_time;
		p_runtime->prover_CR += prover_cr_time;
	

		//printf("P computes alpha(hash)\n");
		TimerOn();
		TimerOn2(&before1[4]);
		get_alpha_SHA256(pf.alpha, pp->p, pf.yL, pf.yR, pf.CL.C, pf.CR.C, pp->security_level);
		//fmpz_set_ui(pf.alpha,1);
		//fmpz_set_ui(pf.alpha,19);			
		RunTime1[4] += TimerOff2(&before1[4], &after1[4]);	// 15
		p_runtime->prover_total+= TimerOff();


		//POE(CR, C/CL, q^(d'+1)) run	
		TimerOn();
		TimerOn2(&before1[5]);
		fmpz_set(poe_u, pf.CR.C);
		fmpz_invmod(poe_w, pf.CL.C, pp->G);
		fmpz_mul(poe_w, poe_w, *C);
		fmpz_mod(poe_w, poe_w, pp->G);
		RunTime1[5] += TimerOff2(&before1[5], &after1[5]);	// 15

		//BN_copy(poe_u, CR.C);
		//BN_mod_inverse(poe_w, CL.C, pp->G, ctx);
		//BN_mod_mul(poe_w, poe_w, *C, pp->G, ctx);

		//eval_pk(pf.POE_proof, poe_w, poe_u, pp, d_+1);
		//printf("poe nomal : ");fmpz_print(pf.POE_proof);printf("\r\n");
		TimerOn2(&before1[6]);
		if(testbit == 0)
			eval_pk_test(pf.POE_proof, poe_w, poe_u, &fR, pp, d_);
		else
			eval_pk_precomputed(pf.POE_proof, poe_w, poe_u, &fR, pp, d_);

		RunTime1[6] += TimerOff2(&before1[6], &after1[6]);	// 15
		int poe_time = TimerOff();
		p_runtime->prover_total += poe_time;
		p_runtime->prover_POE += poe_time;
		//printf("poe pre__ : ");fmpz_print(pf.POE_proof);printf("\r\n");		
		/***********************************		 POE		***********************************/
		//printf("y' <- (a*yL + yR) mod p \n");

		TimerOn();
		TimerOn2(&before1[7]);
		fmpz_mul(y_tmp, pf.alpha, pf.yL);
		fmpz_mod(y_tmp, y_tmp, pp->p);
		
		fmpz_add(*y, y_tmp, pf.yR);
		fmpz_mod(*y, *y, pp->p);

		//BN_mod_mul(y_tmp, alpha, yL, pp->p, ctx);
		//BN_mod_add(*y, y_tmp, yR, pp->p, ctx);
		
		//printf("C' <- CL^a CR\n");
		fmpz_powm(*C, pf.CL.C, pf.alpha, pp->G);
		fmpz_mul(*C, *C, pf.CR.C);
		fmpz_mod(*C, *C, pp->G);

		//printf("b' <- b((p+1)/2)\n");
		// fmpz_set_ui(y_tmp,pp->security_level);
		fmpz_mul_2exp(*b, *b, pp->security_level);
		// fmpz_add_ui(y_tmp,y_tmp,1);
		// fmpz_tdiv_q_2exp(y_tmp,y_tmp,1);		//BN_rshift1(y_tmp,y_tmp);
		// fmpz_mul(*b, *b, y_tmp);
		RunTime1[7] += TimerOff2(&before1[7], &after1[7]);	// 15
		
		//printf("f' <- a*fL + fR\n");
		TimerOn2(&before1[8]);
		i=0;
		do{
			fmpz_mul(y_tmp, pf.alpha, fL.Fx[i]);
			fmpz_mod(y_tmp, y_tmp, *b);

			fmpz_add(poly->Fx[i], y_tmp, fR.Fx[i]);
			fmpz_mod(poly->Fx[i], poly->Fx[i], *b);

			//poly->Fx[i]  = alpha*fL.Fx[i] + fR.Fx[i];			
			fmpz_clear(fR.Fx[i]);
			fmpz_clear(fL.Fx[i]);
			i++;
		}while(i < d_);

		do{
			fmpz_clear(poly->Fx[i]);
			i++;
		}while(i < poly->d);
		poly->d = d_;
		RunTime1[8] += TimerOff2(&before1[8], &after1[8]);	// 15
		//RunTime_eval += TimerOff();
		//printf("P run EvalBounded_prover2(pp, C', z, y', d', b', f'(X))\n\n");

		//TimerOn();

		fmpz_add(pf_yl,pf_yl,pf.yL);
		fmpz_add(pf_yr,pf_yr,pf.yR);
		fmpz_add(pf_cl,pf_cl,pf.CL.C);
		fmpz_add(pf_cr,pf_cr,pf.CR.C);
		fmpz_add(pf_q,pf_q,pf.POE_proof);
		p_runtime->prover_total += TimerOff();

		Write_proof("./Txt/proof.txt", pf, "a+");	
		//RunTime_file_IO += TimerOff();

		EvalBounded_origin_prover(pp, C, z, y, b, poly, testbit, p_runtime);
	}

	return 1;
}
int Eval_prover(_struct_pp_* pp, _struct_commit_* cm, _struct_poly_* poly, int testbit) // ( pp, z, y, d, f~(X) )
{
	int i;
	fmpz_t zero, p, z, z_tmp, y;
	fmpz_t C;

	_struct_prover_timer_ prover_runtime;
	prover_runtime.prover_CL = 0;
	prover_runtime.prover_CR = 0;
	prover_runtime.prover_POE = 0;
	prover_runtime.prover_total = 0;


	_struct_prover_timer_* p_runtime = &prover_runtime;

	// int runtime = 0;
	// int *prover_runtime = &runtime;



	fmpz_init(C);
	fmpz_set(C, cm->C);

	fmpz_init_set_ui(zero,0);
	fmpz_init_set_ui(y,0);
	fmpz_init(p);
	fmpz_init_set_ui(z,100);
	fmpz_init_set_ui(z_tmp,1);

	fmpz_sub_ui(p, pp->p, 1);
	// fmpz_tdiv_q_2exp(p,p,1);

	//i=0;
	//do{
	//	BN_mod_inverse(poly->Fx[i], poly->Fx[i], pp->p, ctx);
	//	i++;
	//}while(i<= poly->d);

	i = 0;
	do{
		fmpz_mul(zero, poly->Fx[i], z_tmp);
		fmpz_mod(zero, zero, pp->p);
		fmpz_add(y, y, zero);
		fmpz_mod(y, y, pp->p);
		fmpz_mul(z_tmp, z_tmp, z);
		fmpz_mod(z_tmp, z_tmp, pp->p);
		
		//BN_mod_mul(zero, poly->Fx[i], z_tmp, pp->p, ctx);
		//BN_mod_add(y, y, zero, pp->p, ctx);
		//BN_mod_mul(z_tmp,z_tmp, z, pp->p, ctx);
		i++;
	}while(i<= poly->d);

	//printf("EvalBounded_prover2 Start\n");
	EvalBounded_origin_prover(pp, &C, z, &y, &p, poly, testbit, p_runtime);

	printf("EVAL_PROVER0 %12llu [us]\r\n", prover_runtime.prover_total);
	printf("EVAL_PROVER_CL %12llu [us]\r\n", prover_runtime.prover_CL);
	printf("EVAL_PROVER_CR %12llu [us]\r\n", prover_runtime.prover_CR);
	printf("EVAL_PROVER_POE %12llu [us]\r\n", prover_runtime.prover_POE);


	fmpz_clear(C);
	fmpz_clear(z);
	fmpz_clear(y);
	fmpz_clear(p);
	fmpz_clear(z_tmp);
	fmpz_clear(zero);

	return 1;
}

int pf_init(_struct_proof_ *pf)
{
	fmpz_init((pf->alpha));
	fmpz_init((pf->yL));
	fmpz_init((pf->yR));
	fmpz_init((pf->POE_proof));
	commit_init(&(pf->CL));
	commit_init(&(pf->CR));

	return 1;	
}
int pf_clear(_struct_proof_ *pf)
{
	fmpz_clear((pf->alpha));
	fmpz_clear((pf->yL));
	fmpz_clear((pf->yR));
	fmpz_clear((pf->POE_proof));
	commit_clear(&(pf->CL));
	commit_clear(&(pf->CR));

	return 1;
}
int Spd(fmpz_t output, fmpz_t p, unsigned int d)
{
	int nbit = 0;
	d++;
	for(nbit=0; d != 0; (d >>= 1), nbit++);
	fmpz_pow_ui(output, p, (int)(nbit-1));
	return 1;
}

int EvalBounded_origin_verify(_struct_pp_ *pp, fmpz_t* C, const fmpz_t z, fmpz_t* y, fmpz_t* b, _struct_poly_* poly, _struct_verify_timer_* v_runtime) 
{
	static FILE *fp = NULL;
	static unsigned char buffer[10000]={0};
	static int isfirst = 0, flag = 1;
	static _struct_proof_ pf;
	static fmpz_t z_tmp;
	static fmpz_t y_tmp;
	static fmpz_t poe_w;
	static fmpz_t poe_u;
	static fmpz_t poe_x;
	static fmpz_t spd;

	TimerOn();
	if(isfirst == 0)
	{
		fp = fopen("./Txt/proof.txt", "r+");
		pf_init(&pf);
		fmpz_init(y_tmp);
		fmpz_init(z_tmp);
		fmpz_init(poe_w);
		fmpz_init(poe_u);
		fmpz_init(poe_x);	
		fmpz_init(spd);


		//TimerOn();
		// Spd(spd, pp->p, poly->d);
		//RunTime_eval += TimerOff();
		isfirst = 1;
	}
	v_runtime->total += TimerOff();

	if(poly->d == 1)
	{
		//TimerOn();
		fscanf(fp, "%s", buffer);

		fmpz_set_str(poly->Fx[0], buffer, 16);
		//RunTime_file_IO += TimerOff();


		TimerOn();

		fmpz_mul_2exp(z_tmp, *b, pp->security_level*4);
		 
		if(fmpz_cmp(poly->Fx[0], z_tmp) > 0){
			printf("bounded fail!! [ |f| > b ]\n");
			printf("f : "); fmpz_print(poly->Fx[0]); printf("\n");
			printf("b : "); fmpz_print(*b);			 printf("\n");
			flag = 0;
		}

		fmpz_mod(z_tmp, *y, pp->p);
		fmpz_mod(y_tmp, poly->Fx[0], pp->p);
		if(fmpz_cmp(z_tmp, y_tmp) != 0){
			printf("ERROR : f mod p != y mod p\n");
			printf("f : "); fmpz_print(y_tmp); printf("\n");
			printf("y : "); fmpz_print(z_tmp); printf("\n");
			flag = 0;
		}
		v_runtime->total += TimerOff();


		fmpz_t tmp;
		fmpz_init(tmp);

		TimerOn();
		fmpz_powm(tmp, pp->g, poly->Fx[0], pp->G);
		int g_f_calc = TimerOff();
		v_runtime->total += g_f_calc;
		v_runtime->check_g_f += g_f_calc;


		TimerOn();
		if(fmpz_equal(tmp, *C) != 1){
			printf("ERROR : g^f != C\n");
			printf("g^f : "); fmpz_print(tmp); printf("\n");
			printf("  C : "); fmpz_print(*C); printf("\n");
			flag = 0;
		}
		//RunTime_eval += TimerOff();

		// if(	flag == 1 )
		// 	printf("Verify Success!!\n");
		// else
		// 	printf("Verify Fail.....\n");
		v_runtime->total += TimerOff();

		pf_clear(&pf);
		isfirst = 0;
		fmpz_clear(z_tmp);
		fmpz_clear(y_tmp);
		fmpz_clear(poe_w);
		fmpz_clear(poe_u);
		fmpz_clear(poe_x);
		fclose(fp);

		return flag;
	}
	else if( ((poly->d)%2) == 1 )
	{
		//printf("d is odd  [d : %d -> d' : %d]\n", poly->d, poly->d + 1);
		TimerOn();
		//TimerOn2(&before[0]);
		fmpz_powm(*C, *C, pp->q, pp->G);
		fmpz_mul(*y, *y, z);
		fmpz_mod(*y, *y, pp->p);	// y=y*z mod p
		fmpz_set_ui(y_tmp, poly->d);
		fmpz_mul(*b, *b, y_tmp);	// b =  bd
		
		poly->d = poly->d + 1;				//d = d + 1		
		//RunTime[0] += TimerOff2(&before[0], &after[0]);	// 14

		//RunTime_eval += TimerOff();
		////RunTime_eval += //RunTime[0];
		v_runtime->total += TimerOff();
		return EvalBounded_origin_verify(pp, C, z, y, b, poly, v_runtime);
	}
	else
	{
		int i;
		int d_ = (poly->d)/ 2; //*d = ((*d+1)>>1)-1;		// P,V compute
		//printf("d is even [d : %d -> d' : %d]\n", poly->d, d_);
		
		TimerOn();
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.alpha, buffer, 16);
		//BN_hex2bn(&alpha, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.yL, buffer, 16);
		//BN_hex2bn(&yL, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.yR, buffer, 16);
		//BN_hex2bn(&yR, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CL.C, buffer, 16);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CR.C, buffer, 16);
		//BN_hex2bn(&CR.C, buffer);
		
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.POE_proof, buffer, 16);
		//RunTime_file_IO += TimerOff();
		
		v_runtime->fileIO += TimerOff();

		// printf("d_: %d\n", d_);
		TimerOn();
		fmpz_set_ui(z_tmp, d_);
		fmpz_powm(z_tmp, z, z_tmp, pp->p); // z_tmp = z^(d'+1) mod p
		fmpz_mul(z_tmp, z_tmp, pf.yR); //  z_tmp * * yr
		//fmpz_set(z_tmp, pf.yR);
		fmpz_mod(z_tmp, z_tmp, pp->p); // z_tmp* yr (mod p)
		fmpz_add(y_tmp, z_tmp, pf.yL); // z_tmp
		fmpz_mod(y_tmp, y_tmp, pp->p);
		//fmpz_print( pf.yR );	printf("\n");
		//fmpz_print( pf.yL );	printf("\n");

		//fmpz_print(y_tmp); printf("\n");
		//fmpz_print(*y); printf("\n");
		
		/*
		printf("----------------------");
		printf("\n");
		print("y_tmp: ");
		fmpz_print(y_tmp);
		printf("\n");
		print("y :");
		fmpz_print(y);
		printf("\n");
		*/
		if(fmpz_cmp(y_tmp, *y) != 0){		
			//RunTime_eval += TimerOff();
			printf("Fail Compare y..\n");
			//TimerOn();
		}
		//else
		//	printf("GOOD\n");
		//fmpz_print(y_tmp);	printf("\n");
		//fmpz_print(*y);	printf("\n");
		//RunTime[2] += TimerOff2(&before[2], &after[2]);

		//TimerOn2(&before[1]);
		int cl_inv_calc = 0;
		fmpz_set(poe_u, pf.CR.C);
		fmpz_invmod(poe_w, pf.CL.C, pp->G);
		fmpz_mul(poe_w, poe_w, *C);
		fmpz_mod(poe_w, poe_w, pp->G);
		v_runtime->total += TimerOff();
		//BN_copy(poe_u, CR.C);
		//BN_mod_inverse(poe_w, CL.C, pp->G, ctx);
		//BN_mod_mul(poe_w, poe_w, *C, pp->G, ctx);

		//RunTime[1] += TimerOff2(&before[1], &after[1]);
		//TimerOn2(&before[3]);
		if( verify_pk(pf.POE_proof, poe_w, poe_u, pp, d_, v_runtime, v_runtime->rnd++) == 0)
		{
			//RunTime_eval += TimerOff();
			printf("Fail POE\n");
			//TimerOn();
		}	
		
		//else{
		//	printf("Succ POE\n");
		//}
		/********************* POE
		*******************************/
		//RunTime[3] += TimerOff2(&before[3], &after[3]);

		//printf("y' <- (a*yL + yR) mod p \n");
		//TimerOn2(&before[4]);
		TimerOn();
		fmpz_mul(y_tmp, pf.alpha, pf.yL);
		fmpz_mod(y_tmp, y_tmp, pp->p);
		fmpz_add(*y, y_tmp, pf.yR);
		fmpz_mod(*y, *y, pp->p);
		v_runtime->total += TimerOff();

		//BN_mod_mul(y_tmp, alpha, yL, pp->p, ctx);
		//BN_mod_add(*y, y_tmp, yR, pp->p, ctx);
		
		//printf("C' <- CL^a CR\n");
		

		TimerOn();
		fmpz_powm(*C, pf.CL.C, pf.alpha, pp->G);
		fmpz_mul(*C, *C, pf.CR.C);
		fmpz_mod(*C, *C, pp->G);
		int c_alpha = TimerOff();
		v_runtime->total += c_alpha;
		v_runtime->CL_alpha += c_alpha;


		//BN_mod_exp(*C, CL.C, alpha, pp->G, ctx);
		//BN_mod_mul(*C, *C, CR.C, pp->G, ctx);

		//printf("b' <- b(p+1)/2\n");
		TimerOn();
		fmpz_mul_2exp(*b, *b, pp->security_level);
		// fmpz_set_ui(y_tmp,pp->security_level);
		// fmpz_get_d_2exp(y_tmp, y_tmp);
		// fmpz_add_ui(y_tmp,y_tmp,1);
		// fmpz_fdiv_q_2exp(y_tmp,y_tmp,1);		//BN_rshift1(y_tmp,y_tmp);
		// fmpz_mul(*b, *b, y_tmp);

		//BN_copy(y_tmp,pp->p);
		//BN_add_word(y_tmp,1);
		//BN_rshift1(y_tmp,y_tmp);
		//BN_mul(*b,*b,y_tmp,ctx);
		////printf("b : %s\n", BN_bn2hex(*b));

		//printf("f' <- a*fL + fR\n");
		poly->d = d_;
		//RunTime[4] += TimerOff2(&before[4], &after[4]);

		//printf("V run EvalBounded_verify(pp, C', z, y', d', b', f'(X))\n\n");
		//RunTime_eval += TimerOff();
		v_runtime->total += TimerOff();
		return EvalBounded_origin_verify(pp, C, z, y, b, poly, v_runtime);
	}
}
int Eval_verify(_struct_pp_* pp, _struct_commit_* cm, _struct_poly_* poly) // ( pp, z, y, d, f~(X) )
{
	int i;
	fmpz_t zero;// = BN_new();
	fmpz_t p;// = BN_new();
	fmpz_t C;// = BN_new();
	fmpz_t z;// = BN_new();
	fmpz_t z_tmp;// = BN_new();
	fmpz_t y;// = BN_new();

	_struct_verify_timer_ verify_runtime;
	verify_runtime.check_g_f = 0;
	verify_runtime.CL_alpha = 0;

	verify_runtime.POE = 0;
	verify_runtime.rnd = 0;
	verify_runtime.POE_r = (int*)calloc(poly->mu, sizeof(int));
	verify_runtime.POE_pf_l = (int*)calloc(poly->mu, sizeof(int));
	verify_runtime.POE_g_r = (int*)calloc(poly->mu, sizeof(int));
	verify_runtime.POE_total = (int*)calloc(poly->mu, sizeof(int));

	verify_runtime.fileIO = 0;
	verify_runtime.total = 0;

	_struct_verify_timer_* v_runtime = &verify_runtime;

	// int runtime = 0;
	// int *ver_runtime = &runtime;
	
	fmpz_init(C);
	fmpz_set(C, cm->C);

	fmpz_init_set_ui(zero,0);
	fmpz_init_set_ui(y,0);
	fmpz_init(p);
	fmpz_init_set_ui(z,100);
	fmpz_init_set_ui(z_tmp,1);

	fmpz_sub_ui(p, pp->p, 1);
	// fmpz_tdiv_q_2exp(p,p,1);



	// poly 계산 
	i = 0;
	do{
		fmpz_mul(zero, poly->Fx[i], z_tmp);
		fmpz_mod(zero, zero, pp->p);
		fmpz_add(y, y, zero);
		fmpz_mod(y, y, pp->p);
		fmpz_mul(z_tmp, z_tmp, z);
		fmpz_mod(z_tmp, z_tmp, pp->p);
		i++;
	}while(i<= poly->d);

	TimerOff();


	//printf("EvalBounded_verify Start\n");
	int flag;
	flag = EvalBounded_origin_verify(pp, &C, z, &y, &p, poly, v_runtime);

	printf("VERIFY_EVAL %12llu [us] [%d]\n", verify_runtime.total, flag);
	printf("VERIFY_EVAL_FILEIO %12llu [us] [%d]\n", verify_runtime.fileIO, flag);
	printf("VERIFY_EVAL_check g^f = c %12llu [us] [%d]\n", verify_runtime.check_g_f, flag);
	printf("VERIFY_EVAL_update CL^a %12llu [us] [%d]\n", verify_runtime.CL_alpha, flag);
	
	int sum = 0;
	printf("VERIFY_EVAL_POE %12llu [us] [%d]\n", verify_runtime.POE, flag);
	printf("VERIFY_EVAL_POE - remainder\n");
	for(int i=0;i<poly->mu;i++) {
		printf("%5d  ", verify_runtime.POE_r[i]);
		sum += verify_runtime.POE_r[i];
	}
	printf("subtotal: %d", sum); sum = 0;
	printf("\nVERIFY_EVAL_POE - pf^l\n");
	for(int i=0;i<poly->mu;i++){
		printf("%5d  ", verify_runtime.POE_pf_l[i]);
		sum += verify_runtime.POE_pf_l[i];
	} 
	printf("subtotal: %d", sum); sum = 0;
	printf("\nVERIFY_EVAL_POE - g^r\n");
	for(int i=0;i<poly->mu;i++){
		printf("%5d  ", verify_runtime.POE_g_r[i]);
		sum += verify_runtime.POE_g_r[i];
	} 
	printf("subtotal: %d", sum); sum = 0;
	printf("\nVERIFY_EVAL_POE - round total\n");
	for(int i=0;i<poly->mu;i++) printf("%d  ", verify_runtime.POE_total[i]);
	

	fmpz_clear(C);
	fmpz_clear(z);
	fmpz_clear(y);
	fmpz_clear(p);
	fmpz_clear(zero);

	return flag;
}
