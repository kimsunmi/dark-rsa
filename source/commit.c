#include "../hedder/codetimer.h"
#include "../hedder/dark_compiler.h"
#include "../hedder/util.h"
#include <omp.h>
#include <stdlib.h>
#include <unistd.h>

fmpz_t** fmpz_pre;
int fmpz_pre_d;

int commit_new(_struct_commit_* cm, _struct_pp_ pp, _struct_poly_ poly)
{
	unsigned long long int RunTime_file_IO = 0, RunTime_commit = 0;

	int flag = 1, i = 0;
	fmpz_t fmpz_tmp;

	fmpz_init(fmpz_tmp);
	fmpz_one(cm->C);
	
	/////pre computation
	static int isfirst = 1;
	static int num_threads, max_threads;
	static fmpz_t* parallel_tmp1;
	static fmpz_t* parallel_tmp2;

	if(isfirst || poly.d > fmpz_pre_d)
	{
		TimerOff();
		printf("Start precomputation\n");
		printf("commit- poly.d: %d\n", poly.d);
		fmpz_pre_d = poly.d;
		int poe_block = fmpz_bits(pp.q)-1;

		if(isfirst == 0)
		{
			for(i=0; i<fmpz_pre_d; i++)
			{
				for(int j = 0; j<poe_block; j++)
					fmpz_clear(fmpz_pre[i][j]);
			}
		}
		else
			isfirst = 0;
		(fmpz_pre) = (fmpz_t**)calloc(fmpz_pre_d, sizeof(fmpz_t*));
		for(i=0; i<fmpz_pre_d; i++){
			(fmpz_pre[i]) = (fmpz_t*)calloc(poe_block, sizeof(fmpz_t));
		}

		max_threads = 1; //(int)omp_get_max_threads();
		// omp_set_num_threads(max_threads);
		num_threads =  max_threads;//max_threads;
		parallel_tmp1 = (fmpz_t*)malloc(sizeof(fmpz_t) * num_threads);
		parallel_tmp2 = (fmpz_t*)malloc(sizeof(fmpz_t) * num_threads);
		
		// #pragma omp parallel for
		for(int i = 0; i<num_threads; i++){
			fmpz_init(parallel_tmp1[i]);
			fmpz_init(parallel_tmp2[i]);
		}	

		// #pragma omp parallel for
		for(int i=0; i < fmpz_pre_d; i++)
			for(int j = 0; j < poe_block; j++)
				fmpz_init(fmpz_pre[i][j]);

		//printf("POE %d\n", poe_block);
		//fmpz_init(fmpz_pre[0]);
		fmpz_set(fmpz_pre[0][0], pp.g);

		//for(int th = 1; th < num_threads; th++)
		//{
		//	fmpz_powm(fmpz_pre[th][0], fmpz_pre[th-1][0], pp.q, pp.G);
		//}
		//#pragma omp parallel for
		//for(int i = 0; i<num_threads; i++){
		//	fmpz_zero(parallel_tmp1[i]);
		//	fmpz_setbit(parallel_tmp1[i], (fmpz_bits(pp.q)-1)*num_threads);
		//}
		//#pragma omp parallel for
		//for(int j = 0; j <num_threads; j++)
		//{
		//	for(int i=j+num_threads; i<fmpz_pre_d; i+=num_threads)
		//	{
		//		fmpz_powm(fmpz_pre[i][0], fmpz_pre[i-num_threads][0], parallel_tmp1[j], pp.G);
		//	}
		//}
		char str1[100] = "precom/precompute-";
		char str2[3000] = {0};
		sprintf(str2, "%d", fmpz_pre_d );
		strcat(str1, str2);
		strcat(str1, ".txt");


		FILE *fp;
		printf("%s\r\n",str1);
		if(access(str1, R_OK) >= 0)
		{
			fp = fopen(str1, "r");
			printf("read mode\r\n");
			fscanf(fp, "%s", str2);		
			fmpz_set_str(pp.G, str2, 16);

			fscanf(fp, "%s", str2);		
			fmpz_set_str(pp.g, str2, 16);
			Write_pp("./Txt/pp.txt", &pp);
			fmpz_set(fmpz_pre[0][0], pp.g);
			for(int i=1; i<fmpz_pre_d; i++)
			{
				fscanf(fp, "%s", str2);		
				fmpz_set_str(fmpz_pre[i][0], str2, 16);
				// if(i%(fmpz_pre_d/10) == 0)
				// 	printf("%6.3f%%\r\n", 100.0*i/fmpz_pre_d);
			}
			fclose(fp);
		}
		else
		{					
		// 	FILE *fp;
		// 	printf("%s\r\n",str1);
		// 	fp = fopen(str1, "w");
		// 	fprintf(fp, "%s\r\n", fmpz_get_str(NULL, 16, pp.G));
		// 	fprintf(fp, "%s\r\n", fmpz_get_str(NULL, 16, fmpz_pre[0][0]));
		// only g
			TimerOn();
			for(int i=1; i<fmpz_pre_d; i++)
			{
				fmpz_powm(fmpz_pre[i][0], fmpz_pre[i-1][0], pp.q, pp.G);
				// fprintf(fp, "%s\r\n", fmpz_get_str(NULL, 16, fmpz_pre[i][0]));
				if(i%1024 == 0)
					printf("%6.3f%%\r\n", 100.0*i/fmpz_pre_d);
			}
			RunTime_commit = TimerOff();
		//	fclose(fp);
		}

		// fmpz_setbit(fmpz_tmp, 128);
		// for(int i = 0; i<fmpz_pre_d; i++)
		// {
		// 	for(int j=1; j<poe_block; j++)
		// 	{
		// 		fmpz_powm(fmpz_pre[i][j], fmpz_pre[i][j-1], fmpz_tmp, pp.G);
		// 	}
		// }
	
		printf("Commit__PRE_ %12llu [us]\n", RunTime_commit);
		fp = fopen("record/precomputation.txt", "a+");
		fprintf(fp, "%d %d %llu [%d]\n", pp.security_level, fmpz_pre_d, RunTime_commit, num_threads);			
		fclose(fp);

		TimerOn();
	}
	//////////
	num_threads =  1; //(int)omp_get_max_threads();
	// #pragma omp parallel for
	for(int i = 0; i<num_threads; i++){
		fmpz_one(parallel_tmp2[i]);
	}	

	// #pragma omp parallel for
	for(int j = 0; j<num_threads; j++)
	{
		for(int i = j*poly.d/num_threads; i <  (j+1)*poly.d/num_threads; i++)
		{
			// 
			if(fmpz_is_zero(poly.Fx[i])==0){
				fmpz_powm(parallel_tmp1[j], fmpz_pre[i][0], poly.Fx[i], pp.G);
				fmpz_mul(parallel_tmp2[j], parallel_tmp2[j], parallel_tmp1[j]);
				fmpz_mod(parallel_tmp2[j], parallel_tmp2[j], pp.G);
			}
			
		}
	}

	for(int j = 0; j<num_threads; j++)
	{
		fmpz_mul(cm->C, cm->C, parallel_tmp2[j]);
		fmpz_mod(cm->C, cm->C, pp.G);
	}

	//printf("\n");
	fmpz_clear(fmpz_tmp);

	return flag;
}


int commit_new_old(_struct_commit_* cm, _struct_pp_ pp, _struct_poly_ poly)
{
	int flag = 1, i = 0;
	fmpz_t fmpz_tmp;

	fmpz_init(fmpz_tmp);
	fmpz_one(cm->C);

	for(i = poly.d - 1; i >= 0; i--)
	{
		//printf("%d\n", i);
		fmpz_powm(cm->C, cm->C, pp.q, pp.G);
		fmpz_powm(fmpz_tmp, pp.g, poly.Fx[i], pp.G);

		fmpz_mul(fmpz_tmp, cm->C, fmpz_tmp);
		fmpz_mod(cm->C, fmpz_tmp, pp.G);
	}
	fmpz_clear(fmpz_tmp);

	return flag;
}

int commit_init(_struct_commit_* cm){
	fmpz_init(cm->C);
	return 1;
}
int commit_clear(_struct_commit_* cm){
	fmpz_clear(cm->C);
	return 1;
}
