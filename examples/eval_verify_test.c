#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

int main()
{
	unsigned long long int RunTime_eval = 0, RunTime_file_IO = 0;

	FILE *fp;
  	_struct_pp_ pp;
	_struct_commit_ cm;
	_struct_poly_ poly;

	pp_init(&pp);
    commit_init(&cm);

	// TimerOn();
	// Read_pp("./Txt/pp.txt", &pp);
	// Read_Commit("./Txt/commit.txt", &cm);
	Read_poly("./Txt/poly.txt", &poly);
	// RunTime_file_IO = TimerOff();
	int d_ = poly.d;
	int flag = 1;

	int iter = 1;//(1<<(21 - (int)(log(poly.d)/log(2))))*2 < 1000 ? (1<<(21 - (int)(log(poly.d)/log(2))))*2 : 1000;
	poly_clear(&poly);
	//TimerOn();
	for(int i = 0; i<iter; i++){
		pp_init(&pp);
		commit_init(&cm);

		TimerOn();
		Read_pp("./Txt/pp.txt", &pp);
		Read_Commit("./Txt/commit.txt", &cm);
		Read_poly("./Txt/poly.txt", &poly);
		RunTime_file_IO += TimerOff();

		TimerOn();
		flag &= Eval_verify(&pp, &cm, &poly);
		RunTime_eval += TimerOff();	
		for(int j = 0; j < poly.d; j++)
			fmpz_clear(poly.Fx[j]);
		pp_clear(&pp);
		commit_clear(&cm);	
	}

	// printf("EVAL_VERIFY_ %12llu [us]\n", RunTime_eval/iter);
	printf("\nVERIFY_I/O__ %12llu [us] [%d - %d]\n", RunTime_file_IO/iter, iter, flag);

	fp = fopen("record/eval_verify.txt", "a+");
	fprintf(fp, "%d %d %llu %llu [%d]\n", pp.security_level, d_, RunTime_file_IO/iter, RunTime_eval/iter, flag);			
	fclose(fp);

	fp = fopen("record/size.txt", "a+");
	fprintf(fp, "%d %d %d %d %d [%d]\n", pp.security_level, d_, getfilesize("Txt/pp.txt"), getfilesize("Txt/commit.txt"), getfilesize("Txt/proof.txt"), flag);		
	fclose(fp);	

	poly_clear(&poly);

	return 0;
}
