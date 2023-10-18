#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

int main()
{
    unsigned long long int RunTime_eval = 0, RunTime_file_IO = 0;
	int d_;
    FILE *fp;
  	_struct_pp_ pp;
	_struct_commit_ cm;
	_struct_poly_ poly;

	fp = fopen("./Txt/proof.txt", "w");
	fclose(fp);

	////////////////////////////////////////////////////////////////////////////
    pp_init(&pp);
    commit_init(&cm);

	TimerOn();
	Read_pp("./Txt/pp.txt", &pp);
	Read_poly("./Txt/poly.txt", &poly);
	RunTime_file_IO = TimerOff();
	
	TimerOn();
	commit_new(&cm, pp, poly);
	RunTime_eval = TimerOff();

	TimerOn();
	Write_Commit("./Txt/commit.txt", &cm);
	RunTime_file_IO += TimerOff();

	printf("Commit_TIME_ %12llu [us]\n", RunTime_eval);
	printf("Commit_I/O__ %12llu [us]\n\n", RunTime_file_IO);

	fp = fopen("record/commit.txt", "a+");
	fprintf(fp, "%d %d %llu %llu\n", pp.security_level, poly.d, RunTime_file_IO, RunTime_eval);			
	fclose(fp);

	pp_clear(&pp);
	commit_clear(&cm);	
	poly_clear(&poly);
	////////////////////////////////////////////////////////////////////////////	

	Read_poly("./Txt/poly.txt", &poly);
	d_ = poly.d;
	int iter = 1; //(21 - (int)(log(poly.d)/log(2)))*10 < 500 ? (21 - (int)(log(poly.d)/log(2)))*10 : 500;
	poly_clear(&poly);

	printf("d_: %d\n", d_);
	printf("iter %d\r\n", iter);

	for(int i = 0; i<iter; i++){
		fp = fopen("./Txt/proof.txt", "w");
		// printf("fp: %p", fp);
		// fprintf(fp, "\r");
		// fseek(fp, 0, SEEK_SET); 
		fclose(fp);
		pp_init(&pp);
		commit_init(&cm);

		TimerOn();
		Read_pp("./Txt/pp.txt", &pp);
		Read_Commit("./Txt/commit.txt", &cm);
		Read_poly("./Txt/poly.txt", &poly);
		RunTime_file_IO += TimerOff();

		TimerOn();
		Eval_prover(&pp, &cm, &poly, 0);
		RunTime_eval = TimerOff();		
		
		pp_clear(&pp);
		commit_clear(&cm);
		poly_clear(&poly);	
	}
	// printf("EVAL_PROVER0 %12llu [us] [%3d]\r\n", RunTime_eval/iter, iter);
	long long int tmp = RunTime_eval;
	// RunTime_eval = 0;
	// for(int i = 0; i<iter; i++){
	// 	fp = fopen("./Txt/proof.txt", "w");
	// 	fprintf(fp, "\r");
	// 	fseek(fp, 0, SEEK_SET); 
	// 	fclose(fp);
	// 	pp_init(&pp);
	// 	commit_init(&cm);

	// 	TimerOn();
	// 	Read_pp("./Txt/pp.txt", &pp);
	// 	Read_Commit("./Txt/commit.txt", &cm);
	// 	Read_poly("./Txt/poly.txt", &poly);
	// 	RunTime_file_IO += TimerOff();

	// 	TimerOn();
	// 	Eval_prover(&pp, &cm, &poly, 1);
	// 	RunTime_eval += TimerOff();		
		
	// 	pp_clear(&pp);
	// 	commit_clear(&cm);
	// 	poly_clear(&poly);		
	// }
	// printf("EVAL_PROVER1 %12llu [us] [%3d]\r\n", RunTime_eval/iter, iter);
	printf("EVAL___I/O__ %12llu [us] [%3d]\r\n\n", RunTime_file_IO/(iter), iter);


	fp = fopen("record/eval_prove.txt", "a+");
	fprintf(fp, "%d %d %llu %llu %llu\n", pp.security_level, d_, RunTime_file_IO/(iter), tmp/iter, RunTime_eval/iter);			
	fclose(fp);

	return 0;
}
