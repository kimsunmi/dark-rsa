#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

int main(int argc, char *argv[])
{
	FILE *fp;
	int LogD, Degree; 
	int security_level = 512;
	unsigned long long int RunTime_eval = 0, RunTime_file_IO = 0;
	_struct_pp_ pp;

	if(argc == 2){
		LogD = atoi(argv[1]);
	}
	else if(argc == 3)
	{
		security_level = atoi(argv[1]);
		LogD = atoi(argv[2]);	
	}
	else
		LogD = 4; 
	
	Degree = (1<<(LogD));
	
	TimerOn();
	pp_init(&pp);
	KeyGen_Class_setup(&pp, security_level, LogD);
	RunTime_eval = TimerOff();

	TimerOn();
	Write_pp("./Txt/pp.txt", &pp);
	RunTime_file_IO = TimerOff();

	printf("log(d) %d d-%d ", LogD, Degree);
	printf("qbit : 2^%d\n", (int)fmpz_bits(pp.q)-1);
	printf("KeyGen_Time_ %12llu [us]\n", RunTime_eval);
	printf("KeyGen_I/O__ %12llu [us]\n", RunTime_file_IO);

	// public parmaeter size: N, g, p
	fp = fopen("record_0119.txt", "a+");
	fprintf(fp,"-------public parameter----------\n");
	fprintf(fp, "N: %d \n", pp.security_level);
	fprintf(fp, "g: %d \n", (int)fmpz_bits(pp.g));
	fprintf(fp, "p: %d \n", (int)fmpz_bits(pp.p));
	fprintf(fp, "|N|+|g|+|p|: %d \n", (int)fmpz_bits(pp.g)+(int)fmpz_bits(pp.p)+pp.security_level);
	fclose(fp);

	fp = fopen("record/setup.txt", "a+");
	fprintf(fp, "%d %d %llu %llu\n", security_level, Degree, RunTime_file_IO, RunTime_eval);			
	fclose(fp);

	make_poly("./Txt/poly.txt", Degree, LogD);
	pp_clear(&pp);

	return 0;
}