#ifndef _POE_H
    #include "../hedder/dark_compiler.h"

    int eval_pk(fmpz_t pf, fmpz_t w, fmpz_t u, _struct_pp_ *pp, const int d);
    int eval_pk_test(fmpz_t pf, fmpz_t w,  fmpz_t u, _struct_poly_* fR, _struct_pp_ *pp, const int d);
    int eval_pk_precomputed(fmpz_t pf, fmpz_t w,  fmpz_t u, _struct_poly_* fR, _struct_pp_ *pp, const int d);
    int verify_pk(fmpz_t pf, fmpz_t w, fmpz_t u, _struct_pp_ *pp, const int d, _struct_verify_timer_* v_runtime, int i);
    #define _POE_H
#endif
