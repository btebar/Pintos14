#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H
#define P 17
#define Q 14
#define assert(P, Q) ((P+Q == 31) && "P+Q != 31")

#define  F (1<<(Q))

#define n_to_fixed(n) (n * F)
#define x_rounded_zero(x) (x / F)
#define x_round_nearest(x) (x > 0) ?  (x + F/2)/F :  (x - F/2)/F
#define add(x, y) ((x) + (y))
#define subtract(x, y) (x-y)
#define add_with_n(x, n) (x + n*F)
#define subtract_n(x, n) (x - n*F)
#define mult_fixed_point(x, y) (((int64_t) x) *y/F)
#define mult_by_n(x, n) (x * n)
#define div_fixed_point(x, y) (((int64_t) x) * F/ y)
#define div_by_n(x, n) (x/n)


#endif
