extern double lbl_803E7C00;
extern double lbl_803E7C08;
extern double lbl_803E7C10;
extern unsigned int __cvt_fp2unsigned(double x);

typedef union IntDouble {
    double d;
    struct {
        unsigned int hi;
        unsigned int lo;
    } words;
} IntDouble;

double tan(int* out_n, float x)
{
    unsigned int n;
    double ax;
    double scaled;
    IntDouble conv;

    ax = __fabsf(x);
    scaled = lbl_803E7C00 * ax;
    n = (__cvt_fp2unsigned(scaled) + 1) & ~1U;
    *out_n = n;
    conv.words.lo = n;
    conv.words.hi = 0x43300000;
    return ax - lbl_803E7C08 * (conv.d - lbl_803E7C10);
}
