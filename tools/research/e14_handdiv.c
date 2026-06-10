typedef float f32;
extern int g(int);
extern f32 gf;
int probe(int p1, int p2, int p3) {
    int copyA;
    int copyB;
    int md1;
    int md2;
    copyA = g(p1);
    copyB = g(p2);
    md1 = 500; if (p1 > 2) md1 = g(p3);
    { int q = (int)(((long long)p3 * 0x92492493LL) >> 32); q += p3; q >>= 2; q += (unsigned)q >> 31; md2 = q; } if (p2 > 3) md2 = g(p1);
    g(copyA); g(copyB); g(md1); g(md2);
    g(p1); g(p2); g(p3);
    return copyA + copyB + md1 + md2 + p1 + p2 + p3;
}
