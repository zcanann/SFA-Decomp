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
    md2 = 600; if (p2 > 3) md2 = g(p1);
    g(copyA); g(copyB); g(md1); g(md2);
    g(p1); g(p2); g(p3);
    return copyA + copyB + md1 + md2 + p1 + p2 + p3;
}
