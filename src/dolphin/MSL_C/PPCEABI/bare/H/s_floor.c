#include "dolphin.h"

extern double lbl_803E7DB0;
extern double lbl_803E7DB8;
extern double lbl_803E7DC0;
extern double lbl_803E7DC8;
extern double lbl_803E7DD0;
extern double lbl_803E7DD8;
extern double lbl_803E7DE0;
extern double lbl_803E7DE8;
extern double lbl_803E7DF0;
extern double lbl_803E7DF8;
extern double lbl_803E7E00;
extern double lbl_803E7E08;
extern double lbl_803E7E10;

double tan(int* out_n, float x);

float floor(float x) {
    int n;
    double y;
    double y2;

    y = tan(&n, x);
    n += (*(u32*)&x >> 29) & 4;
    y2 = y * y;

    switch (n & 6) {
        case 0:
            return (float)(y * (((((lbl_803E7DD8 * y2 + lbl_803E7DD0) * y2 + lbl_803E7DC8) * y2
                                  + lbl_803E7DC0)
                                     * y2
                                 + lbl_803E7DB8)
                                    * y2
                                + lbl_803E7DB0));
        case 2:
            return (float)((((((lbl_803E7E10 * y2 + lbl_803E7E08) * y2 + lbl_803E7E00) * y2 + lbl_803E7DF8) * y2
                              + lbl_803E7DF0)
                                 * y2
                             + lbl_803E7DE8)
                                * y2
                            + lbl_803E7DE0);
        case 4:
            return (float)(-(y * (((((lbl_803E7DD8 * y2 + lbl_803E7DD0) * y2 + lbl_803E7DC8) * y2
                                    + lbl_803E7DC0)
                                       * y2
                                   + lbl_803E7DB8)
                                      * y2
                                  + lbl_803E7DB0)));
        default:
            return (float)(-(y2
                                 * (((((lbl_803E7E10 * y2 + lbl_803E7E08) * y2 + lbl_803E7E00) * y2
                                      + lbl_803E7DF8)
                                         * y2
                                     + lbl_803E7DF0)
                                        * y2
                                    + lbl_803E7DE8)
                             + lbl_803E7DE0));
    }
}
