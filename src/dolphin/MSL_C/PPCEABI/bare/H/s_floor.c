#include "dolphin.h"

extern const double lbl_803E7DB0;
extern const double lbl_803E7DB8;
extern const double lbl_803E7DC0;
extern const double lbl_803E7DC8;
extern const double lbl_803E7DD0;
extern const double lbl_803E7DD8;
extern const double lbl_803E7DE0;
extern const double lbl_803E7DE8;
extern const double lbl_803E7DF0;
extern const double lbl_803E7DF8;
extern const double lbl_803E7E00;
extern const double lbl_803E7E08;
extern const double lbl_803E7E10;

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

const double lbl_803E7DB0 = 0.9999999999999805;
const double lbl_803E7DB8 = -0.16666666666563978;
const double lbl_803E7DC0 = 0.008333333318980809;
const double lbl_803E7DC8 = -0.00019841261464659544;
const double lbl_803E7DD0 = 2.7554973093759717e-06;
const double lbl_803E7DD8 = -2.473889883359452e-08;
const double lbl_803E7DE0 = 1.0;
const double lbl_803E7DE8 = -0.4999999999999672;
const double lbl_803E7DF0 = 0.041666666665824886;
const double lbl_803E7DF8 = -0.001388888881954176;
const double lbl_803E7E00 = 2.4801561642773723e-05;
const double lbl_803E7E08 = -2.755268200651971e-07;
const double lbl_803E7E10 = 2.048770813211803e-09;
