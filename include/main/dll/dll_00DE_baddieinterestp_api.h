#ifndef MAIN_DLL_DLL_00DE_BADDIEINTERESTP_API_H_
#define MAIN_DLL_DLL_00DE_BADDIEINTERESTP_API_H_

#include "types.h"

void BaddieInterestP_free(void);
int BaddieInterestP_getExtraSize(void);
int BaddieInterestP_getObjectTypeId(void);
void BaddieInterestP_hitDetect(void);
void BaddieInterestP_init(void);
void BaddieInterestP_initialise(void);
void BaddieInterestP_release(void);
void BaddieInterestP_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void BaddieInterestP_update(int* obj);

#endif /* MAIN_DLL_DLL_00DE_BADDIEINTERESTP_API_H_ */
