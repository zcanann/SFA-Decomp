#ifndef MAIN_DLL_CRATE2_H_
#define MAIN_DLL_CRATE2_H_

#include "ghidra_import.h"

void dfpstatue1_updateState(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

extern char sDfperchwitchInitNoLongerSupported[];

int dfperchwitch_getExtraSize(void);
void dfperchwitch_free(void);
void dfperchwitch_render(void);
void dfperchwitch_hitDetect(void);
void dfperchwitch_update(void);
void dfperchwitch_init(void);
void dfperchwitch_release(void);
void dfperchwitch_initialise(void);

#endif /* MAIN_DLL_CRATE2_H_ */
