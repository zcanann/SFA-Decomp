#ifndef MAIN_DLL_DIM_DIMBOSSTONSIL_H_
#define MAIN_DLL_DIM_DIMBOSSTONSIL_H_

#include "ghidra_import.h"

#define DIMBOSSTONSIL_OBJECT_TYPE 0x4b
#define DIMBOSSTONSIL_STATE_SIZE 0x410
#define DIMBOSSTONSIL_SCALE_OFFSET 0x274
#define DIMBOSSTONSIL_HEALTH_PHASE_OFFSET 0x354

void dll_DIM_BossGutSpik_update(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                undefined8 param_7,undefined8 param_8,uint param_9,
                                undefined4 param_10,int param_11,int param_12);
void DIMbosstonsil_func0B(void);
int DIMbosstonsil_setScale(int obj);
int DIMbosstonsil_getExtraSize(void);
int DIMbosstonsil_func08(void);
void DIMbosstonsil_render(void *obj,undefined4 p2,undefined4 p3,undefined4 p4,undefined4 p5,
                          char visible);
void DIMbosstonsil_hitDetect(void *obj);
void DIMbosstonsil_update(void *obj);
void DIMbosstonsil_init(int obj,undefined4 param_2,int isAltVariant);
void DIMbosstonsil_release(void);
void DIMbosstonsil_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSSTONSIL_H_ */
