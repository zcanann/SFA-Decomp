#ifndef MAIN_DLL_CR_CRSNOWBIKE_H_
#define MAIN_DLL_CR_CRSNOWBIKE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor12 gSC_levelcontrolObjDescriptor;
extern ObjectDescriptor gSC_MusicTreeObjDescriptor;

void FUN_801dafdc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_801db57c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10);
void FUN_801db580(undefined4 param_1);
void FUN_801db5b8(short *param_1,int param_2);
undefined4 FUN_801db670(int param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801db7b4(int param_1,undefined param_2);
void FUN_801db8c4(void);
void FUN_801db924(int param_1);
void FUN_801db94c(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);

u8 sc_levelcontrol_func11(int *obj);
void sc_levelcontrol_setScale(void);
int sc_levelcontrol_getExtraSize(void);
int sc_levelcontrol_func08(void);
void sc_levelcontrol_free(void);
void sc_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void sc_levelcontrol_hitDetect(void);
void sc_levelcontrol_update(void);
void sc_levelcontrol_init(void);
void sc_levelcontrol_release(void);
void sc_levelcontrol_initialise(void);

int sc_musictree_getExtraSize(void);
int sc_musictree_func08(void);
void sc_musictree_free(void);
void sc_musictree_render(void);
void sc_musictree_hitDetect(void);
void sc_musictree_update(void);
void sc_musictree_init(void);
void sc_musictree_release(void);
void sc_musictree_initialise(void);

#endif /* MAIN_DLL_CR_CRSNOWBIKE_H_ */
