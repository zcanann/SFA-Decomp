#ifndef MAIN_DLL_CF_LASER_H_
#define MAIN_DLL_CF_LASER_H_

#include "ghidra_import.h"

typedef struct LaserState {
  s16 primarySequenceId;
  s16 secondarySequenceId;
  u8 sequenceLatched;
} LaserState;

typedef struct LaserObject {
  u8 pad00[0xAC];
  s8 modeIndex;
  u8 padAD[0xAF - 0xAD];
  u8 statusFlags;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  LaserState *state;
} LaserObject;

#define LASER_OBJECT_STATUS_08 0x08

void laser_initUnsupported(void);
void laserObj_update(int param_1);
void laserObj_init(undefined2 *param_1,int param_2);
undefined4
laser_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
             undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
             undefined4 param_10,int param_11,int param_12,undefined4 param_13,
             undefined4 param_14,undefined4 param_15,undefined4 param_16);
void laser_render(int param_1);
void laser_release(undefined4 param_1);
void laser_hitDetect(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     int param_9);
void FUN_80209d50(void);
void FUN_80209d70(void);
void FUN_80209d90(void);
void FUN_80209db0(void);
void FUN_80209dd0(void);
void FUN_80209df0(void);
void laser_free(int param_1);

#endif /* MAIN_DLL_CF_LASER_H_ */
