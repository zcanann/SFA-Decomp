#ifndef MAIN_DLL_CF_LASER_H_
#define MAIN_DLL_CF_LASER_H_

#include "ghidra_import.h"

typedef struct LaserState {
  s16 primarySequenceId;
  s16 secondarySequenceId;
  u8 sequenceLatched;
} LaserState;

typedef struct LaserObjectMapData {
  u8 pad00[0x18];
  s8 modeIndex;
  u8 pad19[0x1E - 0x19];
  s16 primarySequenceId;
  s16 secondarySequenceId;
} LaserObjectMapData;

typedef struct LaserObject {
  s16 modeWord;
  u8 pad02[0xAC - 2];
  s8 modeIndex;
  u8 padAD[0xAF - 0xAD];
  u8 statusFlags;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  LaserState *state;
} LaserObject;

#define LASER_OBJECT_STATUS_ACTIVE 0x01
#define LASER_OBJECT_STATUS_DISABLED 0x08
#define LASER_OBJECT_FLAGS_SEQUENCE_CONTROL 0x6000

#define LASEROBJ_MODE_SEQUENCE_A 1
#define LASEROBJ_MODE_SEQUENCE_B 2
#define LASEROBJ_MODE_WORD_SHIFT 8

#define LASEROBJ_SEQUENCE_A_EVENT 0x2e8
#define LASEROBJ_SEQUENCE_B_EVENT 0x83c
#define LASEROBJ_SEQUENCE_B_TRIGGER_A 7
#define LASEROBJ_SEQUENCE_B_TRIGGER_B 0xd
#define LASEROBJ_SEQUENCE_B_TRIGGER_A_VALUE 8
#define LASEROBJ_SEQUENCE_B_TRIGGER_B_VALUE 2

#define LASEROBJ_MAIN_SEQUENCE_A_EVENT 0x123
#define LASEROBJ_MAIN_SEQUENCE_B_EVENT 0x83b

int laser_getExtraSizeUnsupported(void);
int laser_func08(void);
void laser_freeUnsupported(void);
void laser_renderUnsupported(void);
void laser_hitDetectUnsupported(void);
void laser_updateUnsupported(void);
void laser_init(void);
void laser_releaseUnsupported(void);
void laser_initialiseUnsupported(void);
int laserObj_getExtraSize(void);
int laserObj_func08(void);
void laserObj_free(void);
void laserObj_render(void);
void laserObj_hitDetect(void);
void laserObj_update(LaserObject *obj);
void laserObj_init(LaserObject *obj,LaserObjectMapData *mapData);
void laserObj_release(void);
void laserObj_initialise(void);
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
