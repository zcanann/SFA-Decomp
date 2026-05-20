#ifndef MAIN_DLL_DB_DBSTEALERWORM_H_
#define MAIN_DLL_DB_DBSTEALERWORM_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor15 gSB_GalleonObjDescriptor;
extern ObjectDescriptor gSB_PropellerObjDescriptor;
extern ObjectDescriptor gSB_ShipHeadObjDescriptor;
extern ObjectDescriptor gSB_ShipMastObjDescriptor;

void FUN_801e1588(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_801e1884(int param_1,int param_2);
undefined4
FUN_801e1edc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,int param_11);
undefined4 FUN_801e1ee4(void);
undefined4 FUN_801e1eec(uint param_1);
void FUN_801e1f70(int param_1,int param_2);
void FUN_801e2034(void);
void FUN_801e20e4(int param_1);
void FUN_801e217c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_801e2180(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
undefined4 FUN_801e2184(void);
void FUN_801e218c(int param_1);
void FUN_801e21b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801e2708(int param_1,int param_2);
void FUN_801e27a0(int param_1);
void FUN_801e27c4(int param_1);
void FUN_801e2940(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void SB_Galleon_func0E(void);
u8 SB_Galleon_render2(int *obj);
void SB_Galleon_modelMtxFn(void);
s32 SB_Galleon_func0B(int *obj);
void SB_Galleon_setScale(void);
int SB_Galleon_getExtraSize(void);
int SB_Galleon_func08(void);
void SB_Galleon_free(void);
void SB_Galleon_render(void);
void SB_Galleon_hitDetect(void);
void SB_Galleon_update(void);
void SB_Galleon_init(void);
void SB_Galleon_release(void);
void SB_Galleon_initialise(void);

int SB_Propeller_getExtraSize(void);
void SB_Propeller_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SB_Propeller_hitDetect(int obj);
void SB_Propeller_update(void);
void SB_Propeller_init(void);

int SB_ShipHead_getExtraSize(void);
int SB_ShipHead_func08(void);
void SB_ShipHead_free(int obj);
void SB_ShipHead_render(void);
void SB_ShipHead_update(void);
void SB_ShipHead_init(void);

int SB_ShipMast_getExtraSize(void);
int SB_ShipMast_func08(void);
void SB_ShipMast_free(void);
void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SB_ShipMast_hitDetect(void);
void SB_ShipMast_init(void);
void SB_ShipMast_release(void);
void SB_ShipMast_initialise(void);

#endif /* MAIN_DLL_DB_DBSTEALERWORM_H_ */
