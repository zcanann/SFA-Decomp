#ifndef MAIN_DLL_DIM_DIMBOULDER_H_
#define MAIN_DLL_DIM_DIMBOULDER_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gIMIceMountainObjDescriptor;
extern ObjectDescriptor gCRrockfallObjDescriptor;
extern ObjectDescriptor gMagicLightObjDescriptor;
extern ObjectDescriptor gIMIcePillarObjDescriptor;

void imicemountain_updateEventState(int *obj);
void FUN_801ac24c(int param_1);
void FUN_801ac340(int param_1,u8 *param_2);
void FUN_801ac490(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
u32 FUN_801accf4(int param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801acd7c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801acda4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801ad248(int param_1);
double FUN_801ad24c(int param_1);
void FUN_801ad318(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801ad350(u64 param_1,double param_2,double param_3,double param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8);
void FUN_801ad97c(int param_1,int param_2);
void FUN_801ad980(void);
u32
FUN_801ad984(u64 param_1,u64 param_2,double param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,int param_9);
void FUN_801adb28(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801adbec(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801adc20(u16 *param_1);
void FUN_801adc9c(u16 *param_1,int param_2);
void FUN_801adca0(u16 *param_1,u16 *param_2,u32 param_3,u32 param_4,
                 u32 param_5,u32 param_6,char param_7,int param_8,int param_9);
u32
FUN_801addec(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,u32 param_10,
            ObjAnimUpdateState *animUpdate,u32 param_12,u32 *param_13,u32 param_14,
            u32 param_15,u32 param_16);

int imicemountain_getExtraSize(void);
int imicemountain_getObjectTypeId(void);
void imicemountain_free(void);
int IMIceMountain_SeqFn(void *obj, int unused, ObjAnimUpdateState *animUpdate);
void imicemountain_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void imicemountain_hitDetect(void);
void imicemountain_update(int* obj);
void imicemountain_init(int* obj);

int crrockfall_getExtraSize(void);
int crrockfall_getObjectTypeId(void);
void crrockfall_free(void);
void crrockfall_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void crrockfall_hitDetect(void);
void crrockfall_update(int* obj);
void crrockfall_init(int* obj, u8* params);
void crrockfall_release(void);
void crrockfall_initialise(void);

int magiclight_getExtraSize(int *obj);
int magiclight_getObjectTypeId(void);
void magiclight_free(int obj);
void magiclight_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void magiclight_hitDetect(void);
void magiclight_update(int obj);
void magiclight_init(int* obj, u8* params);
int magiclight_SeqFn(int *obj);
void magiclight_release(void);
void magiclight_initialise(void);

int dll_16C_getExtraSize(void);
int dll_16C_getObjectTypeId(void);
void dll_16C_free(int *obj);
void dll_16C_hitDetect(void *obj);
void dll_16C_init(void *obj, void *arg2);
int dll_16C_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);
void dll_16C_release(void);
void dll_16C_initialise(void);

int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);
void imicepillar_free(void);
void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void imicepillar_hitDetect(void);
void imicepillar_update(void);
void imicepillar_init(void);
void imicepillar_release(void);
void imicepillar_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOULDER_H_ */
