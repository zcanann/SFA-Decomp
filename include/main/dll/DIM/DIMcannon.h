#ifndef MAIN_DLL_DIM_DIMCANNON_H_
#define MAIN_DLL_DIM_DIMCANNON_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FUN_801ae184(u32 param_1,u32 param_2,u32 param_3,u32 param_4,
                 u32 param_5,char param_6);
void FUN_801ae2ec(u16 *param_1);
void FUN_801ae378(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,int param_12,u32 *param_13,
                 u32 param_14,u32 param_15,u32 param_16);
void FUN_801ae760(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
u32 FUN_801ae788(int param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801ae9e4(int obj);
void FUN_801aea18(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801aea40(int param_1);
void FUN_801aea44(int param_1);
void FUN_801aea8c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801aeab4(int param_1);
void FUN_801aecf8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10);
void FUN_801aef6c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801aef94(short *param_1);
void FUN_801af058(u16 *param_1,int param_2);
void FUN_801af0a0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801af0e4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_801af444(void);
void FUN_801af9e8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801afcf8(int param_1);
void FUN_801afe70(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801b0190(int param_1);
void FUN_801b01e8(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801b031c(int param_1);
void FUN_801b0388(u16 *param_1,u32 param_2,u32 param_3);
void FUN_801b050c(int param_1);
void FUN_801b054c(void);
void FUN_801b05b0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
void FUN_801b0a1c(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,int param_10);
void FUN_801b0d38(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_801b0dcc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b0df4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);

int imanimspacecraft_getExtraSize(void);
int imanimspacecraft_getObjectTypeId(void);
void imanimspacecraft_modelMtxFn(void);
u32 imanimspacecraft_func0B(int *obj);
int imanimspacecraft_setScale(int *obj, int bitIdx);
int imanimspacecraft_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);
void imanimspacecraft_free(int *obj);
void imanimspacecraft_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void imanimspacecraft_hitDetect(void);
void imanimspacecraft_update(int *obj);
void imanimspacecraft_init(int *obj);
void imanimspacecraft_release(void);
void imanimspacecraft_initialise(void);

int imspacethruster_getExtraSize(void);
int imspacethruster_getObjectTypeId(void);
void imspacethruster_free(int obj);
void imspacethruster_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void imspacethruster_hitDetect(void);
void imspacethruster_update(int *obj);
void imspacethruster_init(int *obj, u8 *params);
void imspacethruster_release(void);
void imspacethruster_initialise(void);

int imspacering_getExtraSize(void);
int imspacering_getObjectTypeId(void);
void imspacering_free(void);
void imspacering_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void imspacering_hitDetect(void);
void imspacering_update(s16 *obj);
void imspacering_init(s16 *obj, s8 *params);
void imspacering_release(void);
void imspacering_initialise(void);

int imspaceringgen_getExtraSize(void);
int imspaceringgen_getObjectTypeId(void);
void imspaceringgen_free(void);
void imspaceringgen_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void imspaceringgen_hitDetect(void);
void imspaceringgen_update(s16 *obj);
void imspaceringgen_init(int *obj);
void imspaceringgen_release(void);
void imspaceringgen_initialise(void);

int linkb_levcontrol_getExtraSize(void);
void linkb_levcontrol_update(int *obj);
void linkb_levcontrol_init(int *obj);

int link_levcontrol_getExtraSize(void);
void link_levcontrol_free(int obj);
void link_levcontrol_update(int *obj);
void link_levcontrol_updateAreaMusic(int *obj);
void link_levcontrol_applyEnterAreaEffects(int *obj);
void link_levcontrol_init(int *obj);

int lavaball1be_getExtraSize(int *obj);
int lavaball1be_getObjectTypeId(int *obj);
void lavaball1be_free(int obj);
void lavaball1be_render(int *obj, int p2, int p3, int p4, int p5);
void lavaball1be_hitDetect(void);
void lavaball1be_update(s16 *obj);
void lavaball1be_init(s16 *obj, u8 *params);
void lavaball1be_release(void);
void lavaball1be_initialise(void);
void lavaball1be_setScale(s16 *obj, int p2, int p3);
u32 lavaball1be_func11(int *obj);

int lavaball1bf_getExtraSize(void);
int lavaball1bf_getObjectTypeId(void);
void lavaball1bf_free(int obj, int mode);
void lavaball1bf_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void lavaball1bf_hitDetect(void);
void lavaball1bf_update(int *obj);
void lavaball1bf_init(s16 *obj, u8 *params);
void lavaball1bf_release(void);
void lavaball1bf_initialise(void);
int lavaball1bf_setScale(int *obj);
void lavaball1bf_func11(int *obj);

extern ObjectDescriptor gIMIcePillarObjDescriptor;
extern ObjectDescriptor13 gIMAnimSpaceCraftObjDescriptor;
extern ObjectDescriptor gIMSpaceThrusterObjDescriptor;
extern ObjectDescriptor gIMSpaceRingObjDescriptor;
extern ObjectDescriptor gIMSpaceRingGenObjDescriptor;
extern ObjectDescriptor12 gLavaBall1BEObjDescriptor;
extern ObjectDescriptor12 gLavaBall1BFObjDescriptor;

#endif /* MAIN_DLL_DIM_DIMCANNON_H_ */
