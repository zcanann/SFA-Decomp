#ifndef MAIN_DLL_DLL_13C_H_
#define MAIN_DLL_DLL_13C_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct PollenFragmentConfig {
  s16 spawnSfxId;
  s16 field02;
  s16 field04;
  s16 effectObjectId;
  s16 field08;
  s16 field0A;
  f32 scale;
  s16 field10;
  u16 flags;
} PollenFragmentConfig;

typedef struct PollenExtra {
  s16 phaseX;            /* 0x00: random drift phase seed */
  s16 unk02;             /* 0x02 */
  s16 phaseY;            /* 0x04: random drift phase seed */
  s16 phaseSpeed;        /* 0x06: random drift rate */
  f32 settleVelocity;    /* 0x08: settle/freeze velocity baseline */
  f32 driftVelocity;     /* 0x0C: initial drift velocity */
  s16 unk10;             /* 0x10 */
  s16 fragmentSpawnTimer;/* 0x12 */
} PollenExtra;

#define POLLEN_FRAGMENT_OBJECT_ID 0x482
#define POLLEN_FRAGMENT_SETUP_SIZE 0x24
#define POLLEN_FRAGMENT_SETUP_KIND 5
#define POLLEN_FRAGMENT_BURST_COUNTER_START 5
#define POLLEN_FRAGMENT_RANDOM_ANGLE_MAX 0xffff
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MIN -50
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MAX 50
#define POLLEN_FRAGMENT_SPAWN_TIMER_FRAMES 60
#define POLLEN_FRAGMENT_PARENT_OBJECT_OFFSET 0xc4

void kaldachompspit_render(void *obj, int p2, int p3, int p4, int p5, s8 visible);
void kaldachompspit_hitDetect(void);
void kaldachompspit_init(int obj);
void kaldachompspit_release(void);
void kaldachompspit_initialise(void);
void FUN_80169d38(u64 param_1,u64 param_2,u64 param_3,double param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
int FUN_8016a534(double param_1,double param_2,float *param_3,float *param_4,char param_5);
void FUN_8016a6d4(int obj);
void FUN_8016a708(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
void FUN_8016aa90(u32 param_1);
void FUN_8016aae4(int obj);
void FUN_8016ab18(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8016ab40(int param_1);
int pinponspike_getExtraSize(void);
int pinponspike_getObjectTypeId(void);
void pinponspike_free(int obj);
void pinponspike_render(void);
void pinponspike_hitDetect(void);
void pinponspike_update(int obj);
void pinponspike_init(int obj);
void pinponspike_release(void);
void pinponspike_initialise(void);
void FUN_8016aba8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_8016ae64(double param_1,double param_2,double param_3,u64 param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8,int param_9);
int pollen_getExtraSize(void);
int pollen_getObjectTypeId(void);
void pollen_free(int obj);
void pollen_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void pollen_hitDetect(int obj);
void pollen_update(int obj);
void pollen_init(int obj);
void pollen_release(void);
void pollen_initialise(void);
int pollenfragment_getExtraSize(void);
int pollenfragment_getObjectTypeId(void);
void pollenfragment_free(int obj);
void pollenfragment_render(int *obj, int p2, int p3, int p4, int p5);
void pollenfragment_hitDetect(int obj);
void pollenfragment_update(int obj);
void pollenfragment_init(int obj,int config);
void pollenfragment_release(void);
void pollenfragment_initialise(void);
void FUN_8016b174(int param_1);
void FUN_8016b1dc(void);
void FUN_8016b228(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_8016b428(u64 param_1,u64 param_2,u64 param_3,double param_4,
                 double param_5,double param_6,u64 param_7,u64 param_8,u16 *param_9
                 );

extern ObjectDescriptor gKaldaChompSpitObjDescriptor;
extern ObjectDescriptor gPinPonSpikeObjDescriptor;
extern ObjectDescriptor gPollenObjDescriptor;
extern ObjectDescriptor gPollenFragmentObjDescriptor;
extern PollenFragmentConfig lbl_80320538;
extern PollenFragmentConfig lbl_8032054C;
extern PollenFragmentConfig lbl_80320560;
extern PollenFragmentConfig lbl_80320574;
extern PollenFragmentConfig lbl_80320588;
extern PollenFragmentConfig *lbl_8032059C[];


/* extern-cleanup: consolidated prototypes */
void quakeSpellFn_8016cee8(int* obj, int* x);


/* extern-cleanup: consolidated prototypes (true-def sigs) */
void kaldachompspit_free(int* obj);
void kaldachompspit_update(int obj);

#endif /* MAIN_DLL_DLL_13C_H_ */
