#ifndef MAIN_DLL_DLL_13C_H_
#define MAIN_DLL_DLL_13C_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct PollenExtra
{
    s16 phaseX;             /* 0x00: random drift phase seed */
    s16 unk02;              /* 0x02 */
    s16 phaseY;             /* 0x04: random drift phase seed */
    s16 phaseSpeed;         /* 0x06: random drift rate */
    f32 settleVelocity;     /* 0x08: settle/freeze velocity baseline */
    f32 driftVelocity;      /* 0x0C: initial drift velocity */
    s16 unk10;              /* 0x10 */
    s16 fragmentSpawnTimer; /* 0x12 */
} PollenExtra;

#define POLLEN_FRAGMENT_OBJECT_ID            0x482
#define POLLEN_FRAGMENT_SETUP_SIZE           0x24
#define POLLEN_FRAGMENT_SETUP_KIND           5
#define POLLEN_FRAGMENT_BURST_COUNTER_START  5
#define POLLEN_FRAGMENT_RANDOM_ANGLE_MAX     0xffff
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MIN    -50
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MAX    50
#define POLLEN_FRAGMENT_SPAWN_TIMER_FRAMES   60
#define POLLEN_FRAGMENT_PARENT_OBJECT_OFFSET 0xc4

void FUN_80169d38(u64 param_1, u64 param_2, u64 param_3, double param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, short* param_9);
int FUN_8016a534(double param_1, double param_2, float* param_3, float* param_4, char param_5);
void FUN_8016a6d4(int obj);
void FUN_8016a708(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, short* param_9);
void FUN_8016aa90(u32 param_1);
void FUN_8016aae4(int obj);
void FUN_8016ab18(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_8016ab40(int param_1);
int pinponspike_getExtraSize(void);
int pinponspike_getObjectTypeId(void);
void pinponspike_free(int obj);
void pinponspike_render(void);
void pinponspike_hitDetect(void);
void pinponspike_update(int obj);
void pinponspike_init(GameObject* obj);
void pinponspike_release(void);
void pinponspike_initialise(void);
void FUN_8016aba8(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u32 param_9);
void FUN_8016ae64(double param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9);
int Pollen_getExtraSize(void);
int Pollen_getObjectTypeId(void);
void Pollen_free(int obj);
void Pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void Pollen_hitDetect(GameObject* obj);
void Pollen_update(int obj);
void Pollen_init(GameObject* obj);
void Pollen_release(void);
void Pollen_initialise(void);
int pollenfragment_getExtraSize(void);
int pollenfragment_getObjectTypeId(void);
void pollenfragment_free(GameObject* obj);
void pollenfragment_render(int* obj, int p2, int p3, int p4, int p5);
void pollenfragment_hitDetect(GameObject* obj);
void pollenfragment_update(int obj);
void pollenfragment_init(GameObject* obj, int config);
void pollenfragment_release(void);
void pollenfragment_initialise(void);
void FUN_8016b174(int param_1);
void FUN_8016b1dc(void);
void FUN_8016b228(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u32 param_9);
void FUN_8016b428(u64 param_1, u64 param_2, u64 param_3, double param_4, double param_5, double param_6, u64 param_7,
                  u64 param_8, u16* param_9);

extern ObjectDescriptor gKaldaChompSpitObjDescriptor;
extern ObjectDescriptor gPinPonSpikeObjDescriptor;
extern ObjectDescriptor gPollenObjDescriptor;
extern ObjectDescriptor gPollenFragmentObjDescriptor;

/* extern-cleanup: consolidated prototypes */
void quakeSpellFn_8016cee8(int* obj, int* x);

#endif /* MAIN_DLL_DLL_13C_H_ */
