#ifndef MAIN_DLL_DLL_02B6_CNTHITOBJEC_H
#define MAIN_DLL_DLL_02B6_CNTHITOBJEC_H

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

#define CNTHIT_MODE_VISIBLE_OBJECT 2
#define CNTHIT_PROFILE_COUNT 3
#define CNTHIT_DEFAULT_VISIBLE_EXPLOSION_SIZE 80

#define CNTHIT_MODEL_NO_EXPLOSION_A 0x470EA
#define CNTHIT_MODEL_NO_EXPLOSION_B 0x480F5
#define CNTHIT_MODEL_NO_EXPLOSION_C 0x46710
#define CNTHIT_MODEL_NO_EXPLOSION_D 0x49B43

typedef struct CntHitObjectFlags {
    u8 disabled : 1;
    u8 pad : 7;
} CntHitObjectFlags;

typedef struct CntHitObjectState {
    int remainingHealth;
    int* allowedHitSources;
    u8 allowedHitSourceCount;
    CntHitObjectFlags flags;
    u8 padA[0xC - 0xA];
} CntHitObjectState;

typedef struct CntHitObjectSetup {
    ObjPlacement base;
    s8 hitSourceProfile;
    u8 mode;
    s16 startHealth;
    s16 explosionSize;
    s16 doneGameBit;
    s16 startGameBit;
} CntHitObjectSetup;

typedef struct CntHitObjectAnimEvent {
    u8 pad0[0x81];
    u8 explosionIds[10];
    u8 explosionCount;
} CntHitObjectAnimEvent;

STATIC_ASSERT(offsetof(CntHitObjectState, allowedHitSources) == 0x04);
STATIC_ASSERT(offsetof(CntHitObjectState, allowedHitSourceCount) == 0x08);
STATIC_ASSERT(offsetof(CntHitObjectState, flags) == 0x09);
STATIC_ASSERT(sizeof(CntHitObjectState) == 0x0C);
STATIC_ASSERT(offsetof(CntHitObjectSetup, hitSourceProfile) == 0x18);
STATIC_ASSERT(offsetof(CntHitObjectSetup, mode) == 0x19);
STATIC_ASSERT(offsetof(CntHitObjectSetup, startHealth) == 0x1A);
STATIC_ASSERT(offsetof(CntHitObjectSetup, explosionSize) == 0x1C);
STATIC_ASSERT(offsetof(CntHitObjectSetup, doneGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CntHitObjectSetup, startGameBit) == 0x20);
STATIC_ASSERT(sizeof(CntHitObjectSetup) == 0x24);
STATIC_ASSERT(offsetof(CntHitObjectAnimEvent, explosionIds) == 0x81);
STATIC_ASSERT(offsetof(CntHitObjectAnimEvent, explosionCount) == 0x8B);

extern int* lbl_8032BEF8[];
extern u8 lbl_803DC42C;
extern int lbl_803DC428;
extern ObjectDescriptor gCNThitObjecObjDescriptor;

int cnthitobjec_getExtraSize(void);
int cnthitobjec_getObjectTypeId(void);
void cnthitobjec_free(void);
void cnthitobjec_release(void);
void cnthitobjec_initialise(void);
void cnthitobjec_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
int cnthitobjec_SeqFn(int obj, int unused, CntHitObjectAnimEvent* event);
void cnthitobjec_hitDetect(GameObject* obj);
void cnthitobjec_init(GameObject* obj, CntHitObjectSetup* setup);
void cnthitobjec_update(GameObject* obj);
int mcupgrade_SeqFn(GameObject* obj, int unused, CntHitObjectAnimEvent* event);

#endif
