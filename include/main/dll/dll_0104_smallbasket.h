#ifndef MAIN_DLL_DLL_0104_SMALLBASKET_H_
#define MAIN_DLL_DLL_0104_SMALLBASKET_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

/* Retail SmallBasket placements are 9 words: the common 0x18-byte placement
   head followed by this class-specific 0x0C-byte parameter tail. */
typedef struct SmallBasketPlacement {
    ObjPlacement base;   /* 0x00 */
    s8 rotX;             /* 0x18 */
    u8 subtype;          /* 0x19 selects ambient sfx/content behavior */
    s16 unk1A;           /* 0x1A copied into state byte 0x1F */
    s16 respawnMinutes;  /* 0x1C converted to seconds on initialization */
    s16 enableGameBit;   /* 0x1E starts hidden when set */
    s16 leashRange;      /* 0x20 distance from the placement origin */
    u8 pad22[2];
} SmallBasketPlacement;

STATIC_ASSERT(offsetof(SmallBasketPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(SmallBasketPlacement, respawnMinutes) == 0x1C);
STATIC_ASSERT(offsetof(SmallBasketPlacement, leashRange) == 0x20);
STATIC_ASSERT(sizeof(SmallBasketPlacement) == 0x24);

/* Small-basket per-object extra state. */
typedef struct CfperchState {
    s16 carryAngle;      /* 0x0 low half of the 0x100010 carry message */
    s16 carryParam;      /* 0x2 high half of the 0x100010 carry message */
    u8 unk4[0x5 - 0x4];
    s8 carryState;       /* 0x5 carry/throw state machine: 0 idle, 1 grabbed, 2 carried */
    u8 carryAttached;    /* 0x6 set while held by player; gates the per-frame carry message */
    u8 unk7[0x9 - 0x7];
    u8 throwState;       /* 0x9 in-flight mode: 0 none, 1 thrown, 2 dropped */
    s16 disableTimer;    /* 0xA post-action hide/disable countdown */
    s16 leashRange;      /* 0xC carry leash range from placement origin */
    s16 randomTimer;
    s16 sfxId;
    s16 respawnTimer;
    int hiddenTimer;     /* 0x14 hide/fade countdown while disabled */
    int respawnDelay;    /* 0x18 configured respawn delay */
    s16 enableGameBit;
    u8 subtype;          /* 0x1E object subtype, selects ambient sfx */
    u8 unk1F;
    u8 disguiseGated;    /* 0x20 set for seqId 0x662 */
    u8 unk21[0x24 - 0x21];
} CfperchState;

STATIC_ASSERT(offsetof(CfperchState, carryState) == 0x5);
STATIC_ASSERT(offsetof(CfperchState, throwState) == 0x9);
STATIC_ASSERT(offsetof(CfperchState, disableTimer) == 0xA);
STATIC_ASSERT(offsetof(CfperchState, hiddenTimer) == 0x14);
STATIC_ASSERT(offsetof(CfperchState, enableGameBit) == 0x1C);
STATIC_ASSERT(offsetof(CfperchState, disguiseGated) == 0x20);
STATIC_ASSERT(sizeof(CfperchState) == 0x24);

int SmallBasket_getExtraSize(void);
void SmallBasket_init(GameObject* obj, SmallBasketPlacement* placement);
void SmallBasket_update(GameObject* obj);
void SmallBasket_render(GameObject* obj, int p2, int p3, int p4, int p5, char visible);
void objThrowFn_80182504(GameObject* obj);
int smallbasket_spawnContents(GameObject* obj, GameObject* player, void* state);

extern ObjectDescriptor gSmallBasketObjDescriptor;

#endif /* MAIN_DLL_DLL_0104_SMALLBASKET_H_ */
