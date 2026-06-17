#ifndef MAIN_DLL_DB_DBSTEALERWORM_H_
#define MAIN_DLL_DB_DBSTEALERWORM_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor15 gSB_GalleonObjDescriptor;
extern ObjectDescriptor gSB_PropellerObjDescriptor;
extern ObjectDescriptor gSB_ShipHeadObjDescriptor;
extern ObjectDescriptor gSB_ShipMastObjDescriptor;

/* The galleon DLL exposes an interface vtable to its part objects (the guns,
   the propellers, the figurehead) via *(part->parent->anim.dll). The parts
   query the galleon's stage/phase and report their destruction through it. */
typedef int (*SBGalleonVtblFn)(int galleon);
typedef struct SBGalleonVtbl {
    SBGalleonVtblFn _slot00[8];      /* 0x00..0x1c: standard object-class slots */
    SBGalleonVtblFn onPartDestroyed; /* 0x20: a part reports its destruction */
    SBGalleonVtblFn getStage;        /* 0x24: SBGalleonState.stage */
    SBGalleonVtblFn getPhase;        /* 0x28: SBGalleonState.phase (-1/-2 edge cases) */
    SBGalleonVtblFn getDamagePhase;  /* 0x2c: SBGalleonState.damagePhase */
} SBGalleonVtbl;
#define SB_GALLEON_VTBL(galleon) ((SBGalleonVtbl*)*((GameObject*)(galleon))->anim.dll)

void fn_801E1588(int param_1,int param_2);
int SB_Galleon_animEventCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
undefined4 FUN_801e1ee4(void);
undefined4 FUN_801e2184(void);
int SB_Galleon_func0E(int *obj);
u8 SB_Galleon_getDamagePhase(int *obj);
int SB_Galleon_getPhase(int *obj);
s32 SB_Galleon_getStage(int *obj);
int SB_Galleon_onPartDestroyed(GameObject* obj);
int SB_Galleon_getExtraSize(void);
int SB_Galleon_getObjectTypeId(void);
void SB_Galleon_free(GameObject* obj, int p2);
void SB_Galleon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_Galleon_hitDetect(GameObject* obj);
void SB_Galleon_update(GameObject* obj);
void SB_Galleon_init(GameObject* obj);
void SB_Galleon_release(void);
void SB_Galleon_initialise(void);

int SB_Propeller_getExtraSize(void);
void SB_Propeller_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SB_Propeller_hitDetect(GameObject* obj);
void SB_Propeller_update(int obj);
void SB_Propeller_init(GameObject* param_1,int param_2);

int SB_ShipHead_getExtraSize(void);
int SB_ShipHead_getObjectTypeId(void);
void SB_ShipHead_free(int obj);
void SB_ShipHead_render(GameObject* param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void SB_ShipHead_update(int obj);
void SB_ShipHead_init(int obj);

int SB_ShipMast_getExtraSize(void);
int SB_ShipMast_getObjectTypeId(void);
void SB_ShipMast_free(void);
void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SB_ShipMast_hitDetect(void);
void SB_ShipMast_init(void);
void SB_ShipMast_release(void);
void SB_ShipMast_initialise(void);

#endif /* MAIN_DLL_DB_DBSTEALERWORM_H_ */
