/* === moved from main/dll/mmshrine/shrine1C2.c [801C70F0-801C7724) (TU re-split, docs/boundary_audit.md) === */
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/dll/mmshrine/shrine1C2.h"
#include "main/objseq.h"
#include "main/screen_transition.h"



extern u32 randomGetRange(int min, int max);
extern undefined8 ObjGroup_RemoveObject();


/*
 * --INFO--
 *
 * Function: ecsh_shrine_update
 * EN v1.0 Address: 0x801C60B8
 * EN v1.0 Size: 3360b
 * EN v1.1 Address: 0x801C666C
 * EN v1.1 Size: 3104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void skyFn_80088c94(int a, int b);
extern void audioStopByMask(int mask);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern f32 timeDelta;



#pragma opt_strength_reduction off
#pragma opt_strength_reduction reset


/*
 * --INFO--
 *
 * Function: FUN_801c6e04
 * EN v1.0 Address: 0x801C6E04
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x801C7408
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */






void gpsh_shrine_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int ecsh_creator_getExtraSize(void);
int gpsh_shrine_getExtraSize(void);
int gpsh_shrine_getObjectTypeId(void);

extern void ModelLightStruct_free(void* light);
extern void gameTimerStop(void);
extern void modelLightStruct_setEnabled(void* light, int enabled, f32 scale);
extern void objRenderFn_8003b8f4(f32);
extern void objParticleFn_80099d84(void* obj, f32 scale, int type, f32 extraScale, void* light);
extern f32 lbl_803E5038;

void gpsh_shrine_free(int* obj);

void gpsh_shrine_render(void* obj, int p2, int p3, int p4, int p5, s8 visible);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4FF8;



extern void fn_80296518(int* player, int a, int b);

typedef struct EcshShrineByte15
{
    u8 flag : 1;
    u8 rest : 7;
} EcshShrineByte15;

int gpsh_shrine_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);


extern u8* mmAlloc(int size, int tag, int p);
extern u8 Obj_IsLoadingLocked(void);


extern int getAngle(f32 dx, f32 dz);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern f32 lbl_803E5000;
extern f32 lbl_803E5004;
extern f32 lbl_803E5008;
extern f32 lbl_803E500C;
extern f32 lbl_803E5010;
extern f32 lbl_803E5014;
extern f32 lbl_803E5018;
extern f32 lbl_803E501C;
extern f32 lbl_803E5020;
extern f32 lbl_803E5024;
extern f32 lbl_803E5028;
extern f32 mathSinf(f32 angle);

void fn_801C70F0(s16* obj);

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/creator1C4.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

typedef struct GpshObjcreatorState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} GpshObjcreatorState;


typedef struct GpshObjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} GpshObjcreatorObjectDef;


typedef struct GpshShrineState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    u8 padC[0x12 - 0xC];
    u8 unk12;
    u8 pad13[0x14 - 0x13];
    u8 unk14;
    u8 pad15[0x18 - 0x15];
} GpshShrineState;


extern void* ObjGroup_GetObjects();


/*
 * --INFO--
 *
 * Function: gpsh_shrine_update
 * EN v1.0 Address: 0x801C7724
 * EN v1.0 Size: 2520b
 * EN v1.1 Address: 0x801C7CD8
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} GpshShrineFlags;

extern int mapGetDirIdx(int a);
extern int unlockLevel(int a, int b, int c);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern int isGameTimerDisabled(void);
extern int Obj_FreeObject(int obj);
extern f32 lbl_803E503C;
extern f32 lbl_803E5040;

void gpsh_shrine_update(int obj);


void gpsh_shrine_init(int* obj, int* def);

/* Trivial 4b 0-arg blr leaves. */
void gpsh_shrine_release(void);

void gpsh_shrine_initialise(void);

void gpsh_objcreator_free(void);

void gpsh_objcreator_hitDetect(void);

void gpsh_objcreator_release(void);

void gpsh_objcreator_initialise(void);

extern void hitDetectFn_80097070(int* obj, f32 e, int a, int b, int c, int d);
extern void Sfx_PlayFromObjectLimited(int obj, int sfx, int v);
extern void* Obj_AllocObjectSetup(int size, int type);
extern f32 lbl_803E504C;
extern f32 lbl_803E5050;
extern f32 lbl_803E5054;
extern s16 lbl_803263B8[];

void gpsh_objcreator_update(int* obj);

void gpsh_scene_free(void)
{
}

void gpsh_scene_hitDetect(void)
{
}

void gpsh_scene_update(void)
{
}

void gpsh_scene_release(void)
{
}

void gpsh_scene_initialise(void)
{
}

void ecsh_cup_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int gpsh_objcreator_getExtraSize(void);
int gpsh_objcreator_getObjectTypeId(void);
int gpsh_scene_getExtraSize(void) { return 0x0; }
int gpsh_scene_getObjectTypeId(void) { return 0x0; }
int ecsh_cup_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5048;
extern f32 lbl_803E5058;

void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5058);
}

void ecsh_cup_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


void gpsh_scene_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
}

void gpsh_objcreator_init(int* obj, int* def);
