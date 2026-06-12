/* === moved from main/dll/CF/dll_166.c [8018ADB4-8018ADF0) (TU re-split, docs/boundary_audit.md) === */
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern void* Obj_GetPlayerObject(void);
extern int ObjGroup_FindNearestObject(int group, int obj, f32* maxDistance);
extern void fn_802967E0(void* obj, int enabled);
extern ObjectTriggerInterface** gObjectTriggerInterface;

typedef struct ChestHitParams
{
    u32 a;
    u32 b;
    u32 c;
    u32 d;
} ChestHitParams;

typedef struct ChestFlags
{
    u8 open : 1;
    u8 trigger : 1;
} ChestFlags;

typedef struct ChestHitBlock
{
    ChestHitParams params;
    u16 a;
    u16 b;
    u16 c;
    f32 scale;
    f32 x;
    f32 y;
    f32 z[1];
} ChestHitBlock;

extern ChestHitParams lbl_802C22B0;
extern void* lbl_803DDAE0;
extern int lbl_803DDAE4;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3C20;
extern f32 lbl_803E3C28;
extern f32 lbl_803E3C2C;

/*
 * --INFO--
 *
 * Function: treasurechest_update
 * EN v1.0 Address: 0x8018AA60
 * EN v1.0 Size: 632b
 * EN v1.1 Address: 0x8018AA94
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: treasurechest_release
 * EN v1.0 Address: 0x8018ADB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AF9C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: treasurechest_initialise
 * EN v1.0 Address: 0x8018ADB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AFA0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: magiccavebottom_getExtraSize
 * EN v1.0 Address: 0x8018ADBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018AFA4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int magiccavebottom_getExtraSize(void)
{
    return 1;
}

void magiccavebottom_free(int obj)
{
    extern void Music_Trigger(s32 triggerId, s32 mode);
    extern void GameBit_Set(int eventId, int value);
    (void)obj;
    GameBit_Set(0xefb, 0);
    Music_Trigger(0x2f, 0);
}

void treasurechest_init(int* obj);

#include "main/dll/CF/CFtoggleswitch.h"
#include "main/camera_interface.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct TrickyguardspotPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} TrickyguardspotPlacement;


typedef struct MagiccavetopPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s8 unk20;
    s8 unk21;
    u8 pad22[0x28 - 0x22];
} MagiccavetopPlacement;


typedef struct MagiccavetopObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s8 unk20;
    s8 unk21;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} MagiccavetopObjectDef;


typedef struct MagiccavetopState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x4 - 0x2];
    f32 unk4;
    u8 pad8[0xC - 0x8];
} MagiccavetopState;


extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();

extern f64 DOUBLE_803e4908;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e48b8;
extern f32 FLOAT_803e48c0;
extern f32 FLOAT_803e48c4;
extern f32 FLOAT_803e48c8;
extern f32 FLOAT_803e48cc;
extern f32 FLOAT_803e48d0;
extern f32 FLOAT_803e48d4;
extern f32 FLOAT_803e48d8;
extern f32 FLOAT_803e48dc;
extern f32 FLOAT_803e48e0;
extern f32 FLOAT_803e48e4;
extern f32 FLOAT_803e48e8;
extern f32 FLOAT_803e48ec;
extern f32 FLOAT_803e48f0;
extern f32 FLOAT_803e48f4;
extern f32 FLOAT_803e48f8;
extern f32 FLOAT_803e48fc;
extern f32 FLOAT_803e4900;
extern f32 FLOAT_803e4904;


/*
 * --INFO--
 *
 * Function: FUN_8018af28
 * EN v1.0 Address: 0x8018AF28
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8018AF64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018b220
 * EN v1.0 Address: 0x8018B220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018B230
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018b224
 * EN v1.0 Address: 0x8018B224
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8018B314
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void trickyguardspot_render(void);

extern int* getTrickyObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void objRenderFn_80041018(int obj);
extern u8 framesThisStep;

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable **)((tricky)->dll))

void trickyguardspot_update(TrickyGuardSpotObject* obj);

/* 8b "li r3, N; blr" returners. */
int magiccavetop_getExtraSize(void);
int trickyguardspot_getExtraSize(void);
int infotext_getExtraSize(void);
int cctestinfot_getExtraSize(void);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void trickyguardspot_free(TrickyGuardSpotObject* obj);

extern void ObjGroup_AddObject(int obj, int g);
extern void objSetHintTextIdx(int obj, int idx);

void trickyguardspot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def);

void infotext_init(int obj, s8* def);

void cctestinfot_init(int obj, s8* def);

extern int playerIsDisguised(void);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern u8 fn_801334E0(void);
extern void showHelpText(s16 id);
extern f32 timeDelta;
extern f32 lbl_803E3C88;
extern f32 lbl_803E3C8C;

void cctestinfot_update(int* obj);

extern int Obj_GetActiveModel(int* obj);
extern int* ObjModel_GetRenderOpTextureRefs(int model, int idx);
extern f32 lbl_803E3C4C;

void magiccavetop_init(int* obj, s8* def);

extern void stopRumble2(void);
extern void* fn_802966CC(void* player);
extern void staffSetGlow(void* a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void mapUnload(int idx, int flags);

void magiccavetop_free(int* obj);

extern void envFxActFn_800887f8(int a);
extern void getEnvfxAct(int* obj, int* target, int id, int p);
extern void setAButtonIcon(int idx);
extern void warpToMap(int mapId, int b);

void magiccavebottom_update(int* obj)
{
    extern void Music_Trigger(int a, int b);
    extern undefined8 GameBit_Set(int eventId, int value);
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* sub = ((GameObject*)obj)->extra;

    *(s16*)obj = (s16)((s32)def[0x1a] << 8);
    switch (*sub)
    {
    case 0:
        GameBit_Set(0xefb, 1);
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, 0x2c, 0);
        getEnvfxAct(obj, obj, 0x2d, 0);
        *sub = 1;
        if (def[0x1b] != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        }
        break;
    case 1:
        Music_Trigger(0x2f, 1);
        *sub = 2;
        break;
    case 2:
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
        {
            setAButtonIcon(0x19);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            *sub = 3;
            if (def[0x1b] != 0)
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(3, obj, -1);
            }
        }
        else
        {
            objRenderFn_80041018((int)obj);
        }
        break;
    case 3:
        GameBit_Set(0x91e, 1);
        warpToMap(GameBit_Get(0x1b8), 0);
        break;
    }
}

extern f32 lbl_803E3C80;
extern f32 lbl_803E3C84;

void infotext_update(int obj);

extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern int loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void lockLevel(int idx, int b);
extern void stopRumble(void);
extern void doRumble(f32 v);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern void objfx_spawnArcedBurst(int* obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 sx, f32 sy, f32 sz,
                                  void* args, int a);
extern f32 lbl_803E3C30;
extern f32 lbl_803E3C34;
extern f32 lbl_803E3C38;
extern f32 lbl_803E3C3C;
extern f32 lbl_803E3C40;
extern f32 lbl_803E3C44;
extern f32 lbl_803E3C48;
extern f32 lbl_803E3C50;
extern f32 lbl_803E3C54;
extern f32 lbl_803E3C58;
extern f32 lbl_803E3C5C;
extern f32 lbl_803E3C60;
extern f32 lbl_803E3C64;
extern f32 lbl_803E3C68;
extern f32 lbl_803E3C6C;

typedef struct MagicCaveTopFxArgs
{
    u8 pad[12];
    f32 x;
    f32 y;
    f32 z;
} MagicCaveTopFxArgs;

void magiccavetop_update(int* obj);
