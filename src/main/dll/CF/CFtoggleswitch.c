#include "main/dll/CF/CFtoggleswitch.h"
#include "main/camera_interface.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objanim_internal.h"
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


extern uint GameBit_Get(int eventId);
extern undefined8 GameBit_Set(int eventId, int value);
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern MapEventInterface** gMapEventInterface;
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
void trickyguardspot_render(void)
{
}

extern int* getTrickyObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void objRenderFn_80041018(int obj);
extern u8 framesThisStep;

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable **)((tricky)->dll))

void trickyguardspot_update(TrickyGuardSpotObject* obj)
{
    u8* sub;
    u8* def;
    ObjAnimComponent* tricky;
    TrickyGuardSpotStateFlags* flags;

    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = (ObjAnimComponent*)getTrickyObject();
    flags = (TrickyGuardSpotStateFlags*)(sub + 4);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
    flags->trickyInRange = 0;
    if (tricky != NULL)
    {
        if ((u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) != 0)
        {
            if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                               (f32*)((char*)tricky + 0x18)) < (f32)(s32)((TrickyguardspotPlacement*)def)->unk1A)
            {
                *(int*)sub = *(int*)sub - framesThisStep;
                flags->trickyInRange = 1;
            }
        }
    }
    if (*(u32*)sub != 0)
    {
        if (tricky != NULL && (u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) == 0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & TRICKY_GUARD_SPOT_VISIBLE_HITBOX_FLAG) != 0)
            {
                TRICKY_GUARD_SPOT_VTABLE(tricky)->setGuardSpotAction(
                    tricky, obj, TRICKY_GUARD_SPOT_ACTION, TRICKY_GUARD_SPOT_ACTION_PARAM);
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
            objRenderFn_80041018((int)obj);
        }
    }
    else if (tricky != NULL)
    {
        TRICKY_GUARD_SPOT_VTABLE(tricky)->resetGuardSpotAction(tricky);
        *(int*)sub = def[0x19] * 0x3c;
    }
    GameBit_Set(((TrickyguardspotPlacement*)def)->unk1E, flags->trickyInRange);
}

/* 8b "li r3, N; blr" returners. */
int magiccavetop_getExtraSize(void) { return 0xc; }
int trickyguardspot_getExtraSize(void) { return 0x8; }
int infotext_getExtraSize(void) { return 0x4; }
int cctestinfot_getExtraSize(void) { return 0x8; }
int deathgas_getExtraSize(void) { return 0x10; }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void trickyguardspot_free(TrickyGuardSpotObject* obj) { ObjGroup_RemoveObject(obj, TRICKY_GUARD_SPOT_GROUP); }

extern void ObjGroup_AddObject(int obj, int g);
extern void objSetHintTextIdx(int obj, int idx);

void trickyguardspot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def)
{
    TrickyGuardSpotState* state = obj->state;
    ObjGroup_AddObject((int)obj, TRICKY_GUARD_SPOT_GROUP);
    state->resetTimer = (int)def->resetSeconds * 60;
    obj->objAnim.rotX = (s16)(s32)
    def->initialYaw;
}

void infotext_init(int obj, s8* def)
{
    u32 v;
    v = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    *(s16*)obj = (s16)((s32)(u8)def[0x18] << 8);
    objSetHintTextIdx(obj, (int)(u8)def[0x19]);
}

void cctestinfot_init(int obj, s8* def)
{
    u32 v;
    v = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    *(s16*)obj = (s16)((s32)(u8)def[0x1A] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)(u8)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)(u8)def[0x18] << 8);
}

extern int playerIsDisguised(void);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern u8 fn_801334E0(void);
extern void showHelpText(s16 id);
extern f32 timeDelta;
extern f32 lbl_803E3C88;
extern f32 lbl_803E3C8C;

void cctestinfot_update(int* obj)
{
    extern void*Obj_GetPlayerObject(void);
    u8* sub = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if (sub[4] != 0)
    {
        if (playerIsDisguised() == 0)
        {
            sub[4] = 0;
        }
    }
    else
    {
        if (playerIsDisguised() != 0)
        {
            sub[4] = 1;
        }
    }
    objSetHintTextIdx((int)obj, sub[4]);
    Obj_SetActiveModelIndex(obj, sub[4]);
    if (ObjTrigger_IsSet((int)obj) != 0 && fn_801334E0() == 0)
    {
        *(f32*)sub = lbl_803E3C88;
    }
    if (*(f32*)sub > lbl_803E3C8C)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) == 0)
        {
            *(f32*)sub = lbl_803E3C8C;
        }
        else
        {
            *(f32*)sub = *(f32*)sub - timeDelta;
            showHelpText(((s16*)((char*)*(int**)&((GameObject*)obj)->anim.modelInstance + 0x7c))[sub[4]]);
        }
    }
}

extern int Obj_GetActiveModel(int* obj);
extern int* ObjModel_GetRenderOpTextureRefs(int model, int idx);
extern f32 lbl_803E3C4C;

void magiccavetop_init(int* obj, s8* def)
{
    int* state = ((GameObject*)obj)->extra;
    int* refs;
    ((GameObject*)obj)->objectFlags = (u16)((u32)((GameObject*)obj)->objectFlags | 0x6000);
    if (GameBit_Get(((MagiccavetopObjectDef*)def)->unk1C) != 0)
    {
        ((MagiccavetopState*)state)->unk4 = lbl_803E3C4C;
    }
    *(s16*)obj = (s16)((s32)(u8)def[0x23] << 8);
    refs = ObjModel_GetRenderOpTextureRefs(Obj_GetActiveModel(obj), 0);
    if (((MagiccavetopObjectDef*)def)->unk24 > 0)
    {
        if (GameBit_Get(((MagiccavetopObjectDef*)def)->unk24) != 0)
        {
            ((MagiccavetopState*)state)->unk1 = (u8)(((MagiccavetopState*)state)->unk1 | 0x0c);
            *(u8*)((char*)refs + 8) = 23;
        }
        else
        {
            *(u8*)((char*)refs + 8) = 22;
        }
    }
}

extern void stopRumble2(void);
extern void* Obj_GetPlayerObject(void);
extern void* fn_802966CC(void* player);
extern void staffSetGlow(void* a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void mapUnload(int idx, int flags);

void magiccavetop_free(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    void* p;
    void* r;
    stopRumble2();
    p = Obj_GetPlayerObject();
    if (p != NULL)
    {
        r = fn_802966CC(p);
        if (r != NULL)
        {
            staffSetGlow(r, 5, 0);
        }
    }
    if (state[0] == 1)
    {
        if (def[0x22] == 0)
        {
            mapUnload(mapGetDirIdx(def[0x1f]), 0x20000000);
        }
    }
}

extern void envFxActFn_800887f8(int a);
extern void getEnvfxAct(int* obj, int* target, int id, int p);
extern void Music_Trigger(int a, int b);
extern void setAButtonIcon(int idx);
extern void warpToMap(int mapId, int b);

void magiccavebottom_update(int* obj)
{
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

void infotext_update(int obj)
{
    f32* sub = ((GameObject*)obj)->extra;
    if (ObjTrigger_IsSet(obj) != 0 && fn_801334E0() == 0)
    {
        *sub = lbl_803E3C80;
    }
    if (*sub > lbl_803E3C84)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) == 0)
        {
            *sub = lbl_803E3C84;
        }
        else
        {
            *sub = *sub - timeDelta;
            showHelpText(
                ((s16*)((char*)*(int**)&((GameObject*)obj)->anim.modelInstance + 0x7c))[(*(u8**)&((GameObject*)obj)->
                    anim.placementData)[0x19]]);
        }
    }
    if ((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0)
    {
        objRenderFn_80041018(obj);
    }
}

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

void magiccavetop_update(int* obj)
{
    MagicCaveTopFxArgs fx;
    int* player;
    u8* sub;
    u8* def;
    int gb;
    u8 dirIdx;
    int range;
    void* staff;
    f32 dist;
    f32 t;

    player = (int*)Obj_GetPlayerObject();
    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    gb = 0;
    if (player != NULL)
    {
        if (GameBit_Get(0x91e) != 0)
        {
            GameBit_Set(0x91e, 0);
            (*gMapEventInterface)->setAnimEvent(def[0x1f], def[0x1a], 0);
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            unlockLevel(0, 0, 1);
            *sub = 3;
            return;
        }
        dirIdx = mapGetDirIdx(def[0x1f]);
        dist = vec3f_distanceSquared(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
        gb = GameBit_Get(((MagiccavetopPlacement*)def)->unk1C);
        switch (*sub)
        {
        case 0:
            range = def[0x19] * 2;
            if (dist < (f32)(range * range))
            {
                if (def[0x22] == 0)
                {
                    loadMapAndParent(def[0x1f]);
                }
                *sub = 1;
            }
            break;
        case 1:
            range = def[0x18] * 2;
            if (dist > (f32)(range * range))
            {
                if (def[0x22] == 0)
                {
                    mapUnload(dirIdx, 0x20000000);
                }
                *sub = 0;
            }
            else if (dist < lbl_803E3C30 && gb != 0)
            {
                *sub = 2;
                (*gMapEventInterface)->setAnimEvent(def[0x1f], def[0x1a], 1);
                (*gMapEventInterface)->setMode(def[0x1f], def[0x1b]);
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            }
            break;
        case 2:
            GameBit_Set(0x1b8, ((MagiccavetopPlacement*)def)->unk21);
            if (def[0x22] != 0)
            {
                unlockLevel(0, 0, 1);
                lockLevel(def[0x1e], 0);
                lockLevel(def[0x1e], 1);
            }
            else
            {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(((GameObject*)obj)->anim.mapEventSlot), 0);
                lockLevel(dirIdx, 1);
            }
            if (((GameObject*)obj)->anim.mapEventSlot == 0xd)
            {
                GameBit_Set(0xe05, 0);
            }
            warpToMap(((MagiccavetopPlacement*)def)->unk20, 0);
            break;
        case 3:
            if (dist > lbl_803E3C30)
            {
                *sub = 1;
            }
            break;
        }
        if ((sub[1] & 4) == 0)
        {
            if (dist >= lbl_803E3C34)
            {
                *(f32*)(sub + 8) = lbl_803E3C38;
                sub[1] &= ~2;
            }
            else if ((sub[1] & 2) == 0)
            {
                if ((sub[1] & 1) != 0)
                {
                    if (dist < lbl_803E3C3C)
                    {
                        stopRumble();
                        if (player != NULL)
                        {
                            staff = fn_802966CC(player);
                            if (staff != NULL)
                            {
                                staffSetGlow(staff, 5, 0);
                            }
                        }
                        sub[2] = 0;
                    }
                    else if (dist < lbl_803E3C40)
                    {
                        if (sub[2] == 1)
                        {
                            stopRumble();
                            if (player != NULL)
                            {
                                staff = fn_802966CC(player);
                                if (staff != NULL)
                                {
                                    staffSetGlow(staff, 5, 0);
                                }
                            }
                            sub[2] = 0;
                        }
                        else
                        {
                            stopRumble2();
                            if (player != NULL)
                            {
                                staff = fn_802966CC(player);
                                if (staff != NULL)
                                {
                                    staffSetGlow(staff, 5, 0);
                                }
                            }
                            sub[2] = 1;
                        }
                    }
                    else
                    {
                        stopRumble2();
                        if (player != NULL)
                        {
                            staff = fn_802966CC(player);
                            if (staff != NULL)
                            {
                                staffSetGlow(staff, 5, 0);
                            }
                        }
                        sub[2] = 1;
                    }
                    sub[1] &= ~1;
                    *(f32*)(sub + 8) += timeDelta;
                }
                else if (dist < lbl_803E3C34)
                {
                    doRumble(lbl_803E3C44);
                    if (player != NULL)
                    {
                        staff = fn_802966CC(player);
                        if (staff != NULL)
                        {
                            staffSetGlow(staff, 5, 2);
                        }
                    }
                    sub[1] |= 1;
                    *(f32*)(sub + 8) += timeDelta;
                }
                if (*(f32*)(sub + 8) > lbl_803E3C48)
                {
                    sub[1] |= 2;
                }
            }
        }
    }
    if (gb != 0)
    {
        if (lbl_803E3C38 == ((MagiccavetopState*)sub)->unk4)
        {
            Sfx_PlayFromObject(obj, 0x4a2);
        }
        ((MagiccavetopState*)sub)->unk4 += timeDelta;
        if (((MagiccavetopState*)sub)->unk4 > lbl_803E3C4C)
        {
            ((MagiccavetopState*)sub)->unk4 = lbl_803E3C4C;
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha =
                (u8)(int)(lbl_803E3C50 * (((MagiccavetopState*)sub)->unk4 / lbl_803E3C4C));
        }
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0;
    }
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        t = lbl_803E3C38;
        fx.x = t;
        fx.y = lbl_803E3C54;
        fx.z = t;
        if ((sub[1] & 8) != 0)
        {
            objfx_spawnArcedBurst(obj, 1, lbl_803E3C58, 5, 2, 0x32, lbl_803E3C5C, lbl_803E3C60, lbl_803E3C64, fx.pad,
                                  0);
            fx.y = lbl_803E3C68;
            objfx_spawnArcedBurst(obj, 5, lbl_803E3C58, 5, 2, 0x14, 10.0f, 10.0f, 10.0f, fx.pad, 0);
        }
        else
        {
            objfx_spawnArcedBurst(obj, 1, lbl_803E3C58, 2, 2, 0x32, lbl_803E3C5C, lbl_803E3C60, lbl_803E3C64, fx.pad,
                                  0);
            fx.y = lbl_803E3C68;
            objfx_spawnArcedBurst(obj, 5, lbl_803E3C58, 2, 2, 0x14, 10.0f, 10.0f, 10.0f, fx.pad, 0);
        }
    }
}
