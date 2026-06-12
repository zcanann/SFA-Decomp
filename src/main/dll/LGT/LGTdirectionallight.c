/* === moved from main/dll/LGT/LGTpointlight.c [801F3C2C-801F3C7C) (TU re-split, docs/boundary_audit.md) === */
#include "main/expgfx.h"


extern void* objCreateLight(void* obj, int);
extern void modelLightStruct_setLightKind(void*, int);
extern void modelLightStruct_setPosition(f32, f32, f32);
extern void modelLightStruct_setDiffuseColor(void*, u8, u8, u8, int);
extern void modelLightStruct_setSpecularColor(void*, u8, u8, u8, int);
extern void modelLightStruct_setDistanceAttenuation(void*, f32, f32);
extern void modelLightStruct_setEnabled(void*, int, f32);
extern void modelLightStruct_startColorFade(void*, int, int);
extern void modelLightStruct_setDiffuseTargetColor(void*, int, int, int, int);
extern void lightSetField4D(void*, int);
extern void modelLightStruct_setupGlow(void*, int, u8, u8, u8, int, f32);
extern void modelLightStruct_setGlowProjectionRadius(void*, f32);

extern u8 lbl_802C2488[];
extern f32 lbl_803E5E08;
extern f32 lbl_803E5E0C;
extern f32 lbl_803E5E10;
extern f32 lbl_803E5E20;
extern f32 lbl_803E5E24;
extern f32 lbl_803E5E28;
extern f32 lbl_803E5E2C;
extern f32 lbl_803E5E30;
extern f32 lbl_803E5E34;
extern f32 lbl_803E5E38;
extern f32 lbl_803E5E3C;
extern f32 lbl_803E5E40;

typedef struct LightColorTable
{
    u8 c[45];
} LightColorTable;

/*
 * --INFO--
 *
 * Function: lightsource_init
 * EN v1.0 Address: 0x801F37CC
 * EN v1.0 Size: 1112b
 */

/* Trivial 4b 0-arg blr leaves. */
void lightsource_release(void);

void lightsource_initialise(void);

void wmworm_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int wmworm_getExtraSize(void) { return 0x1c; }
int wmworm_getObjectTypeId(void) { return 0x0; }

void wmworm_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void wmworm_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/LGT/LGTdirectionallight.h"

extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern undefined4 FUN_80017710();
extern int FUN_80017a98();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern void setDrawLights(int mode);
extern int getSkyColorFn_80088e08(int slot);
extern void skySetOverrideLightColorEnabled(u8 enabled);
extern void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
extern void skyFn_80089710(int flags, u32 enabled, int startComplete);
extern f32 fn_8008ED88(void);
extern void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2);
extern void fn_80089510(int flags, u8 red, u8 green, u8 blue);
extern void fn_80089578(int flags, u8 red, u8 green, u8 blue);
extern void skySetOverrideLightDirectionEnabled(u8 enabled);
extern void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
extern void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);
extern void ObjGroup_RemoveObject(int obj, int group);
extern void Music_Trigger(int musicId, int param);
extern void GameBit_Set(int eventId, int value);

typedef struct
{
    f32 x, y, z;
} LightVec3;

typedef struct
{
    LightVec3 light;
    LightVec3 color;
    LightVec3 fog;
} LightVecSet;

extern f64 lbl_803E5E88;

extern void* Obj_GetPlayerObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern EffectInterface** gPartfxInterface;
extern byte framesThisStep;
extern f32 lbl_803E5E58;
extern f32 lbl_803E5E5C;
extern f32 lbl_803E5E60;
extern f32 lbl_802C24B8[];
extern undefined4 DAT_802c2c08;
extern undefined4 DAT_802c2c0c;
extern undefined4 DAT_802c2c10;
extern undefined4 DAT_802c2c14;
extern undefined4 DAT_802c2c18;
extern undefined4 DAT_802c2c1c;
extern undefined4 DAT_802c2c20;
extern undefined4 DAT_802c2c24;
extern undefined4 DAT_802c2c28;
extern undefined4 DAT_802c2c2c;
extern undefined4 DAT_802c2c30;
extern undefined4 DAT_802c2c34;
extern undefined4 DAT_803dc070;
extern f64 DOUBLE_803e6ae0;
extern f64 DOUBLE_803e6ae8;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern u8 lbl_803DC110;
extern u8 lbl_803DC114;
extern u8 lbl_803DC118;
extern u8 lbl_803DC11C;
extern u8 lbl_803DC120;
extern u8 lbl_803DC124;
extern f32 lbl_803DDC88;
extern f32 lbl_803DDC8C;
extern u8 lbl_803DDC90;
extern u8 lbl_803DDC94;
extern u8 lbl_803DDC98;
extern u8 lbl_803DDC9C;
extern f32 lbl_803E5E70;
extern f32 lbl_803E5E74;
extern f32 lbl_803E5E78;
extern f32 lbl_803E5E7C;
extern f32 lbl_803E5E80;
extern f32 lbl_803E5E84;
extern f32 lbl_803E6AA0;
extern f32 lbl_803E6AA4;
extern f32 lbl_803E6AA8;
extern f32 lbl_803E6AB8;
extern f32 lbl_803E6ABC;
extern f32 lbl_803E6AC0;
extern f32 lbl_803E6AC4;
extern f32 lbl_803E6AC8;
extern f32 lbl_803E6ACC;
extern f32 lbl_803E6AD0;
extern f32 lbl_803E6AD4;
extern f32 lbl_803E6AD8;
extern f32 lbl_803E6AF0;
extern f32 lbl_803E6AF4;
extern f32 lbl_803E6AF8;

/*
 * --INFO--
 *
 * Function: wmworm_update
 * EN v1.0 Address: 0x801F3C7C
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801F42B4
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole on
void wmworm_update(GameObject* obj)
{
    float fVar1;
    float fVar2;
    float fVar3;
    GameObject* player;
    WmWormState* state;
    ObjPlacement* placement;
    short burstCount;
    f32 dist;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    placement = (ObjPlacement*)obj->anim.placementData;
    if (player != NULL)
    {
        dist = Vec_xzDistance(&player->anim.worldPosX, &placement->posX);
        if (dist > lbl_803E5E58)
        {
            obj->anim.localPosX = state->homeX;
            obj->anim.localPosY = state->homeY;
            obj->anim.localPosZ = state->homeZ;
        }
        else
        {
            fVar1 = player->anim.worldPosX - obj->anim.localPosX;
            fVar2 = player->anim.worldPosY - obj->anim.localPosY;
            fVar3 = player->anim.worldPosZ - obj->anim.localPosZ;
            if ((fVar1 > lbl_803E5E5C) || (fVar1 < lbl_803E5E5C))
            {
                obj->anim.localPosX = lbl_803E5E60 * fVar1 * timeDelta + obj->anim.localPosX;
            }
            if ((fVar2 > lbl_803E5E5C) || (fVar2 < lbl_803E5E5C))
            {
                obj->anim.localPosY = lbl_803E5E60 * fVar2 * timeDelta + obj->anim.localPosY;
            }
            if ((fVar3 > lbl_803E5E5C) || (fVar3 < lbl_803E5E5C))
            {
                obj->anim.localPosZ = lbl_803E5E60 * fVar3 * timeDelta + obj->anim.localPosZ;
            }
            burstCount = state->burstCount;
            if ((-1 < burstCount) || ((-1 >= burstCount && (obj->unkF4 < 1))))
            {
                if (burstCount == 0)
                {
                    state->unk0C = 1;
                }
                obj->anim.rotY += 300;
                if (0 < state->burstCount)
                {
                    for (burstCount = 0; burstCount < state->burstCount; burstCount = burstCount + 1)
                    {
                        (*gPartfxInterface)->spawnObject(obj, state->particleEffectId, NULL, 4,
                                                         -1, NULL);
                    }
                }
                else
                {
                    (*gPartfxInterface)->spawnObject(obj, state->particleEffectId, NULL, 4,
                                                     -1, NULL);
                }
                obj->unkF4 = -state->burstCount;
            }
            else if ((burstCount < 0) && (0 < obj->unkF4))
            {
                obj->unkF4 = obj->unkF4 - (u32)framesThisStep;
            }
        }
    }
    return;
}

#pragma peephole off
void wmworm_init(GameObject* obj, WmWormSetup* setup)
{
    WmWormState* state;

    obj->anim.rotX = 0;
    state = obj->extra;
    state->effectScale = (f32)((s32)setup->effectScale << 2);
    state->particleEffectId = setup->particleEffectId;
    state->burstCount = setup->burstCount;
    state->unk0C = 0;
    if (state->burstCount < 1)
    {
        obj->unkF4 = state->burstCount;
    }
    else
    {
        obj->unkF4 = 0;
    }
    state->homeX = obj->anim.localPosX;
    state->homeY = obj->anim.localPosY;
    state->homeZ = obj->anim.localPosZ;
}


/* Trivial 4b 0-arg blr leaves. */
void wmworm_release(void)
{
}

void wmworm_initialise(void)
{
}
