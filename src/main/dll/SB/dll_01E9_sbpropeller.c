#include "main/obj_placement.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();

extern EffectInterface** gPartfxInterface;
extern undefined4 DAT_803de8c0;
extern f32 lbl_803E64A8;

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u32 fn_801E2570(void);
extern f32 timeDelta;

extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern int DBprotection_getCameraState(u32 g);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern int Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32* x, f32* y, f32* z, int p);
extern void spawnExplosion(int obj, f32 s, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E5810;
extern f32 lbl_803E5814;
extern f32 lbl_803E5818;
extern f32 lbl_803E581C;
extern f32 lbl_803E5820;
extern f32 lbl_803E5824;

extern u32 lbl_803DDC40;
extern void objRenderFn_8003b8f4(f32);

void SB_Propeller_update(int obj)
{
    ObjAnimComponent* objAnim;
    int camA;
    int camB;
    int camC;
    int pf4;
    int i;
    int j;
    u32 hit;
    f32* pf;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;

    objAnim = (ObjAnimComponent*)obj;
    pf = ((GameObject*)obj)->extra;
    camA = (**(int (**)(int))(**(int**)(*(int*)&((GameObject*)obj)->anim.parent + 0x68) + 0x24))(
        *(int*)&((GameObject*)obj)->anim.parent);
    camB = (**(int (**)(int))(**(int**)(*(int*)&((GameObject*)obj)->anim.parent + 0x68) + 0x28))(
        *(int*)&((GameObject*)obj)->anim.parent);
    if (((((SBPropellerState*)pf)->health != 0) && (camB < 6)) && (((GameObject*)obj)->anim.seqId != 0x69c))
    {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x2c6);
    }
    camC = DBprotection_getCameraState(*(int*)&((GameObject*)obj)->anim.parent);
    if ((camC < 2) && (((SBPropellerState*)pf)->health <= 0))
    {
        ((SBPropellerState*)pf)->smokeTimer = ((SBPropellerState*)pf)->smokeTimer - timeDelta;
        if (((SBPropellerState*)pf)->smokeTimer <= lbl_803E5814)
        {
            f32 spd;
            for (i = randomGetRange(10, 0x19), spd = lbl_803E5810; i != 0; i--)
            {
                stk.b = ((GameObject*)obj)->anim.worldPosX;
                stk.c = ((GameObject*)obj)->anim.worldPosY;
                stk.d = ((GameObject*)obj)->anim.worldPosZ;
                stk.a = spd;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x9f, stk.pad, 0x200001, -1, NULL);
            }
            ((SBPropellerState*)pf)->smokeTimer = (f32)(int)
            randomGetRange(0x5a, 0xf0);
        }
        if ((2 < camA) && (objAnim->bankIndex == 1))
        {
            stk.a = lbl_803E5818;
            stk.mode = 0xc0a;
            ObjPath_GetPointWorldPosition(obj, 0, &stk.b, &stk.c, &stk.d, 0);
            stk.b = stk.b - ((GameObject*)obj)->anim.worldPosX;
            stk.c = stk.c - ((GameObject*)obj)->anim.worldPosY;
            stk.d = stk.d - ((GameObject*)obj)->anim.worldPosZ;
            for (j = 0; j < framesThisStep; j++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7aa, stk.pad, 2, -1, NULL);
            }
        }
    }
    if (*(void**)&((GameObject*)obj)->anim.parent != NULL)
    {
        pf4 = *(int*)(*(int*)&((GameObject*)obj)->anim.parent + 0xf4);
        if ((((GameObject*)obj)->anim.seqId != 0x69c) && (pf4 < 4))
        {
            ((SBPropellerState*)pf)->spinBlend = (f32)((SBPropellerState*)pf)->spinRate / lbl_803E581C;
            if (((SBPropellerState*)pf)->spinBlend < lbl_803E5814)
            {
                ((SBPropellerState*)pf)->spinBlend = -((SBPropellerState*)pf)->spinBlend;
            }
            if (((SBPropellerState*)pf)->spinBlend < *(f32*)&lbl_803E5820)
            {
                ((SBPropellerState*)pf)->spinBlend = lbl_803E5820;
            }
        }
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            ((GameObject*)obj)->unkF4 = 0;
        }
        if (((((((camB == 1) && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0))
                        && (((GameObject*)obj)->unkF4 == 0))
                    && ((hit != 0 && (hit != Obj_GetPlayerObject()))))
                && ((*(s16*)(hit + 0x46) != 0x69c
                    && ((*(s16*)(hit + 0x46) != 0x9a
                        && ((((GameObject*)obj)->unkF4 = 0x14, *(void**)&((GameObject*)obj)->anim.parent != NULL)))))))
            && ((camA == 2 || (camA == 5)))) && (((GameObject*)obj)->anim.seqId == 0x69c))
        {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, 0x2c7);
            ((SBPropellerState*)pf)->health -= 1;
            if (((SBPropellerState*)pf)->health <= 0)
            {
                *(u8*)&((SBPropellerState*)pf)->health = 0;
                (**(void (**)(int))(**(int**)(*(int*)&((GameObject*)obj)->anim.parent + 0x68) + 0x20))(
                    *(int*)&((GameObject*)obj)->anim.parent);
                ObjHits_DisableObject(obj);
                *(s16*)&((GameObject*)obj)->anim.flags = *(s16*)&((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
                spawnExplosion(obj, lbl_803E5824, 1, 1, 1, 0, 1, 1, 0);
                Sfx_PlayFromObject(obj, 0x2c8);
            }
        }
        if (((GameObject*)obj)->unkF4 == 0)
        {
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 6;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->objectHitMask = 0x10;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->skeletonHitMask = 0x10;
        }
        else
        {
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 0;
        }
        ((GameObject*)obj)->anim.rotZ = -((f32)((SBPropellerState*)pf)->spinRate * timeDelta - (
            f32)((GameObject*)obj)->anim.rotZ);
    }
}

void SB_Propeller_init(int obj, int arg2)
{
    ObjAnimComponent* objAnim;
    uint randVal;
    float* state;

    objAnim = (ObjAnimComponent*)obj;
    state = ((GameObject*)obj)->extra;
    randVal = randomGetRange(0x5a, 0xf0);
    ((SBPropellerState*)state)->smokeTimer = (f32)(s32)(randVal);
    ((SBPropellerState*)state)->spinBlend = lbl_803E64A8;
    ((SBPropellerState*)state)->spinRate = 1200;
    *(u8*)&((SBPropellerState*)state)->health = 4;
    objAnim->bankIndex = (char)*(s16*)(arg2 + 0x1a);
    if (((GameObject*)obj)->anim.seqId != 0x69c)
    {
        DAT_803de8c0 = obj;
    }
    return;
}

void SB_ShipHead_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible);

int SB_Propeller_getExtraSize(void) { return 0x10; }
int SB_ShipHead_getExtraSize(void);

u32 fn_801E2570(void) { return lbl_803DDC40; }

u8 SB_Galleon_render2(int* obj);

void SB_Propeller_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5810);
}

void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void SB_Propeller_hitDetect(int obj)
{
    if (((GameObject*)obj)->anim.seqId != 0x69c) return;
    ((GameObject*)obj)->anim.rotZ = *(s16*)(lbl_803DDC40 + 4);
}

void SB_ShipGun_free(int param_1);
