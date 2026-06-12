#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"

/* SB_Propeller_getExtraSize == 0x10. */
typedef struct SBPropellerState
{
    f32 smokeTimer; /* 0x00: countdown to the next smoke burst */
    f32 spinBlend; /* 0x04 */
    int spinRate; /* 0x08: init 1200 */
    s8 health; /* 0x0c: init 4 */
    u8 pad0D[3];
} SBPropellerState;

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

/* SB_ShipHead_getExtraSize == 0x10. */
typedef struct SBShipHeadState
{
    int target; /* 0x00: the 0x8c galleon-side object */
    s8 health; /* 0x04: init 4 */
    u8 pad05[3];
    f32 swayA; /* 0x08 */
    f32 swayB; /* 0x0c */
} SBShipHeadState;

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern undefined4 getLActions();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 FUN_8003b818();

extern undefined4 DAT_803dc070;
extern EffectInterface** gPartfxInterface;
extern undefined4 DAT_803de8c0;
extern f32 lbl_803DC074;
extern f32 lbl_803E64A8;
extern f32 lbl_803E64C8;
extern f32 lbl_803E64CC;
extern f32 lbl_803E64D0;
extern f32 lbl_803E64D4;

/*
 * --INFO--
 *
 * Function: SB_Galleon_animEventCallback
 * EN v1.0 Address: 0x801E1AAC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x801E18DC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void DBprotection_storeHomePosition(int obj);
extern int ObjList_GetObjects(int* start, int* end);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Music_Trigger(s32 snd, s32 mode);
extern f32 lbl_803E56CC;
extern void Sfx_StopFromObject(int obj, int sfxId);
extern u32 fn_801E2570(void);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern f32 lbl_803E57F4;
extern f32 lbl_803E57F8;
extern f32 lbl_803E5790;
extern f32 timeDelta;

int SB_Galleon_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate);

/*
 * --INFO--
 *
 * Function: fn_801E1588
 * EN v1.0 Address: 0x801E1588
 * EN v1.0 Size: 1316b
 * EN v1.1 Address: 0x801E1B78
 * EN v1.1 Size: 1316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    f32 x, y, z;
} SkyVec3;

extern void setDrawLights(int mode);
extern void skySetOverrideLightColorEnabled(int on);
extern void skySetOverrideLightColor(int r, int g, int b);
extern void skyFn_80089710(int a, int b, int c);
extern f32 fn_8008ED88(void);
extern void skyFn_800895e0(int idx, int r, int g, int b, int a, int b2);
extern void fn_80089510(int idx, int r, int g, int b);
extern void fn_80089578(int idx, int r, int g, int b);
extern void skySetOverrideLightDirectionEnabled(int on);
extern void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 w);
extern void skyFn_800894a8(int idx, f32 x, f32 y, f32 z);
extern int* Obj_GetActiveModel(int obj);
extern int ObjModel_GetRenderOp(int model, int idx);
extern f32 lbl_802C23F8[12];
extern u8 lbl_803DC078[4];
extern u8 lbl_803DC07C[4];
extern u8 lbl_803DC080[4];
extern u8 lbl_803DC084[4];
extern u8 lbl_803DC088[4];
extern u8 lbl_803DC08C[4];
extern f32 lbl_803DDC24;
extern f32 lbl_803DDC28;
extern u8 lbl_803DDC2D;
extern u8 lbl_803DDC30[3];
extern u8 lbl_803DDC34[3];
extern u8 lbl_803DDC38[3];
extern f32 lbl_803E57A4;
extern f32 lbl_803E57B4;
extern f32 lbl_803E57E0;
extern f32 lbl_803E57F0;
extern f32 lbl_803E5724;

void fn_801E1588(int obj, int state);


/*
 * --INFO--
 *
 * Function: SB_Propeller_update
 * EN v1.0 Address: 0x801E21B4
 * EN v1.0 Size: 1364b
 * EN v1.1 Address: 0x801E2BBC
 * EN v1.1 Size: 1212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern int DBprotection_getCameraState(u32 g);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern int Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32* x, f32* y, f32* z, int p);
extern void spawnExplosion(f32 s, int obj, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E5810;
extern f32 lbl_803E5814;
extern f32 lbl_803E5818;
extern f32 lbl_803E581C;
extern f32 lbl_803E5820;
extern f32 lbl_803E5824;

void SB_Propeller_update(int obj)
{
    ObjAnimComponent* objAnim;
    int camA;
    int camB;
    int camC;
    int i;
    int hit;
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
    if ((camC < 2) && (((SBPropellerState*)pf)->health < 1))
    {
        ((SBPropellerState*)pf)->smokeTimer = ((SBPropellerState*)pf)->smokeTimer - timeDelta;
        if (((SBPropellerState*)pf)->smokeTimer <= lbl_803E5814)
        {
            f32 spd = lbl_803E5810;
            for (i = randomGetRange(10, 0x19); i != 0; i--)
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
            for (i = 0; i < framesThisStep; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7aa, stk.pad, 2, -1, NULL);
            }
        }
    }
    if (*(int*)&((GameObject*)obj)->anim.parent != 0)
    {
        if ((((GameObject*)obj)->anim.seqId != 0x69c) && (*(int*)(*(int*)&((GameObject*)obj)->anim.parent + 0xf4) < 4))
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
                        && ((((GameObject*)obj)->unkF4 = 0x14, *(int*)&((GameObject*)obj)->anim.parent != 0)))))))
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
                *(u16*)&((GameObject*)obj)->anim.flags = *(u16*)&((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
                spawnExplosion(lbl_803E5824, obj, 1, 1, 1, 0, 1, 1, 0);
                Sfx_PlayFromObject(obj, 0x2c8);
            }
        }
        if (((GameObject*)obj)->unkF4 == 0)
        {
            ObjHitsPriorityState* hitState = *(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState;
            hitState->hitVolumePriority = 6;
            hitState->hitVolumeId = 1;
            hitState->objectHitMask = 0x10;
            hitState->skeletonHitMask = 0x10;
        }
        else
        {
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 0;
        }
        ((GameObject*)obj)->anim.rotZ = (int)-((f32)((SBPropellerState*)pf)->spinRate * timeDelta - (
            f32)((GameObject*)obj)->anim.rotZ);
    }
}

/*
 * --INFO--
 *
 * Function: SB_Propeller_init
 * EN v1.0 Address: 0x801E2708
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801E3078
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: SB_ShipHead_render
 * EN v1.0 Address: 0x801E27C4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801E314C
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SB_ShipHead_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible);

/*
 * --INFO--
 *
 * Function: SB_ShipHead_update
 * EN v1.0 Address: 0x801E2940
 * EN v1.0 Size: 1892b
 * EN v1.1 Address: 0x801E32D4
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u32 getSbGalleon(void);
extern f32 Vec_distance(void* a, void* b);
extern void Sfx_StopObjectChannel(int obj, int ch);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32* x, f32* y, f32* z);
extern u8* Obj_AllocObjectSetup(int size, int objId);
extern int Obj_SetupObject(u8* setup, int a, int b, int c, int d);
extern u8 lbl_803DC090;
extern int lbl_803DDC48;
extern f32 lbl_803E5834;
extern f32 lbl_803E5840;
extern f32 lbl_803E5844;
extern f32 lbl_803E5848;
extern f32 lbl_803E584C;
extern f32 lbl_803E5850;
extern f32 lbl_803E5854;
extern f32 lbl_803E5858;
extern f32 lbl_803E585C;
extern f32 sqrtf(f32);

void SB_ShipHead_update(int obj);


/* Trivial 4b 0-arg blr leaves. */
void SB_Galleon_release(void);

void SB_Galleon_initialise(void);

void SB_ShipMast_free(void);

void SB_ShipMast_hitDetect(void);

void SB_ShipMast_init(void);

void SB_ShipMast_release(void);

void SB_ShipMast_initialise(void);

extern f32 lbl_803E586C;
extern f32 lbl_803E5870;
extern f32 lbl_803E5874;
extern f32 lbl_803E5878;

void SB_ShipMast_update(int* obj);

/* 8b "li r3, N; blr" returners. */
int SB_Galleon_getExtraSize(void);
int SB_Galleon_getObjectTypeId(void);
int SB_Propeller_getExtraSize(void) { return 0x10; }
int SB_ShipHead_getExtraSize(void);
int SB_ShipHead_getObjectTypeId(void);
int SB_ShipMast_getExtraSize(void);
int SB_ShipMast_getObjectTypeId(void);
int SB_ShipGun_getExtraSize(void);

/* sda21 accessors. */
extern u32 gSbGalleon;
extern u32 lbl_803DDC40;
u32 getSbGalleon(void);
u32 fn_801E2570(void) { return lbl_803DDC40; }

/* Pattern wrappers. */
u8 SB_Galleon_render2(int* obj);

/* 16b chained patterns. */
s32 SB_Galleon_func0B(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5868;

void SB_Propeller_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5810);
}

void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void SB_ShipHead_free(int x);

/* SB_Propeller_hitDetect: guard on 0x46 == 0x69c, copy halfword from sda21 ptr. */
void SB_Propeller_hitDetect(int obj)
{
    if (((GameObject*)obj)->anim.seqId != 0x69c) return;
    ((GameObject*)obj)->anim.rotZ = *(s16*)(lbl_803DDC40 + 4);
}

/* SB_ShipGun_free: expgfx interface freeObject callback. */
void SB_ShipGun_free(int param_1);

/* SB_Galleon_setScale: state machine; advance counter, optionally play sfx. */
int SB_Galleon_setScale(int obj);

/* SB_Galleon_hitDetect: per-step expgfx spawn loop. */
extern f32 lbl_803E57FC;
extern f32 lbl_803E5800;
extern f32 lbl_803E5804;
extern f32 lbl_803E5808;
extern f32 lbl_803E5738;
extern f32 lbl_803E56F0;
extern f32 lbl_803E56C8;

void SB_Galleon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void SB_Galleon_hitDetect(int obj);


/*
 * --INFO--
 *
 * Function: SB_Galleon_update
 * EN v1.0 Address: 0x801E21AC
 * EN v1.0 Size: 568b
 */
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int idx, int p2);
extern void fn_801DFA28(int obj);
extern void DBprotection_updateShield(int obj);
extern void SCGameBitLatch_Update(u8* latch, int mask, int a, int b, int bit, int c);
extern ObjectTriggerInterface** gObjectTriggerInterface;

void SB_Galleon_update(int obj);

/*
 * --INFO--
 *
 * Function: SB_Galleon_init
 * EN v1.0 Address: 0x801E23E4
 * EN v1.0 Size: 388b
 */
extern void objSetSlot(void* obj, int slot);
extern void* textureLoadAsset(int id);
extern int lbl_803DDC18;
extern int lbl_803DDC1C;
extern f32 lbl_803E580C;

void SB_Galleon_init(int obj);


/* SB_Galleon_free: textureFree manager textures, ObjGroup_RemoveObject, kill music, set bit. */
extern void textureFree(void* tex);

void SB_Galleon_free(int obj, int p2);

/* SB_ShipHead_init: add to group, alloc msg queue, set state + bias positions. */
extern void ObjMsg_AllocQueue(int obj, int n);
extern f32 lbl_803E5830;
extern f32 lbl_803E5838;

void SB_ShipHead_init(int obj);

/* SB_ShipGun_render: conditional render with multiple flag checks. */
extern f32 lbl_803E5888;

void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */
int SB_Galleon_modelMtxFn(int* obj);

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */
int SB_Galleon_func0E(int* obj);
