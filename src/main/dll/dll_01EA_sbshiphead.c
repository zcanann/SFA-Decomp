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

void SB_Propeller_update(int obj);

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
void SB_Propeller_init(int obj, int arg2);

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
void SB_ShipHead_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    int ref;
    int state;
    byte i;
    u8 fxArgs[6];
    undefined2 sfxId;
    float volume;
    float dx;
    float dy;
    float dz[3];

    if (visible != 0)
    {
        state = *(int*)&((GameObject*)obj)->extra;
        FUN_8003b818(obj);
        ref = *(int*)&((GameObject*)obj)->anim.parent;
        if ((((ref != 0) && (((GameObject*)ref)->anim.seqId == 0x8e)) &&
            (ref = (**(code**)(**(int**)&((GameObject*)ref)->anim.dll + 0x2c))(), ref != 0)) && (ref != 2))
        {
            ((SBShipHeadState*)state)->swayA = ((SBShipHeadState*)state)->swayA - lbl_803DC074;
            if (((SBShipHeadState*)state)->swayA <= lbl_803E64CC)
            {
                ((SBShipHeadState*)state)->swayA = ((SBShipHeadState*)state)->swayA + lbl_803E64D0;
            }
            ((SBShipHeadState*)state)->swayB = ((SBShipHeadState*)state)->swayB - lbl_803DC074;
            if (((SBShipHeadState*)state)->swayB <= lbl_803E64CC)
            {
                ((SBShipHeadState*)state)->swayB = ((SBShipHeadState*)state)->swayB + lbl_803E64C8;
            }
            volume = lbl_803E64D4;
            sfxId = 0xc0a;
            ObjPath_GetPointWorldPosition(obj, 0xd, &dx, &dy, dz, 0);
            dx = dx - ((GameObject*)obj)->anim.worldPosX;
            dy = dy - ((GameObject*)obj)->anim.worldPosY;
            dz[0] = dz[0] - ((GameObject*)obj)->anim.worldPosZ;
            for (i = 0; i < DAT_803dc070; i = i + 1)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7aa, fxArgs, 2, -1, NULL);
            }
        }
    }
    return;
}

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

void SB_ShipHead_update(int obj)
{
    f32 ddx;
    f32 ddy;
    f32 ddz;
    f32 s;
    int player;
    u8* galleon;
    int state;
    int i;
    int mode;
    SBShipHeadState* hs;
    int proj;
    u8* setup;
    int msg;
    int start;
    int end;
    int hit;
    f32 px;
    f32 py;
    f32 pz;
    int tmp2[2];
    int tmp3;

    mode = 0;
    player = Obj_GetPlayerObject();
    galleon = *(u8**)&((GameObject*)obj)->anim.parent;
    if (galleon != 0)
    {
        state = DBprotection_getCameraState(getSbGalleon());
        if (state == 2)
        {
            if (Vec_distance((void*)(player + 0x18), (void*)&((GameObject*)obj)->anim.worldPosX) < lbl_803E5840)
            {
                Sfx_PlayFromObject(obj, 0x312);
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x40);
            }
        }
        state = ((GameObject*)galleon)->unkF4;
        hs = ((GameObject*)obj)->extra;
        if (*(void**)&hs->target == 0)
        {
            int* arr = (int*)ObjList_GetObjects(&start, &end);
            for (i = start; i < end; i++)
            {
                int o = arr[i];
                if (*(s16*)(o + 0x46) == 0x8c)
                {
                    hs->target = o;
                    i = end;
                }
            }
        }
        if (ObjMsg_Pop(obj, &msg, tmp2, &tmp3) != 0)
        {
            switch (msg)
            {
            case 0x130002:
                mode = 1;
                break;
            case 0x130003:
                mode = 2;
                break;
            }
        }
        if (((**(int (**)(u8*))(**(int**)&((GameObject*)galleon)->anim.dll + 0x28))(galleon) >= 2)
            && (((GameObject*)obj)->unkF8 <= 0) && (((uint)(state - 3) <= 1 || (state == 5)))
            && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0)
            && (*(s16*)(hit + 0x46) != 0x114))
        {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, 0x37);
            hs->health -= 1;
            if (hs->health <= 0)
            {
                (**(void (**)(u8*))(**(int**)&((GameObject*)galleon)->anim.dll + 0x20))(galleon);
                ((GameObject*)obj)->unkF8 = 300;
                ObjHits_DisableObject(obj);
            }
        }
        if (0 < ((GameObject*)obj)->unkF8)
        {
            ((GameObject*)obj)->unkF8 = ((GameObject*)obj)->unkF8 - framesThisStep;
        }
        if (state == 8)
        {
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 + 1;
            if (10 < ((GameObject*)obj)->unkF4)
            {
                ((GameObject*)obj)->unkF4 = 0;
            }
        }
        if ((state == 5) && (lbl_803DDC48 != 5))
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E5834, 0);
            lbl_803DC090 = 0;
        }
        if ((((((GameObject*)obj)->anim.currentMove == 1) && (lbl_803E5844 <= ((GameObject*)obj)->anim.
                currentMoveProgress))
            && (lbl_803DC090 == 0)) && (Obj_IsLoadingLocked() != 0))
        {
            lbl_803DC090 = 1;
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 + framesThisStep;
            Sfx_PlayFromObject(obj, 0x38);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E5848;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ - lbl_803E584C;
            Obj_GetWorldPosition(obj, &px, &py, &pz);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5848;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + lbl_803E584C;
            setup = Obj_AllocObjectSetup(0x18, 0x114);
            setup[6] = 0xff;
            setup[7] = 0xff;
            setup[4] = 2;
            setup[5] = 1;
            ((ObjPlacement*)setup)->posX = px;
            ((ObjPlacement*)setup)->posY = py;
            ((ObjPlacement*)setup)->posZ = pz;
            proj = Obj_SetupObject(setup, 5, -1, -1, 0);
            ddx = *(f32*)(player + 0x18) - *(f32*)(proj + 0xc);
            ddy = (*(f32*)(player + 0x1c) - lbl_803E5850) - *(f32*)(proj + 0x10);
            ddz = *(f32*)(player + 0x20) - *(f32*)(proj + 0x14);
            s = lbl_803E5850 / sqrtf(ddz * ddz + (ddx * ddx + ddy * ddy));
            *(f32*)(proj + 0x24) = ddx * s;
            *(f32*)(proj + 0x28) = ddy * s;
            *(f32*)(proj + 0x2c) = ddz * s;
            *(int*)(proj + 0xf4) = 0x78;
            *(int*)(proj + 0xf8) = hs->target;
        }
        if ((mode == 1) && (Obj_IsLoadingLocked() != 0))
        {
            Sfx_PlayFromObject(obj, 0x38);
            player = Obj_GetPlayerObject();
            setup = Obj_AllocObjectSetup(0x18, 0x138);
            ((ObjPlacement*)setup)->posX = lbl_803E5854 + *(f32*)(player + 0x18);
            ((ObjPlacement*)setup)->posY = lbl_803E5848 + (*(f32*)(player + 0x1c) + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            ((ObjPlacement*)setup)->posZ = lbl_803E5858 + (*(f32*)(player + 0x20) + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            setup[4] = 2;
            setup[5] = 1;
            setup[6] = 0xff;
            setup[7] = 0xff;
            Obj_SetupObject(setup, 5, -1, -1, 0);
        }
        proj = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E585C, timeDelta, NULL);
        if ((((GameObject*)obj)->anim.currentMove == 1) && (proj != 0))
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5834, 0);
        }
    }
    lbl_803DDC48 = state;
}


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
int SB_Propeller_getExtraSize(void);
int SB_ShipHead_getExtraSize(void) { return 0x10; }
int SB_ShipHead_getObjectTypeId(void) { return 0x1; }
int SB_ShipMast_getExtraSize(void);
int SB_ShipMast_getObjectTypeId(void);
int SB_ShipGun_getExtraSize(void);

/* sda21 accessors. */
extern u32 gSbGalleon;
extern u32 lbl_803DDC40;
u32 getSbGalleon(void);
u32 fn_801E2570(void);

/* Pattern wrappers. */
u8 SB_Galleon_render2(int* obj);

/* 16b chained patterns. */
s32 SB_Galleon_func0B(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5868;

void SB_Propeller_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void SB_ShipHead_free(int x) { ObjGroup_RemoveObject(x, 0x3); }

/* SB_Propeller_hitDetect: guard on 0x46 == 0x69c, copy halfword from sda21 ptr. */
void SB_Propeller_hitDetect(int obj);

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

void SB_ShipHead_init(int obj)
{
    f32* p = (f32*)((int**)obj)[0xb8 / 4];
    ObjGroup_AddObject(obj, 3);
    ObjMsg_AllocQueue(obj, 10);
    ((SBShipHeadState*)p)->health = 4;
    ((SBShipHeadState*)p)->swayB = ((SBShipHeadState*)p)->swayB + lbl_803E5830;
    ((SBShipHeadState*)p)->swayA = ((SBShipHeadState*)p)->swayA + lbl_803E5838;
}

/* SB_ShipGun_render: conditional render with multiple flag checks. */
extern f32 lbl_803E5888;

void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */
int SB_Galleon_modelMtxFn(int* obj);

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */
int SB_Galleon_func0E(int* obj);
