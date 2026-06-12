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

/* SB_Propeller_getExtraSize == 0x10. */


STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

/* SB_ShipHead_getExtraSize == 0x10. */


STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern undefined4 getLActions();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();

extern EffectInterface** gPartfxInterface;

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

int SB_Galleon_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    ((GameObject*)obj)->anim.mapEventSlot = -1;
    fn_801E1588(obj, state);
    {
        f32 z = lbl_803E56CC;
        ((SBGalleonState*)state)->moveScale = lbl_803E56CC;
        ((SBGalleonState*)state)->swayX = z;
        ((SBGalleonState*)state)->swayY = z;
        ((SBGalleonState*)state)->swayZ = z;
    }
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)DBprotection_storeHomePosition;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 2:
            if (((SBGalleonState*)state)->spiritPhase == 1)
            {
                ((SBGalleonState*)state)->spiritPhase = 0;
            }
            else
            {
                ((SBGalleonState*)state)->spiritPhase = 1;
            }
            break;
        case 3:
            {
                int start;
                int end;
                int* arr = (int*)ObjList_GetObjects(&start, &end);
                for (i = start; i < end; i++)
                {
                    if (*(s16*)(arr[i] + 0x46) == 0xf7)
                    {
                        ((SBGalleonState*)state)->linkedActor = arr[i];
                        i = end;
                    }
                }
                ((SBGalleonState*)state)->sprayActive = 1;
                break;
            }
        case 4:
            ((SBGalleonState*)state)->sprayActive = 0;
            break;
        case 5:
            if (((SBGalleonState*)state)->spiritPhase == 2)
            {
                ((SBGalleonState*)state)->spiritPhase = 0;
            }
            else
            {
                ((SBGalleonState*)state)->spiritPhase = 2;
            }
            break;
        case 6:
            Sfx_PlayFromObject(obj, 0x143);
            break;
        case 7:
            Sfx_StopFromObject(obj, 0x143);
            break;
        case 8:
            if (((SBGalleonState*)state)->spiritPhase == 8)
            {
                ((SBGalleonState*)state)->spiritPhase = 1;
            }
            else
            {
                ((SBGalleonState*)state)->spiritPhase = 8;
            }
            break;
        case 9:
            ((SBGalleonState*)state)->skyFlag = 1;
            break;
        case 10:
            ((SBGalleonState*)state)->skyFlag = 0;
            break;
        case 0xb:
            Sfx_PlayFromObject(fn_801E2570(), 0x2c6);
            break;
        case 0xc:
            ((SBGalleonState*)state)->musicIdB = 0xa3;
            Music_Trigger(((SBGalleonState*)state)->musicIdB, 1);
            Music_Trigger(((SBGalleonState*)state)->musicIdA, 0);
            break;
        case 0xd:
            ((SBGalleonState*)state)->textTimer = lbl_803E57F8;
            ((SBGalleonState*)state)->textRising = 1;
            ((SBGalleonState*)state)->textAlpha = lbl_803E56CC;
            break;
        }
    }
    {
        f32 z = lbl_803E56CC;
        if (((SBGalleonState*)state)->textTimer >= z)
        {
            ((SBGalleonState*)state)->textTimer = ((SBGalleonState*)state)->textTimer - timeDelta;
            if (((SBGalleonState*)state)->textTimer < z)
            {
                ((SBGalleonState*)state)->textTimer = z;
                ((SBGalleonState*)state)->textRising = 0;
            }
        }
    }
    if (((SBGalleonState*)state)->textRising != 0)
    {
        ((SBGalleonState*)state)->textAlpha = lbl_803E5790 * timeDelta + ((SBGalleonState*)state)->textAlpha;
    }
    else
    {
        ((SBGalleonState*)state)->textAlpha = -(lbl_803E5790 * timeDelta - ((SBGalleonState*)state)->textAlpha);
    }
    {
        f32 v = ((SBGalleonState*)state)->textAlpha;
        f32 c = lbl_803E56CC;
        if (!(v < lbl_803E56CC))
        {
            c = lbl_803E57F4;
            if (!(v > lbl_803E57F4))
            {
                c = v;
            }
        }
        ((SBGalleonState*)state)->textAlpha = c;
    }
    if (((SBGalleonState*)state)->textAlpha > lbl_803E56CC)
    {
        gameTextSetColor(0xff, 0xff, 0xff, (int)((SBGalleonState*)state)->textAlpha);
        gameTextShow(0x4b1);
    }
    ((SBGalleonState*)state)->posX = ((GameObject*)obj)->anim.localPosX;
    ((SBGalleonState*)state)->posY = ((GameObject*)obj)->anim.localPosY;
    ((SBGalleonState*)state)->posZ = ((GameObject*)obj)->anim.localPosZ;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

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

void fn_801E1588(int obj, int state)
{
    int* model;
    int i;
    int rop;
    SkyVec3 a;
    SkyVec3 b;
    SkyVec3 c;
    SkyVec3 d;
    a = ((SkyVec3*)lbl_802C23F8)[0];
    b = ((SkyVec3*)lbl_802C23F8)[1];
    c = ((SkyVec3*)lbl_802C23F8)[2];
    d = ((SkyVec3*)lbl_802C23F8)[3];
    setDrawLights(0);
    skySetOverrideLightColorEnabled(1);
    skySetOverrideLightColor(0x29, 0x4b, 0xa9);
    skyFn_80089710(7, 1, 0);
    if (fn_8008ED88() > lbl_803E56CC)
    {
        lbl_803DDC24 = lbl_803E57A4;
        lbl_803DDC28 = lbl_803E57A4;
    }
    lbl_803DDC28 = -(lbl_803E57B4 * timeDelta - lbl_803DDC28);
    if (lbl_803DDC28 < lbl_803E56CC)
    {
        lbl_803DDC28 = lbl_803E56CC;
    }
    {
        int v0 = lbl_803DC080[0];
        lbl_803DDC38[0] = (f32)v0 + lbl_803DDC28 * (f32)(lbl_803DC084[0] - v0);
    }
    {
        int v1 = lbl_803DC080[1];
        lbl_803DDC38[1] = (f32)v1 + lbl_803DDC28 * (f32)(lbl_803DC084[1] - v1);
    }
    {
        int v2 = lbl_803DC080[2];
        lbl_803DDC38[2] = (f32)v2 + lbl_803DDC28 * (f32)(lbl_803DC084[2] - v2);
    }
    skyFn_800895e0(7, lbl_803DDC38[0], lbl_803DDC38[1], lbl_803DDC38[2], 0x40, 0x40);
    {
        int v0 = lbl_803DC078[0];
        lbl_803DDC34[0] = (f32)v0 + lbl_803DDC28 * (f32)(lbl_803DC07C[0] - v0);
    }
    {
        int v1 = lbl_803DC078[1];
        lbl_803DDC34[1] = (f32)v1 + lbl_803DDC28 * (f32)(lbl_803DC07C[1] - v1);
    }
    {
        int v2 = lbl_803DC078[2];
        lbl_803DDC34[2] = (f32)v2 + lbl_803DDC28 * (f32)(lbl_803DC07C[2] - v2);
    }
    fn_80089510(7, lbl_803DDC34[0], lbl_803DDC34[1], lbl_803DDC34[2]);
    {
        int v0 = lbl_803DC088[0];
        lbl_803DDC30[0] = (f32)v0 + lbl_803DDC28 * (f32)(lbl_803DC08C[0] - v0);
    }
    {
        int v1 = lbl_803DC088[1];
        lbl_803DDC30[1] = (f32)v1 + lbl_803DDC28 * (f32)(lbl_803DC08C[1] - v1);
    }
    {
        int v2 = lbl_803DC088[2];
        lbl_803DDC30[2] = (f32)v2 + lbl_803DDC28 * (f32)(lbl_803DC08C[2] - v2);
    }
    fn_80089578(7, lbl_803DDC30[0], lbl_803DDC30[1], lbl_803DDC30[2]);
    lbl_803DDC2D = lbl_803DDC28 * lbl_803E57E0 + lbl_803E57F0;
    skySetOverrideLightDirectionEnabled(1);
    skySetOverrideLightDirection(lbl_803DDC28 * (d.x - c.x) + c.x,
                                 lbl_803DDC28 * (d.y - c.y) + c.y,
                                 lbl_803DDC28 * (d.z - c.z) + c.z, lbl_803E5724);
    if (((SBGalleonState*)state)->skyFlag == 0)
    {
        skyFn_800894a8(7, a.x, a.y, a.z);
    }
    else
    {
        skyFn_800894a8(7, b.x, b.y, b.z);
    }
    model = Obj_GetActiveModel(obj);
    i = 0;
    {
        f32 scale = lbl_803E57F4;
        for (; i < *(u8*)(*model + 0xf8); i++)
        {
            rop = ObjModel_GetRenderOp(*model, i);
            if (*(u8*)(rop + 0x29) == 1)
            {
                *(u8*)(rop + 0xc) = scale * lbl_803DDC28;
            }
        }
    }
}


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
extern u8 framesThisStep;

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



/* Trivial 4b 0-arg blr leaves. */
void SB_Galleon_release(void)
{
}

void SB_Galleon_initialise(void)
{
}

void SB_ShipMast_free(void);







/* 8b "li r3, N; blr" returners. */
int SB_Galleon_getExtraSize(void) { return 0xb4; }
int SB_Galleon_getObjectTypeId(void) { return 0x0; }
int SB_Propeller_getExtraSize(void);

/* sda21 accessors. */
extern u32 gSbGalleon;
u32 getSbGalleon(void) { return gSbGalleon; }
u32 fn_801E2570(void);

/* Pattern wrappers. */
u8 SB_Galleon_render2(int* obj) { return *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x79); }

/* 16b chained patterns. */
s32 SB_Galleon_func0B(int* obj) { return *(s8*)((char*)((int**)obj)[0xb8 / 4] + 0x2b); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);



/* ObjGroup_RemoveObject(x, N) wrappers. */

/* SB_Propeller_hitDetect: guard on 0x46 == 0x69c, copy halfword from sda21 ptr. */

/* SB_ShipGun_free: expgfx interface freeObject callback. */

/* SB_Galleon_setScale: state machine; advance counter, optionally play sfx. */
int SB_Galleon_setScale(int obj)
{
    s8* p = (s8*)((int**)obj)[0xb8 / 4];
    int s = ((SBGalleonState*)p)->phase;
    if (s != 1)
    {
        if (s >= 2)
        {
            Sfx_PlayFromObject(obj, SFXen_diallp_c);
        }
        ((SBGalleonState*)p)->stage = ((SBGalleonState*)p)->stage + 1;
        return 1;
    }
    {
        int t = *(s8*)&((SBGalleonState*)p)->flightPattern;
        if (t == 0 || t == 1 || t == 2)
        {
            ((SBGalleonState*)p)->phaseCounter = ((SBGalleonState*)p)->phaseCounter + 1;
            return 1;
        }
    }
    return 0;
}

/* SB_Galleon_hitDetect: per-step expgfx spawn loop. */
extern f32 lbl_803E57FC;
extern f32 lbl_803E5800;
extern f32 lbl_803E5804;
extern f32 lbl_803E5808;
extern f32 lbl_803E5738;
extern f32 lbl_803E56F0;
extern f32 lbl_803E56C8;

void SB_Galleon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* p = (u8*)((int**)obj)[0xb8 / 4];
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 unused;
        f32 a;
        f32 b;
        f32 c;
    } stk;
    if (visible != 0)
    {
        if ((s8)((SBGalleonState*)p)->cameraState < 2)
        {
            stk.mode = (u16)(s32)((SBGalleonState*)p)->wanderA;
            stk.a = lbl_803E5804;
            stk.b = lbl_803E5800;
            stk.c = lbl_803E57FC;
            (*gPartfxInterface)->spawnObject((void*)obj, 0xa3, stk.pad, 2, -1, NULL);
            stk.mode = (u16)(s32)((SBGalleonState*)p)->wanderB;
            stk.a = lbl_803E5808;
            (*gPartfxInterface)->spawnObject((void*)obj, 0xa3, stk.pad, 2, -1, NULL);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E57A4);
    }
}

void SB_Galleon_hitDetect(int obj)
{
    int* p = ((int**)obj)[0xb8 / 4];
    u8 i;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;
    if (((SBGalleonState*)p)->sprayActive != 0 && ((SBGalleonState*)p)->linkedActor != 0)
    {
        stk.a = lbl_803E5738;
        stk.mode = 0xc0a;
        stk.b = lbl_803E56CC;
        stk.c = lbl_803E56F0;
        stk.d = lbl_803E56C8;
        for (i = 0; i < framesThisStep; i = i + 1)
        {
            (*gPartfxInterface)->spawnObject(
                (void*)((SBGalleonState*)p)->linkedActor, 0x7aa, stk.pad, 2, -1, 0);
        }
    }
}


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

void SB_Galleon_update(int obj)
{
    s8* p = (s8*)((int**)obj)[0xb8 / 4];
    ((GameObject*)obj)->anim.mapEventSlot = ((SBGalleonState*)p)->mapLayer;
    fn_801E1588(obj, (int)p);
    if (GameBit_Get(0x75) == 0)
    {
        (*gMapEventInterface)->setMode(0xb, 1);
        (*gMapEventInterface)->setAnimEvent(0xb, 0, 1);
        (*gMapEventInterface)->setAnimEvent(0xb, 1, 1);
        (*gMapEventInterface)->setAnimEvent(0xb, 5, 1);
        lockLevel(mapGetDirIdx(0xb), 0);
        if ((*gMapEventInterface)->getAnimEvent(*(u8*)(obj + 0x34), 1) == 0)
        {
            (*gMapEventInterface)->setAnimEvent(*(u8*)(obj + 0x34), 1, 1);
        }
        ((GameObject*)obj)->unkF4 = 0;
    }
    else
    {
        if ((((SBGalleonState*)p)->unk80 == 0) && (*(s8*)&((SBGalleonState*)p)->cameraState > 0))
        {
            *(s8*)&((SBGalleonState*)p)->unk80 = 1;
        }
        switch (*(s8*)&((SBGalleonState*)p)->cameraState)
        {
        case 0:
            fn_801DFA28(obj);
            break;
        case 1:
            (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
            *(s8*)&((SBGalleonState*)p)->cameraState = 2;
            break;
        case 2:
            DBprotection_updateShield(obj);
            break;
        case 3:
            (*gMapEventInterface)->setMode(0xb, 1);
            ((GameObject*)obj)->anim.mapEventSlot = -1;
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
            *(s8*)&((SBGalleonState*)p)->cameraState = 4;
            break;
        }
        SCGameBitLatch_Update((u8*)p + 0xb0, 1, -1, -1, 0xa71, 0xa4);
    }
}

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

void SB_Galleon_init(int obj)
{
    int p = *(int*)&((GameObject*)obj)->extra;
    gSbGalleon = obj;
    ObjGroup_AddObject(obj, 3);
    objSetSlot((void*)obj, 0x5a);
    ((GameObject*)obj)->animEventCallback = (void*)SB_Galleon_animEventCallback;
    ((SBGalleonState*)p)->posX = ((GameObject*)obj)->anim.localPosX;
    ((SBGalleonState*)p)->posY = ((GameObject*)obj)->anim.localPosY;
    ((SBGalleonState*)p)->posZ = ((GameObject*)obj)->anim.localPosZ;
    *(u8*)&((SBGalleonState*)p)->sweepDir = 1;
    ((SBGalleonState*)p)->timer26 = 0xf0;
    ((SBGalleonState*)p)->phaseTimer = 0xf0;
    ((SBGalleonState*)p)->spiritPhase = 0;
    ((SBGalleonState*)p)->headingLatch = 200;
    ((SBGalleonState*)p)->envfxActs[2] = 0x89;
    ((SBGalleonState*)p)->envfxActs[3] = 0x95;
    ((SBGalleonState*)p)->envfxActs[4] = 0x86;
    ((SBGalleonState*)p)->envfxActs[5] = 0x88;
    ((SBGalleonState*)p)->envfxActs[0] = 0x87;
    ((SBGalleonState*)p)->envfxActs[1] = 0x97;
    ((SBGalleonState*)p)->mapLayer = ((GameObject*)obj)->anim.mapEventSlot;
    *(s16*)obj = 0x4000;
    ((GameObject*)obj)->anim.rotY = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    lbl_803DDC18 = (int)textureLoadAsset(0x16d);
    lbl_803DDC1C = (int)textureLoadAsset(0x89);
    ((SBGalleonState*)p)->unk84 = 100;
    (*gMapEventInterface)->setMode(((GameObject*)obj)->anim.mapEventSlot, 1);
    getLActions(obj, obj, 0x58, 0, 0, 0);
    ((SBGalleonState*)p)->wanderTimerA = lbl_803E56CC;
    ((SBGalleonState*)p)->wanderTimerB = lbl_803E580C;
    (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags |= 0x1800;
    setDrawLights(0);
    ((SBGalleonState*)p)->musicIdA = 0x92;
    ((SBGalleonState*)p)->musicIdB = 0x91;
    Music_Trigger(((SBGalleonState*)p)->musicIdB, 1);
}


/* SB_Galleon_free: textureFree manager textures, ObjGroup_RemoveObject, kill music, set bit. */
extern void textureFree(void* tex);

void SB_Galleon_free(int obj, int p2)
{
    u8* p = (u8*)((int**)obj)[0xb8 / 4];
    if ((void*)lbl_803DDC18 != NULL)
    {
        textureFree((void*)lbl_803DDC18);
        lbl_803DDC18 = 0;
    }
    if ((void*)lbl_803DDC1C != NULL)
    {
        textureFree((void*)lbl_803DDC1C);
        lbl_803DDC1C = 0;
    }
    ObjGroup_RemoveObject(obj, 3);
    if (((SBGalleonState*)p)->unk80 != 0 && p2 == 0)
    {
        ((SBGalleonState*)p)->unk80 = 0;
    }
    gSbGalleon = 0;
    Music_Trigger(((SBGalleonState*)p)->musicIdB, 0);
    Music_Trigger(((SBGalleonState*)p)->musicIdA, 0);
    GameBit_Set(0xac8, 1);
}

/* SB_ShipHead_init: add to group, alloc msg queue, set state + bias positions. */
extern void ObjMsg_AllocQueue(int obj, int n);

void SB_ShipHead_init(int obj);

/* SB_ShipGun_render: conditional render with multiple flag checks. */


/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */
int SB_Galleon_modelMtxFn(int* obj)
{
    u8* p = (u8*)((int**)obj)[0xb8 / 4];
    u8 b = *(u8*)&((SBGalleonState*)p)->phase;
    if ((s8)b == 0)
    {
        if (((SBGalleonState*)p)->timer26 > 0) return -2;
    }
    if ((s8)b == 1)
    {
        int t = (s8)((SBGalleonState*)p)->flightPattern;
        if (t == 2) return -1;
        if (t == 3) return -1;
        if (t == 5) return -1;
    }
    return (s8)b;
}

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */
int SB_Galleon_func0E(int* obj)
{
    register s8* p = (s8*)((int**)obj)[0xb8 / 4];
    s8 phase;
    int wrappedPhase;
    if (((SBGalleonState*)p)->phase == 1)
    {
        phase = ((SBGalleonState*)p)->phaseCounter;
        if (phase >= 5)
        {
            wrappedPhase = phase - 5;
        }
        else
        {
            wrappedPhase = phase;
        }
        return (6 - wrappedPhase) * 0x5a;
    }
    return 0x640;
}
