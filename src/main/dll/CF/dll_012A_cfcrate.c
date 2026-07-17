/*
 * cfccrate (DLL 0x12A) - the shared "crate" prop handler: one DLL
 * driving dozens of simple placement types across maps (cogs, warding
 * stones, rising water, spinning rings, lock symbols, galleon masts,
 * ice floes, ...). init seeds per-type state from the placement record,
 * update dispatches per-type motion/SFX on the romlist type id, and the
 * SeqFn handles the few types with anim-event work.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/render_lactions_api.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/dll/CF/dll_012B_fxemit.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/object_descriptor.h"
#include "main/dll/CF/dll_012A_cfcrate.h"
#include "main/object_render_legacy.h"

extern f32 lbl_803E3E40;

u16 gCfCrateDefaultSfxTable[4] = {0x151, 0, 0, 0};

typedef struct CfccratePlacement
{
    s16 id;
    u8 pad2[0x8 - 0x2];
    f32 homeX;
    f32 homeY;
    f32 homeZ;
    u8 pad14[0x18 - 0x14];
    s8 rotX;      /* 0x18: spawn pitch byte, <<8 into anim.rotX */
    u8 bankIndex; /* 0x19: anim bank index */
    s16 param1A;
    s16 param1C;
    u8 pad1E[0x20 - 0x1E];
    s16 gameBit;
} CfccratePlacement;

STATIC_ASSERT(offsetof(CfccratePlacement, id) == 0x0);
STATIC_ASSERT(offsetof(CfccratePlacement, homeX) == 0x8);
STATIC_ASSERT(offsetof(CfccratePlacement, homeY) == 0xC);
STATIC_ASSERT(offsetof(CfccratePlacement, homeZ) == 0x10);
STATIC_ASSERT(offsetof(CfccratePlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(CfccratePlacement, bankIndex) == 0x19);
STATIC_ASSERT(offsetof(CfccratePlacement, param1A) == 0x1A);
STATIC_ASSERT(offsetof(CfccratePlacement, param1C) == 0x1C);
STATIC_ASSERT(offsetof(CfccratePlacement, gameBit) == 0x20);

#define CFCRATE_HIT_VOLUME_SLOT 0x13

#define PARTFX_SPAWN(obj, fxId, a, b, c, d)                                                                            \
    (*gPartfxInterface)->spawnObject((void*)(obj), (fxId), (void*)(a), (b), (c), (void*)(d))



int CFCrate_getExtraSize(void)
{
    return 0x4c;
}
int CFCrate_getObjectTypeId(void)
{
    return 0x1;
}

void CFCrate_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void CFCrate_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{

    int objectType;
    CfCcrateState* state;

    state = (obj)->extra;
    if ((s32)visible == 0 || (objectType = (obj)->anim.seqId) == 0x1b8)
    {
        return;
    }
    if (visible == 0 || objectType == 0x6bf)
    {
        if (mainGetBit(state->gameBit2) == 0)
        {
            return;
        }
    }
    objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, 1.0f);
}

int CFCrate_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    CfCcrateState* state;
    int i;

    state = (obj)->extra;
    switch ((obj)->anim.seqId)
    {
    case 0x85:
    case 0x86:
        break;
    case 0x8E: /* SB_Galleon */
        break;
    case 0xAB:
        break;
    case 0xAE:
        break;
    case 0x10D: /* DIM2IceFloe */
        break;
    case 0x409:
        break;
    case 0x2B7: /* WM_largerock */
        if (mainGetBit(state->gameBit2) != 0)
        {
            ((u8*)animUpdate)[0x90] = (u8)(((u8*)animUpdate)[0x90] | 4);
        }
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 1)
            {
                PARTFX_SPAWN(obj, 0x44, 0, 2, -1, 0);
            }
            animUpdate->eventIds[i] = 0;
        }
        break;
    }
    return 0;
}

void CFCrate_hitDetect(void)
{
}

void CFCrate_update(GameObject* obj)
{

    CfCcrateState* state;
    int viewslot;
    int cam;
    int rotDelta;
    short id;

    Obj_GetPlayerObject();
    state = (obj)->extra;
    cam = (int)Camera_GetCurrentViewSlot();
    id = (obj)->anim.seqId;
    viewslot = *(int*)&(obj)->anim.placementData;

    switch (id)
    {
    case 0x7de: /* LinkF_cog */
        if (mainGetBit(state->gameBit) != 0)
        {
            (obj)->anim.rotZ = (short)-(timeDelta * state->oscVelB - (f32)(obj)->anim.rotZ);
        }
        else
        {
            (obj)->anim.rotZ = (short)(timeDelta * state->oscVelB + (f32)(obj)->anim.rotZ);
        }
        break;
    case 0x729: /* VFP_Warding... */
        if (mainGetBit(state->gameBit) == 0)
        {
            (obj)->anim.rotY = (obj)->anim.rotY + framesThisStep * 100;
        }
        break;
    case 0x71b: /* DFP_WaterHi... */
        state->lingerTimer -= framesThisStep;
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, CFCRATE_HIT_VOLUME_SLOT, 1, 0);
        if (state->lingerTimer <= 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            (obj)->anim.localPosY = (f32) - (2.0 * timeDelta - (obj)->anim.localPosY);
        }
        break;
    case 0x6fc: /* DFP_Water */
        if ((mainGetBit(state->gameBit) != 0) &&
            ((obj)->anim.localPosY <= 40.0f + ((CfccratePlacement*)viewslot)->homeY))
        {
            (obj)->anim.localPosY = 0.5f * timeDelta + (obj)->anim.localPosY;
            if ((obj)->anim.localPosY >= 40.0f + ((CfccratePlacement*)viewslot)->homeY)
            {
                mainSetBits(state->gameBit, 0);
            }
        }
        break;
    case 0x6fd: /* DFP_InnerRing */
        if (mainGetBit(state->gameBit) != 0)
        {
            (obj)->anim.rotX = (obj)->anim.rotX + (s32)(4000.0f * timeDelta);
            (obj)->anim.rotZ = (obj)->anim.rotZ + (s32)(1000.0f * timeDelta);
        }
        else
        {
            (obj)->anim.rotX = (obj)->anim.rotX + (s32)(4000.0f * timeDelta);
            (obj)->anim.rotZ = (obj)->anim.rotZ + (s32)(1000.0f * timeDelta);
        }
        break;
    case 0x6fe: /* DFP_OuterRing */
        if (mainGetBit(state->gameBit) != 0)
        {
            (obj)->anim.rotY = (obj)->anim.rotY + (s32)(4000.0f * timeDelta);
            (obj)->anim.rotZ = (obj)->anim.rotZ + (s32)(1000.0f * timeDelta);
        }
        else
        {
            (obj)->anim.rotY = (obj)->anim.rotY + (s32)(4000.0f * timeDelta);
            (obj)->anim.rotZ = (obj)->anim.rotZ + (s32)(1000.0f * timeDelta);
        }
        break;
    case 0x622: /* VFP_locksym */
    {
        ObjTextureRuntimeSlot* p = objFindTexture(obj, 0, 0);
        if ((p != NULL) && (mainGetBit(state->gameBit) != 0) && (p->textureId == 0))
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_en_littletink22_3c4);
            p->textureId = 0x100;
        }
        break;
    }
    case 0x65c:
        break;
    case 0x65d:
        ObjAnim_AdvanceCurrentMove((int)obj, 0.002f, timeDelta, NULL);
        break;
    case 0x6b4: /* MMP_Organic... */
        ObjAnim_AdvanceCurrentMove((int)obj, 0.002f, timeDelta, NULL);
        break;
    case 0x708: /* VFP_newball... */
        if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) != 0)
        {
            mainSetBits(state->gameBit, 1);
        }
        if (mainGetBit(state->gameBit) == 0)
        {
            (obj)->anim.rotX = (obj)->anim.rotX + ((s8*)viewslot)[0x18] * framesThisStep;
        }
        break;
    case 0x409:
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        break;
    case 0x6be: /* VFP_liftgra... */
        if ((mainGetBit(state->gameBit2) != 0) && (state->gameBit2Latch == 0))
        {
            state->gameBit2Latch = 1;
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        break;
    case 0x4bf:
        if (((obj)->anim.localPosY < 30.0f + ((CfccratePlacement*)viewslot)->homeY) &&
            (mainGetBit(state->gameBit) != 0))
        {
            (obj)->anim.localPosY = (obj)->anim.localPosY + timeDelta;
        }
        break;
    case 0x828:
        if ((mainGetBit(state->gameBit2) != 0) && (state->gameBit2Latch == 0))
        {
            if ((obj)->anim.rotZ + (rotDelta = (s32)(100.0f * timeDelta)) > 0x7fff)
            {
                state->gameBit2Latch = 1;
                (obj)->anim.rotZ = 0x7fff;
            }
            else
            {
                (obj)->anim.rotZ = (short)((obj)->anim.rotZ + rotDelta);
            }
        }
        break;
    case 0x8e:
        state->oscPosA = 3.0f * state->oscVelA + state->oscPosA;
        if ((state->oscPosA > 180.0f) || (state->oscPosA < -180.0f))
        {
            state->oscVelA = -state->oscVelA;
        }
        if ((state->oscPosB > 90.0f) || (state->oscPosB < -90.0f))
        {
            state->oscVelB = -state->oscVelB;
        }
        state->oscPosB = 3.0f * state->oscVelB + state->oscPosB;
        break;
    case 0x10d:
        state->sfxTimer -= framesThisStep;
        if (state->sfxTimer < 0)
        {
            u32 r;
            int tbl;
            r = randomGetRange(0, state->sfxCount - 1) << 1;
            tbl = *(int volatile*)&state->sfxTable;
            Sfx_PlayFromObject((int)obj, *(u16*)(tbl + r));
            state->sfxTimer = state->sfxPeriod;
            r = randomGetRange(0, state->sfxPeriod);
            state->sfxTimer = state->sfxTimer + r;
        }
        break;
    case 0x125:
    {
        f32 fx, fy, fz;
        f32 dist;
        int player;

        (obj)->anim.rotZ = (s16)(1.5 * (double)-(s32) * (s16*)(cam + 4));
        player = (int)Obj_GetPlayerObject();
        fx = ((GameObject*)player)->anim.worldPosX - (obj)->anim.worldPosX;
        fz = ((GameObject*)player)->anim.worldPosZ - (obj)->anim.worldPosZ;
        fy = ((GameObject*)player)->anim.worldPosY - (obj)->anim.worldPosY;
        dist = sqrtf(fy * fy + (fx * fx + fz * fz));
        if (dist < 75.0f && state->proximityLatch == 1)
        {
            state->proximityLatch = 0;
            getLActionsVoid6((int)obj, (int)obj, 0x5c, 0, 0, 0);
        }
        else if ((dist > 75.0f) && (state->proximityLatch == 0))
        {
            state->proximityLatch = 1;
            getLActionsVoid6((int)obj, (int)obj, 0x5d, 0, 0, 0);
        }
        break;
    }
    }
}

void CFCrate_init(GameObject* obj, int aux)
{

    ObjAnimComponent* objAnim;
    CfCcrateState* state;
    short id;
    f32 zeroF;

    objAnim = (ObjAnimComponent*)obj;
    id = ((CfccratePlacement*)aux)->id;
    state = (obj)->extra;
    zeroF = 1.0f;
    state->unk2C = zeroF;

    switch (id)
    {
    case 0x2bb:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        (obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
        (obj)->anim.rotZ = ((CfccratePlacement*)aux)->param1C;
        (obj)->anim.rootMotionScale = zeroF;
        break;
    case 0x1d0:
    case 0x1d1:
    case 0x1d7:
    case 0x1e6:
    case 0x201:
    case 0x23b:
    case 0x492:
    case 0x78b:
    case 0x78c:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        break;
    case 0x726:
        (obj)->animEventCallback = CFCrate_SeqFn;
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        break;
    case 0x71b:
        state->lingerTimer = ((CfccratePlacement*)aux)->param1A;
        break;
    case 0x6be:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit2Latch = 0;
        state->gameBit2 = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x828:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit2Latch = 0;
        state->gameBit2 = ((CfccratePlacement*)aux)->gameBit;
        if ((mainGetBit(state->gameBit2) != 0) && (state->gameBit2Latch == 0))
        {
            (obj)->anim.rotZ = 0x7fff;
            state->gameBit2Latch = 1;
        }
        break;
    case 0x6bf:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        (obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
        state->gameBit2 = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x708:
        objAnim->bankIndex = (s8)((CfccratePlacement*)aux)->param1A;
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        if (objAnim->bankIndex >= 3)
        {
            objAnim->bankIndex = 0;
        }
        Obj_SetActiveModelIndex(obj, objAnim->bankIndex);
        break;
    case 0x6fc:
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x622:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x6b4:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        (obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
        ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
        break;
    case 0x66c:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x216:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        (obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
        break;
    case 0x4bf:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        *(u8*)&objAnim->bankIndex = ((CfccratePlacement*)aux)->bankIndex;
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        if (mainGetBit(state->gameBit) != 0)
        {
            (obj)->anim.localPosY = 30.0f + ((CfccratePlacement*)aux)->homeY;
        }
        break;
    case 0x8e:
        (obj)->anim.rotX = 0;
        (obj)->anim.rotY = 0;
        if (((CfccratePlacement*)aux)->param1C >= 0x3e8)
        {
            (obj)->anim.rootMotionScale = zeroF / ((f32)(s32)((CfccratePlacement*)aux)->param1C / 1000.0f);
        }
        else
        {
            (obj)->anim.rootMotionScale = 0.2f;
        }
        state->gameBit2Latch = 0;
        state->homeX = ((CfccratePlacement*)aux)->homeX;
        state->homeY = ((CfccratePlacement*)aux)->homeY;
        state->homeZ = ((CfccratePlacement*)aux)->homeZ;
        state->oscPosA = state->oscPosB = 0.0f;
        state->unk28 = 1000.0f;
        state->unk20 = 400.0f;
        state->oscVelA = state->oscVelB = 0.5f;
        (obj)->anim.rotZ = 0;
        (obj)->animEventCallback = CFCrate_SeqFn;
        break;
    case 0x7de:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        (obj)->anim.rotY = 0;
        if (((CfccratePlacement*)aux)->param1C >= 0x3e8)
        {
            (obj)->anim.rootMotionScale = zeroF / ((f32)(s32)((CfccratePlacement*)aux)->param1C / 1000.0f);
        }
        else
        {
            (obj)->anim.rootMotionScale = zeroF;
        }
        state->oscVelB = (f32)(s32)((CfccratePlacement*)aux)->param1A;
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        if (mainGetBit(state->gameBit) != 0)
        {
            state->oscVelB *= -1.0f;
        }
        break;
    case 0xd7:
        (obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        (obj)->anim.rootMotionScale = zeroF;
        state->gameBit2Latch = 0;
        state->homeX = ((CfccratePlacement*)aux)->homeX;
        state->homeY = ((CfccratePlacement*)aux)->homeY;
        state->homeZ = ((CfccratePlacement*)aux)->homeZ;
        state->oscVelA = state->oscVelB = state->unk20 = state->unk28 = state->oscPosA = state->oscPosB = 0.0f;
        (obj)->animEventCallback = CFCrate_SeqFn;
        break;
    case 0x125:
        (obj)->anim.rotX = 0;
        (obj)->anim.rotY = 0;
        (obj)->anim.rotZ = 0;
        (obj)->anim.rootMotionScale = zeroF;
        (obj)->unkF4 = 0;
        (obj)->unkF8 = 0;
        state->oscVelB = lbl_803E3E40;
        state->oscVelA = 0.5f;
        state->unk32 = 0;
        state->unk34 = randomGetRange(0x3e8, 0x1388);
        state->proximityLatch = 1;
        (obj)->animEventCallback = CFCrate_SeqFn;
        break;
    case 0x10d:
        *(int*)&(obj)->anim.hitReactState = 0;
        if (((CfccratePlacement*)aux)->param1A == 0)
        {
            state->sfxTable = (u16*)&gCfCrateDefaultSfxTable;
            state->sfxCount = 1;
        }
        state->sfxPeriod = (u16)((CfccratePlacement*)aux)->param1C;
        state->sfxTimer = state->sfxPeriod;
        break;
    }
}

void CFCrate_release(void)
{
}

void CFCrate_initialise(void)
{
}

ObjectDescriptor gCFCrateObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)CFCrate_initialise, (ObjectDescriptorCallback)CFCrate_release, 0,
    (ObjectDescriptorCallback)CFCrate_init, (ObjectDescriptorCallback)CFCrate_update,
    (ObjectDescriptorCallback)CFCrate_hitDetect, (ObjectDescriptorCallback)CFCrate_render,
    (ObjectDescriptorCallback)CFCrate_free, (ObjectDescriptorCallback)CFCrate_getObjectTypeId,
    CFCrate_getExtraSize,
};
