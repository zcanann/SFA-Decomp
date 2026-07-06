/*
 * cfccrate (DLL 0x12A) - the shared "crate" prop handler: one DLL
 * driving dozens of simple placement types across maps (cogs, warding
 * stones, rising water, spinning rings, lock symbols, galleon masts,
 * ice floes, ...). init seeds per-type state from the placement record,
 * update dispatches per-type motion/SFX on the romlist type id, and the
 * SeqFn handles the few types with anim-event work.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/CF/dll_012B_fxemit.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct CfccratePlacement
{
    s16 id;
    u8 pad2[0x8 - 0x2];
    f32 homeX;
    f32 homeY;
    f32 homeZ;
    u8 pad14[0x18 - 0x14];
    s8 rotX;     /* 0x18: spawn pitch byte, <<8 into anim.rotX */
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

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E3DD8;
extern void Obj_FreeObject(int obj);
extern void getLActions(int p1, int p2, int p3, int p4, int p5, int p6);
extern float sqrtf(float x);
extern f64 lbl_803E3DE0;
extern const f32 lbl_803E3DE8;
extern f32 lbl_803E3DEC;
extern f32 lbl_803E3DF0;
extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DF8;
extern f32 lbl_803E3DFC;
extern f32 lbl_803E3E00;
extern f32 lbl_803E3E04;
extern f32 lbl_803E3E08;
extern f32 lbl_803E3E0C;
extern f32 lbl_803E3E10;
extern f32 lbl_803E3E14;
extern f64 lbl_803E3E18;
extern f32 lbl_803E3E20;
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void* gCfCrateDefaultSfxTable;
extern f32 lbl_803E3E30;
extern f32 lbl_803E3E34;
extern f32 lbl_803E3E38;
extern f32 lbl_803E3E3C;
extern f32 lbl_803E3E40;
extern f32 sqrtf(f32);

#define PARTFX_SPAWN(obj, fxId, a, b, c, d) \
  (*gPartfxInterface)->spawnObject((void *)(obj), (fxId), (void *)(a), (b), (c), (void *)(d))

int cfccrate_getExtraSize(void) { return 0x4c; }
int cfccrate_getObjectTypeId(void) { return 0x1; }

void cfccrate_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void cfccrate_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{

    int objectType;
    CfCcrateState* state;

    state = ((GameObject*)obj)->extra;
    if ((s32)visible == 0 || (objectType = ((GameObject*)obj)->anim.seqId) == 0x1b8)
    {
        return;
    }
    if (visible == 0 || objectType == 0x6bf)
    {
        if (GameBit_Get(state->gameBit2) == 0)
        {
            return;
        }
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E3DD8);
}

int CFCrate_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    CfCcrateState* state;
    int i;

    state = ((GameObject*)obj)->extra;
    switch (((GameObject*)obj)->anim.seqId)
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
        if (GameBit_Get(state->gameBit2) != 0)
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

void cfccrate_hitDetect(void)
{
}

void cfccrate_update(int obj)
{


    CfCcrateState* state;
    int viewslot;
    int cam;
    int tmp;
    short id;

    Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    cam = (int)Camera_GetCurrentViewSlot();
    id = ((GameObject*)obj)->anim.seqId;
    viewslot = *(int*)&((GameObject*)obj)->anim.placementData;

    switch (id)
    {
    case 0x7de: /* LinkF_cog */
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.rotZ = (short)-(timeDelta * state->oscVelB - (f32)((GameObject*)obj)->anim.rotZ);
        }
        else
        {
            ((GameObject*)obj)->anim.rotZ = (short)(timeDelta * state->oscVelB + (f32)((GameObject*)obj)->anim.rotZ);
        }
        break;
    case 0x729: /* VFP_Warding... */
        if (GameBit_Get(state->gameBit) == 0)
        {
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 100;
        }
        break;
    case 0x71b: /* DFP_WaterHi... */
        state->lingerTimer -= framesThisStep;
        ObjHits_SetHitVolumeSlot(obj, 0x13, 1, 0);
        if (state->lingerTimer <= 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY = (f32)-(lbl_803E3DE0 * timeDelta - ((GameObject*)obj)->anim.localPosY);
        }
        break;
    case 0x6fc: /* DFP_Water */
        if ((GameBit_Get(state->gameBit) != 0) &&
            (((GameObject*)obj)->anim.localPosY <= lbl_803E3DE8 + ((CfccratePlacement*)viewslot)->homeY))
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E3DEC * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY >= lbl_803E3DE8 + ((CfccratePlacement*)viewslot)->homeY)
            {
                GameBit_Set(state->gameBit, 0);
            }
        }
        break;
    case 0x6fd: /* DFP_InnerRing */
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        else
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        break;
    case 0x6fe: /* DFP_OuterRing */
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        else
        {
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        break;
    case 0x622: /* VFP_locksym */
        {
            ObjTextureRuntimeSlot* p = objFindTexture((void*)obj, 0, 0);
            if ((p != NULL) && (GameBit_Get(state->gameBit) != 0) && (p->textureId == 0))
            {
                Sfx_PlayFromObject(obj, SFXTRIG_en_littletink22_3c4);
                p->textureId = 0x100;
            }
            break;
        }
    case 0x65c:
        break;
    case 0x65d:
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E3DF8, timeDelta, NULL);
        break;
    case 0x6b4: /* MMP_Organic... */
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E3DF8, timeDelta, NULL);
        break;
    case 0x708: /* VFP_newball... */
        if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) != 0)
        {
            GameBit_Set(state->gameBit, 1);
        }
        if (GameBit_Get(state->gameBit) == 0)
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX +
                ((s8*)viewslot)[0x18] * framesThisStep;
        }
        break;
    case 0x409:
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        break;
    case 0x6be: /* VFP_liftgra... */
        if ((GameBit_Get(state->gameBit2) != 0) && (state->gameBit2Latch == 0))
        {
            state->gameBit2Latch = 1;
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        break;
    case 0x4bf:
        if ((((GameObject*)obj)->anim.localPosY < lbl_803E3DFC + ((CfccratePlacement*)viewslot)->homeY) &&
            (GameBit_Get(state->gameBit) != 0))
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + timeDelta;
        }
        break;
    case 0x828:
        if ((GameBit_Get(state->gameBit2) != 0) && (state->gameBit2Latch == 0))
        {
            if (((GameObject*)obj)->anim.rotZ + (tmp = (s32)(lbl_803E3E00 * timeDelta)) > 0x7fff)
            {
                state->gameBit2Latch = 1;
                ((GameObject*)obj)->anim.rotZ = 0x7fff;
            }
            else
            {
                ((GameObject*)obj)->anim.rotZ = (short)(((GameObject*)obj)->anim.rotZ + tmp);
            }
        }
        break;
    case 0x8e:
        state->oscPosA = lbl_803E3E04 * state->oscVelA + state->oscPosA;
        if ((state->oscPosA > lbl_803E3E08) ||
            (state->oscPosA < lbl_803E3E0C))
        {
            state->oscVelA = -state->oscVelA;
        }
        if ((state->oscPosB > lbl_803E3E10) ||
            (state->oscPosB < lbl_803E3E14))
        {
            state->oscVelB = -state->oscVelB;
        }
        state->oscPosB = lbl_803E3E04 * state->oscVelB + state->oscPosB;
        break;
    case 0x10d:
        state->sfxTimer -= framesThisStep;
        if (state->sfxTimer < 0)
        {
            u32 r;
            int tbl;
            r = randomGetRange(0, state->sfxCount - 1) << 1;
            tbl = *(int volatile*)&state->sfxTable;
            Sfx_PlayFromObject(obj, *(u16*)(tbl + r));
            state->sfxTimer = state->sfxPeriod;
            r = randomGetRange(0, state->sfxPeriod);
            state->sfxTimer = state->sfxTimer + r;
        }
        break;
    case 0x125:
        {
            f32 fx, fy, fz;
            f32 dist;
            int p;

            ((GameObject*)obj)->anim.rotZ = (s16)(lbl_803E3E18 * (double)-(s32)*(s16*)(cam + 4));
            p = (int)Obj_GetPlayerObject();
            fx = ((GameObject*)p)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            fz = ((GameObject*)p)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
            fy = ((GameObject*)p)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
            dist = sqrtf(fy * fy + (fx * fx + fz * fz));
            if (dist < lbl_803E3E20 && state->proximityLatch == 1)
            {
                state->proximityLatch = 0;
                getLActions(obj, obj, 0x5c, 0, 0, 0);
            }
            else if ((dist > *(f32*)&lbl_803E3E20) && (state->proximityLatch == 0))
            {
                state->proximityLatch = 1;
                getLActions(obj, obj, 0x5d, 0, 0, 0);
            }
            break;
        }
    }
}

void cfccrate_init(int obj, int aux)
{

    ObjAnimComponent* objAnim;
    CfCcrateState* state;
    short id;
    f32 zeroF;

    objAnim = (ObjAnimComponent*)obj;
    id = ((CfccratePlacement*)aux)->id;
    state = ((GameObject*)obj)->extra;
    zeroF = lbl_803E3DD8;
    state->unk2C = zeroF;

    switch (id)
    {
    case 0x2bb:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        ((GameObject*)obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
        ((GameObject*)obj)->anim.rotZ = ((CfccratePlacement*)aux)->param1C;
        ((GameObject*)obj)->anim.rootMotionScale = zeroF;
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
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        break;
    case 0x726:
        ((GameObject*)obj)->animEventCallback = CFCrate_SeqFn;
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        break;
    case 0x71b:
        state->lingerTimer = ((CfccratePlacement*)aux)->param1A;
        break;
    case 0x6be:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit2Latch = 0;
        state->gameBit2 = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x828:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit2Latch = 0;
        state->gameBit2 = ((CfccratePlacement*)aux)->gameBit;
        if ((GameBit_Get(state->gameBit2) != 0) && (state->gameBit2Latch == 0))
        {
            ((GameObject*)obj)->anim.rotZ = 0x7fff;
            state->gameBit2Latch = 1;
        }
        break;
    case 0x6bf:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        ((GameObject*)obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
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
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x6b4:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        ((GameObject*)obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E3E30, 0);
        break;
    case 0x66c:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        break;
    case 0x216:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        ((GameObject*)obj)->anim.rotY = ((CfccratePlacement*)aux)->param1A;
        break;
    case 0x4bf:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        *(u8*)&objAnim->bankIndex = ((CfccratePlacement*)aux)->bankIndex;
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E3DFC + ((CfccratePlacement*)aux)->homeY;
        }
        break;
    case 0x8e:
        ((GameObject*)obj)->anim.rotX = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        if (((CfccratePlacement*)aux)->param1C >= 0x3e8)
        {
            ((GameObject*)obj)->anim.rootMotionScale = zeroF / ((f32)(s32)((CfccratePlacement*)aux)->param1C / lbl_803E3DF4);
        }
        else
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3E34;
        }
        state->gameBit2Latch = 0;
        state->homeX = ((CfccratePlacement*)aux)->homeX;
        state->homeY = ((CfccratePlacement*)aux)->homeY;
        state->homeZ = ((CfccratePlacement*)aux)->homeZ;
        state->oscPosA = state->oscPosB = lbl_803E3E30;
        state->unk28 = lbl_803E3DF4;
        state->unk20 = lbl_803E3E38;
        state->oscVelA = state->oscVelB = lbl_803E3DEC;
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->animEventCallback = CFCrate_SeqFn;
        break;
    case 0x7de:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        ((GameObject*)obj)->anim.rotY = 0;
        if (((CfccratePlacement*)aux)->param1C >= 0x3e8)
        {
            ((GameObject*)obj)->anim.rootMotionScale = zeroF / ((f32)(s32)((CfccratePlacement*)aux)->param1C / lbl_803E3DF4);
        }
        else
        {
            ((GameObject*)obj)->anim.rootMotionScale = zeroF;
        }
        state->oscVelB = (f32)(s32)((CfccratePlacement*)aux)->param1A;
        state->gameBit = ((CfccratePlacement*)aux)->gameBit;
        if (GameBit_Get(state->gameBit) != 0)
        {
            state->oscVelB = state->oscVelB * lbl_803E3E3C;
        }
        break;
    case 0xd7:
        ((GameObject*)obj)->anim.rotX = (short)(((CfccratePlacement*)aux)->rotX << 8);
        ((GameObject*)obj)->anim.rootMotionScale = zeroF;
        state->gameBit2Latch = 0;
        state->homeX = ((CfccratePlacement*)aux)->homeX;
        state->homeY = ((CfccratePlacement*)aux)->homeY;
        state->homeZ = ((CfccratePlacement*)aux)->homeZ;
        state->oscVelA = state->oscVelB = state->unk20 = state->unk28 = state->oscPosA = state->oscPosB = lbl_803E3E30;
        ((GameObject*)obj)->animEventCallback = CFCrate_SeqFn;
        break;
    case 0x125:
        ((GameObject*)obj)->anim.rotX = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->anim.rootMotionScale = zeroF;
        ((GameObject*)obj)->unkF4 = 0;
        ((GameObject*)obj)->unkF8 = 0;
        state->oscVelB = lbl_803E3E40;
        state->oscVelA = lbl_803E3DEC;
        state->unk32 = 0;
        state->unk34 = randomGetRange(0x3e8, 0x1388);
        state->proximityLatch = 1;
        ((GameObject*)obj)->animEventCallback = CFCrate_SeqFn;
        break;
    case 0x10d:
        *(int*)&((GameObject*)obj)->anim.hitReactState = 0;
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

void cfccrate_release(void)
{
}

void cfccrate_initialise(void)
{
}
