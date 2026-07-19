/*
 * dim2roofrub (DLL 0xC7) - DIM2 roof-rub object and shared DLL glue.
 * The dim2roofrub object is a GC-map interactive surface that triggers
 * animation sequences and particle effects when the player walks over it.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/shader_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/objfx.h"
#include "main/objprint_render_api.h"
#include "main/dll/DIM/dll_00C7_dim2roofrub_api.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/frame_timing.h"
#include "main/object_render.h"

#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/camera_interface.h"
#include "main/objseq.h"
#include "main/obj_list.h"
#include "main/dll/dll_0004_dummy04.h"

#define DIM2ROOFRUB_OBJFLAG_RENDERED 0x800

typedef struct Dim2roofrubPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId;         /* 0x14: ObjPlacement-head map id (after posX/Y/Z) */
    s16 animDataIndex; /* 0x18 anim-data set selector (-1 = none); obj.userData1 = animDataIndex+1 */
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} Dim2roofrubPlacement;

typedef struct Dim2roofrubState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 unk8;
    s8 unk9;
    u8 unkA;
    u8 unkB;
    u8 unkC;
    u8 padD[0x18 - 0xD];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 dampingFactor; /* 0x24: d/(d + placement[0x24]) smoothing coefficient */
    s32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x6A - 0x54];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 unk70;
    u8 pad71[0x94 - 0x71];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0x114 - 0xB2];
    s16 unk114;
    s16 unk116;
    u8 pad118[0x140 - 0x118];
} Dim2roofrubState;

typedef struct Dim2FxRow
{
    f32 x;
    f32 y;
    f32 z;
    f32 w;
    u8 b1;
    u8 b2;
    u8 pad[2];
} Dim2FxRow;
typedef struct Dim2FxVec
{
    u8 pad[8];
    f32 fade;
    f32 x;
    f32 y;
    f32 z;
} Dim2FxVec;
typedef struct Dim2PartVec
{
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} Dim2PartVec;

GenPropsWGPipe GXWGFifo : (0xCC008000);
#define DIM2ROOFRUB_SEQID_SLIDE 0xa8
#define DIM2ROOFRUB_SEQID_TREAD 0x451
#define DIM2ROOFRUB_EVENT_TOGGLE_LIGHT 1
#define DIM2ROOFRUB_EVENT_TOGGLE_HEAVY 2
#define DIM2ROOFRUB_EVENT_TOGGLE_FX    3
#define DIM2ROOFRUB_EVENT_SPAWN_DUST   4
#define DIM2ROOFRUB_PARTFX 2046
extern u32 lbl_80320768[];

void dim2roofrub_spawnEffects(int* obj)
{
    Dim2FxVec v;
    int flags;

    if ((((GameObject*)obj)->userData2 & 4) != 0)
    {
        u8 i = 0;
        f32 scale = (0.64f);
        Dim2FxRow* tbl = (Dim2FxRow*)lbl_80320768;
        for (; i < 10; i++)
        {
            f32 f = ((GameObject*)obj)->anim.rootMotionScale;
            Dim2FxRow* row = &tbl[i];
            v.x = scale * (f * row->x);
            v.y = scale * (f * row->y);
            v.z = scale * (f * row->z);
            objfx_spawnMaskedHitEffect(obj, f * row->w, 3, row->b1, row->b2, &v);
        }
    }
    v.fade = (-1.0f);
    flags = ((GameObject*)obj)->userData2;
    if ((flags & 1) != 0)
    {
        int count;
        if ((flags & 2) != 0)
        {
            count = 6;
        }
        else
        {
            count = 3;
        }
        v.x = (0.64f) * ((-0.8230000138282776f) * ((GameObject*)obj)->anim.rootMotionScale);
        v.y = (0.64f) * ((-0.08399999886751175f) * ((GameObject*)obj)->anim.rootMotionScale);
        v.z = (0.64f) * ((-2.5999999046325684f) * ((GameObject*)obj)->anim.rootMotionScale);
        objfx_spawnLightPulse((GameObject*)obj, (0.02500000037252903f) * ((GameObject*)obj)->anim.rootMotionScale,
                              1, 0, count, (0.699999988079071f), &v);
        v.x = (0.0f);
        v.y = (0.64f) * ((0.20900000631809235f) * ((GameObject*)obj)->anim.rootMotionScale);
        v.z = (0.64f) * ((-3.5999999046325684f) * ((GameObject*)obj)->anim.rootMotionScale);
        objfx_spawnLightPulse((GameObject*)obj, (0.02500000037252903f) * ((GameObject*)obj)->anim.rootMotionScale,
                              1, 0, count, (0.5f), &v);
        v.x = (0.64f) * ((0.8230000138282776f) * ((GameObject*)obj)->anim.rootMotionScale);
        v.y = (0.64f) * ((-0.08399999886751175f) * ((GameObject*)obj)->anim.rootMotionScale);
        v.z = (0.64f) * ((-2.5999999046325684f) * ((GameObject*)obj)->anim.rootMotionScale);
        objfx_spawnLightPulse((GameObject*)obj, (0.02500000037252903f) * ((GameObject*)obj)->anim.rootMotionScale,
                              1, 0, count, (0.699999988079071f), &v);
    }
    if (((GameObject*)obj)->anim.seqId == DIM2ROOFRUB_SEQID_SLIDE)
    {
        objfx_spawnDirectionalBurst(obj, 7, (1.0f), 5, 1, 10, (6.0f), NULL, 0x20000000);
    }
    else if (((GameObject*)obj)->anim.seqId == DIM2ROOFRUB_SEQID_TREAD)
    {
        int* model = (int*)Obj_GetActiveModel((GameObject*)obj);
        *(u8*)((char*)*(int**)((char*)model + 0x34) + 8) = 2;
        if ((((GameObject*)obj)->objectFlags & DIM2ROOFRUB_OBJFLAG_RENDERED) != 0)
        {
            objfx_spawnDirectionalBurst(obj, 5, (1.0f), 2, 1, 20, (2.5f), NULL, 0);
        }
    }
}

int dim2roofrub_getExtraSize(void)
{
    return 0x140;
}

u32 lbl_80320768[] = {
    0x00000000, 0x3FD5A1CB, 0xC0253F7D, 0x3C23D70A, 0x06100000, 0x402F3B64, 0x3F4B020C, 0xBFFA1CAC, 0x3C23D70A,
    0x09200000, 0x402EB852, 0x3F476C8B, 0xBF73B646, 0x3C23D70A, 0x07200000, 0x4032E148, 0xBF795810, 0xBFF8F5C3,
    0x3C23D70A, 0x09200000, 0x4033F7CF, 0xBF810625, 0xBF747AE1, 0x3C23D70A, 0x07200000, 0xC02F3B64, 0x3F4B020C,
    0xBFFC28F6, 0x3C23D70A, 0x09200000, 0xC02EB852, 0x3F476C8B, 0xBF73B646, 0x3C23D70A, 0x07200000, 0xC032E148,
    0xBF795810, 0xBFFC49BA, 0x3C23D70A, 0x09200000, 0xC033F7CF, 0xBF810625, 0xBF747AE1, 0x3C23D70A, 0x07200000,
    0x00000000, 0x3ECF5C29, 0x403CED91, 0x3C23D70A, 0x08400000,
};

ObjectDescriptor gDIM2RoofRubObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim2roofrub_init,
    (ObjectDescriptorCallback)dim2roofrub_update,
    0,
    (ObjectDescriptorCallback)dim2roofrub_render,
    (ObjectDescriptorCallback)dim2roofrub_free,
    0,
    dim2roofrub_getExtraSize,
};
void dim2roofrub_free(int* obj)
{
    (*gObjectTriggerInterface)->freeState(((GameObject*)obj)->extra);
    gTitleMenuControlInterfaceCopy->vtable->func05(obj, 0xffff, 0, 0, 0);
    Sfx_StopObjectChannel((int)obj, 0x7f);
}

#define DIM2ROOFRUB_SEQID_SLIDE 0xa8
#define DIM2ROOFRUB_SEQID_TREAD 0x451

#define DIM2ROOFRUB_EVENT_TOGGLE_LIGHT 1
#define DIM2ROOFRUB_EVENT_TOGGLE_HEAVY 2
#define DIM2ROOFRUB_EVENT_TOGGLE_FX    3
#define DIM2ROOFRUB_EVENT_SPAWN_DUST   4
/* dust particle spawned 3x on the SPAWN_DUST anim event */
#define DIM2ROOFRUB_PARTFX 2046

void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5)
{
    f32 mWorld[12];
    f32 mTransPlayer[12];
    f32 mWorldCombined[12];
    f32 mTransNeg[12];
    f32 mRotY[12];
    f32 mRotZ[12];
    f32 mTransPos[12];
    f32 mCam[12];
    f32 mA[12];
    f32 mB[12];
    f32 mC[12];
    f32 mD[12];
    f32 mFinal[12];

    dim2roofrub_spawnEffects(obj);
    if ((((ObjSeqState*)((GameObject*)obj)->extra)->stateFlags & 4) != 0)
    {
        int* prm;
        s16* cam;
        Obj_BuildWorldTransformMatrix((GameObject*)obj, mWorld, 0);
        prm = *(int**)&((GameObject*)obj)->anim.placementData;
        PSMTXTrans(mTransPlayer, -(((Dim2roofrubPlacement*)prm)->posX - playerMapOffsetX),
                   -((Dim2roofrubPlacement*)prm)->posY, -(((Dim2roofrubPlacement*)prm)->posZ - playerMapOffsetZ));
        PSMTXConcat(mTransPlayer, mWorld, mWorldCombined);
        cam = (s16*)(*gCameraInterface)->getCamera();
        ((GameObject*)cam)->anim.rotY += 0x8000;
        ((GameObject*)cam)->anim.rootMotionScale = (1.0f);
        Obj_BuildWorldTransformMatrix((GameObject*)cam, mCam, 0);
        ((GameObject*)cam)->anim.rotY += 0x8000;
        ((GameObject*)cam)->anim.rootMotionScale = (0.0f);
        PSMTXTrans(mTransNeg, -mCam[3], -mCam[7], -mCam[11]);
        PSMTXRotRad(mRotY, 'y', (3.1415927410125732f));
        PSMTXRotRad(mRotZ, 'z', (3.1415927410125732f));
        PSMTXTrans(mTransPos, mCam[3], mCam[7], mCam[11]);
        PSMTXConcat(mTransNeg, mCam, mA);
        PSMTXConcat(mRotY, mA, mB);
        PSMTXConcat(mRotZ, mB, mC);
        PSMTXConcat(mTransPos, mC, mD);
        PSMTXConcat(mD, mWorldCombined, mFinal);
        objSetMtxFn_800412d4((u32)mFinal);
        objRenderModel((GameObject*)obj);
    }
    else
    {
        objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
    }
}

void dim2roofrub_update(int* obj)
{
    ObjSeqState* seq = ((GameObject*)obj)->extra;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if (params != NULL && ((Dim2roofrubPlacement*)params)->animDataIndex != -1)
    {
        Dim2PartVec v;
        int count;
        int res;
        for (res = 0; res < seq->eventCount; res++)
        {
            int b = seq->eventIds[res];
            switch (b)
            {
            case DIM2ROOFRUB_EVENT_TOGGLE_LIGHT:
                ((GameObject*)obj)->userData2 ^= 1;
                break;
            case DIM2ROOFRUB_EVENT_TOGGLE_HEAVY:
                ((GameObject*)obj)->userData2 ^= 2;
                break;
            case DIM2ROOFRUB_EVENT_TOGGLE_FX:
                ((GameObject*)obj)->userData2 ^= 4;
                break;
            case DIM2ROOFRUB_EVENT_SPAWN_DUST:
            {
                int k;
                v.x = ((GameObject*)obj)->anim.localPosX;
                v.y = ((GameObject*)obj)->anim.localPosY;
                v.z = ((GameObject*)obj)->anim.localPosZ;
                for (k = 3; k != 0; k--)
                {
                    (*gPartfxInterface)->spawnObject(obj, DIM2ROOFRUB_PARTFX, &v, 0x200001, -1, NULL);
                }
                break;
            }
            }
        }
        res = (*gObjectTriggerInterface)->update((u8*)obj, timeDelta);
        if (res != 0 && ((GameObject*)obj)->seqIndex == -2)
        {
            int slot8 = *(s8*)&seq->slot;
            int* list;
            int slot;
            int cnt;
            int* match = NULL;
            list = ObjList_GetObjects(&res, &count);
            res = cnt = 0;
            slot = slot8;
            for (; res < count; res++)
            {
                int* other = (int*)*list;
                if (((GameObject*)other)->seqIndex == slot8)
                {
                    match = (int*)*list;
                }
                if (((GameObject*)other)->seqIndex == -2 && ((GameObject*)other)->anim.classId == 0x10)
                {
                    ObjSeqState* otherSeq = *(ObjSeqState**)&((GameObject*)other)->extra;
                    if (slot == (s8)otherSeq->slot)
                    {
                        cnt++;
                    }
                }
                list++;
            }
            if (cnt <= 1 && match != NULL && ((GameObject*)match)->seqIndex != -1)
            {
                ((GameObject*)match)->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(slot);
            }
            ((GameObject*)obj)->seqIndex = -1;
        }
    }
}

void dim2roofrub_init(int* obj, int* params)
{
    int* state;
    int f4;
    objSetSlot((GameObject*)obj, 0x64);
    state = ((GameObject*)obj)->extra;
    ((Dim2roofrubState*)state)->unk6A = ((Dim2roofrubPlacement*)params)->unk1A;
    ((Dim2roofrubState*)state)->unk6E = -1;
    {
        f32 d = (1.0f);
        ((Dim2roofrubState*)state)->dampingFactor = d / (d + (f32)(u32) * (u8*)((char*)params + 0x24));
    }
    ((Dim2roofrubState*)state)->unk28 = -1;
    ((Dim2roofrubState*)state)->unk98 = 0;
    ((Dim2roofrubState*)state)->unk94 = 0;
    ((Dim2roofrubState*)state)->unk116 = 0;
    ((Dim2roofrubState*)state)->unk114 = 0;
    ((GameObject*)obj)->userData2 = 0;
    f4 = ((GameObject*)obj)->userData1;
    if (f4 == 0 && ((Dim2roofrubPlacement*)params)->animDataIndex != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)params);
        ((GameObject*)obj)->userData1 = ((Dim2roofrubPlacement*)params)->animDataIndex + 1;
    }
    else if (f4 != 0 && ((Dim2roofrubPlacement*)params)->animDataIndex != f4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)state);
        if (((Dim2roofrubPlacement*)params)->animDataIndex != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)params);
        }
        ((GameObject*)obj)->userData1 = ((Dim2roofrubPlacement*)params)->animDataIndex + 1;
    }
    {
        ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
        if (modelState != NULL)
        {
            modelState->shadowTintA = 0x64;
            ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
        }
    }
}

static inline void swipePos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void swipeColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}

static inline void swipeTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}
