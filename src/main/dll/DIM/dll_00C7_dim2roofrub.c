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
#include "main/object_render_legacy.h"

#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/camera_interface.h"
#include "main/objseq.h"
#include "main/obj_list.h"

#define DIM2ROOFRUB_OBJFLAG_RENDERED 0x800

typedef struct Dim2roofrubPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId;         /* 0x14: ObjPlacement-head map id (after posX/Y/Z) */
    s16 animDataIndex; /* 0x18 anim-data set selector (-1 = none); obj.unkF4 = animDataIndex+1 */
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

extern void** gTitleMenuControlInterfaceCopy;

#define objfx_spawnMaskedHitEffectLegacy(obj, scale, type, mode, mask, origin)                                    \
    ((void (*)(void*, f32, int, int, int, void*))objfx_spawnMaskedHitEffect)(                                    \
        (void*)(obj), (scale), (type), (mode), (mask), (origin))
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 gDim2RoofRubEffectScale = 0.64f;
__declspec(section ".sdata2") f32 lbl_803E3244 = -1.0f;
__declspec(section ".sdata2") f32 lbl_803E3248 = -0.8230000138282776f;
__declspec(section ".sdata2") f32 lbl_803E324C = -0.08399999886751175f;
__declspec(section ".sdata2") f32 lbl_803E3250 = -2.5999999046325684f;
__declspec(section ".sdata2") f32 lbl_803E3254 = 0.02500000037252903f;
__declspec(section ".sdata2") f32 lbl_803E3258 = 0.699999988079071f;
__declspec(section ".sdata2") f32 lbl_803E325C = 0.0f;
__declspec(section ".sdata2") f32 lbl_803E3260 = 0.20900000631809235f;
__declspec(section ".sdata2") f32 lbl_803E3264 = -3.5999999046325684f;
__declspec(section ".sdata2") f32 lbl_803E3268 = 0.5f;
__declspec(section ".sdata2") f32 lbl_803E326C = 0.8230000138282776f;
__declspec(section ".sdata2") f32 lbl_803E3270 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E3274 = 6.0f;
__declspec(section ".sdata2") f32 lbl_803E3278 = 2.5f;
__declspec(section ".sdata2") f32 gDim2RoofRubPi = 3.1415927410125732f;
#pragma explicit_zero_data off

int dim2roofrub_getExtraSize(void)
{
    return 0x140;
}
void dim2roofrub_free(int* obj)
{
    (*gObjectTriggerInterface)->freeState(((GameObject*)obj)->extra);
    ((void (*)(int*, int, int, int, int))((void**)*(void**)gTitleMenuControlInterfaceCopy)[2])(obj, 0xffff, 0, 0, 0);
    Sfx_StopObjectChannelPtrLegacy(obj, 0x7f);
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

void dim2roofrub_init(int* obj, int* params)
{
    int* state;
    int f4;
    objSetSlot((GameObject*)obj, 0x64);
    state = ((GameObject*)obj)->extra;
    ((Dim2roofrubState*)state)->unk6A = ((Dim2roofrubPlacement*)params)->unk1A;
    ((Dim2roofrubState*)state)->unk6E = -1;
    {
        f32 d = lbl_803E3270;
        ((Dim2roofrubState*)state)->dampingFactor = d / (d + (f32)(u32) * (u8*)((char*)params + 0x24));
    }
    ((Dim2roofrubState*)state)->unk28 = -1;
    ((Dim2roofrubState*)state)->unk98 = 0;
    ((Dim2roofrubState*)state)->unk94 = 0;
    ((Dim2roofrubState*)state)->unk116 = 0;
    ((Dim2roofrubState*)state)->unk114 = 0;
    ((GameObject*)obj)->unkF8 = 0;
    f4 = ((GameObject*)obj)->unkF4;
    if (f4 == 0 && ((Dim2roofrubPlacement*)params)->animDataIndex != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)params);
        ((GameObject*)obj)->unkF4 = ((Dim2roofrubPlacement*)params)->animDataIndex + 1;
    }
    else if (f4 != 0 && ((Dim2roofrubPlacement*)params)->animDataIndex != f4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)state);
        if (((Dim2roofrubPlacement*)params)->animDataIndex != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)params);
        }
        ((GameObject*)obj)->unkF4 = ((Dim2roofrubPlacement*)params)->animDataIndex + 1;
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

#define DIM2ROOFRUB_SEQID_SLIDE 0xa8
#define DIM2ROOFRUB_SEQID_TREAD 0x451

#define DIM2ROOFRUB_EVENT_TOGGLE_LIGHT 1
#define DIM2ROOFRUB_EVENT_TOGGLE_HEAVY 2
#define DIM2ROOFRUB_EVENT_TOGGLE_FX    3
#define DIM2ROOFRUB_EVENT_SPAWN_DUST   4
/* dust particle spawned 3x on the SPAWN_DUST anim event */
#define DIM2ROOFRUB_PARTFX 2046

void dim2roofrub_spawnEffects(int* obj)
{
    Dim2FxVec v;
    int flags;

    if ((((GameObject*)obj)->unkF8 & 4) != 0)
    {
        u8 i = 0;
        f32 scale = gDim2RoofRubEffectScale;
        Dim2FxRow* tbl = (Dim2FxRow*)lbl_80320768;
        for (; i < 10; i++)
        {
            f32 f = ((GameObject*)obj)->anim.rootMotionScale;
            Dim2FxRow* row = &tbl[i];
            v.x = scale * (f * row->x);
            v.y = scale * (f * row->y);
            v.z = scale * (f * row->z);
            objfx_spawnMaskedHitEffectLegacy(obj, f * row->w, 3, row->b1, row->b2, &v);
        }
    }
    v.fade = lbl_803E3244;
    flags = ((GameObject*)obj)->unkF8;
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
        v.x = gDim2RoofRubEffectScale * (lbl_803E3248 * ((GameObject*)obj)->anim.rootMotionScale);
        v.y = gDim2RoofRubEffectScale * (lbl_803E324C * ((GameObject*)obj)->anim.rootMotionScale);
        v.z = gDim2RoofRubEffectScale * (lbl_803E3250 * ((GameObject*)obj)->anim.rootMotionScale);
        objfx_spawnLightPulseLegacy((GameObject*)(obj), lbl_803E3254 * ((GameObject*)obj)->anim.rootMotionScale, 1, 0, count,
                              lbl_803E3258, &v);
        v.x = lbl_803E325C;
        v.y = gDim2RoofRubEffectScale * (lbl_803E3260 * ((GameObject*)obj)->anim.rootMotionScale);
        v.z = gDim2RoofRubEffectScale * (lbl_803E3264 * ((GameObject*)obj)->anim.rootMotionScale);
        objfx_spawnLightPulseLegacy((GameObject*)(obj), lbl_803E3254 * ((GameObject*)obj)->anim.rootMotionScale, 1, 0, count,
                              lbl_803E3268, &v);
        v.x = gDim2RoofRubEffectScale * (lbl_803E326C * ((GameObject*)obj)->anim.rootMotionScale);
        v.y = gDim2RoofRubEffectScale * (lbl_803E324C * ((GameObject*)obj)->anim.rootMotionScale);
        v.z = gDim2RoofRubEffectScale * (lbl_803E3250 * ((GameObject*)obj)->anim.rootMotionScale);
        objfx_spawnLightPulseLegacy((GameObject*)(obj), lbl_803E3254 * ((GameObject*)obj)->anim.rootMotionScale, 1, 0, count,
                              lbl_803E3258, &v);
    }
    if (((GameObject*)obj)->anim.seqId == DIM2ROOFRUB_SEQID_SLIDE)
    {
        objfx_spawnDirectionalBurstLegacy(obj, 7, lbl_803E3270, 5, 1, 10, lbl_803E3274, 0, 0x20000000);
    }
    else if (((GameObject*)obj)->anim.seqId == DIM2ROOFRUB_SEQID_TREAD)
    {
        int* model = (int*)Obj_GetActiveModel((GameObject*)obj);
        *(u8*)((char*)*(int**)((char*)model + 0x34) + 8) = 2;
        if ((((GameObject*)obj)->objectFlags & DIM2ROOFRUB_OBJFLAG_RENDERED) != 0)
        {
            objfx_spawnDirectionalBurstLegacy(obj, 5, lbl_803E3270, 2, 1, 20, lbl_803E3278, 0, 0);
        }
    }
}

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
        ((GameObject*)cam)->anim.rootMotionScale = lbl_803E3270;
        Obj_BuildWorldTransformMatrix((GameObject*)cam, mCam, 0);
        ((GameObject*)cam)->anim.rotY += 0x8000;
        ((GameObject*)cam)->anim.rootMotionScale = lbl_803E325C;
        PSMTXTrans(mTransNeg, -mCam[3], -mCam[7], -mCam[11]);
        PSMTXRotRad(mRotY, 'y', gDim2RoofRubPi);
        PSMTXRotRad(mRotZ, 'z', gDim2RoofRubPi);
        PSMTXTrans(mTransPos, mCam[3], mCam[7], mCam[11]);
        PSMTXConcat(mTransNeg, mCam, mA);
        PSMTXConcat(mRotY, mA, mB);
        PSMTXConcat(mRotZ, mB, mC);
        PSMTXConcat(mTransPos, mC, mD);
        PSMTXConcat(mD, mWorldCombined, mFinal);
        objSetMtxFn_800412d4((u32)mFinal);
        objRenderModelPtrLegacy(obj);
    }
    else
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E3270);
    }
}

typedef struct Dim2PartVec
{
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} Dim2PartVec;

#pragma opt_propagation off
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
                ((GameObject*)obj)->unkF8 ^= 1;
                break;
            case DIM2ROOFRUB_EVENT_TOGGLE_HEAVY:
                ((GameObject*)obj)->unkF8 ^= 2;
                break;
            case DIM2ROOFRUB_EVENT_TOGGLE_FX:
                ((GameObject*)obj)->unkF8 ^= 4;
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
#pragma opt_propagation reset

GenPropsWGPipe GXWGFifo : (0xCC008000);

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
