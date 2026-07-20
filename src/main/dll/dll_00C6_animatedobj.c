/* DLL 0xC6 - animated object [8016984C-801713AC) */
#include "main/object_render.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/shader_api.h"
#include "main/objprint_render_api.h"
#include "main/dll/dll_00C6_animatedobj_api.h"
#include "main/frame_timing.h"
#include "main/dll/genpropswgpipe_struct.h"

#include "main/game_object.h"
#include "main/obj_list.h"
#include "main/obj_link.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/camera_interface.h"
#include "main/maketex_sequence_api.h"
#include "main/objseq.h"
#include "main/objhits.h"
#include "main/dll/dll_0004_dummy04.h"

/* object group this object joins while active */
#define ANIMATEDOBJ_OBJGROUP 7

#define ANIMATEDOBJ_OBJFLAG_UPDATE_DISABLED 0x8000
/* DLL-id spawned+child-attached on seq event 0xa (generic child; no cache
   field / named spawn-fn / kind name -> suffixless per role-gate). */
#define ANIMATEDOBJ_CHILD_OBJ 0x69
#define ANIMATEDOBJ_KRYSTAL_OBJ 0x774

typedef struct AnimatedobjPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId; /* 0x14: ObjPlacement map id */
    s16 loadKey;
    s16 gameBit; /* 0x1A: copied into ObjSeqState.gameBit at init */
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} AnimatedobjPlacement;





int animatedobj_getExtraSize(void) { return 0x140; }

ObjectDescriptor gAnimatedObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)animatedobj_init,
    (ObjectDescriptorCallback)animatedobj_update,
    0,
    (ObjectDescriptorCallback)animatedobj_render,
    (ObjectDescriptorCallback)animatedobj_free,
    0,
    animatedobj_getExtraSize,
};

void animatedobj_free(int* obj, int seqFlag)
{
    (*gObjectTriggerInterface)
        ->freeState(((GameObject*)obj)->extra);
    gTitleMenuControlInterfaceCopy->vtable->func05(obj, 0xffff, 0, 0, 0);
    Sfx_RemoveLoopedObjectSoundForObject((u32)obj);
    Sfx_StopObjectChannel((int)obj, 0x7f);
    if (((GameObject*)obj)->anim.seqId == ANIMATEDOBJ_KRYSTAL_OBJ && ((GameObject*)obj)->childCount != 0)
    {
        Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
        ObjLink_DetachChild((GameObject*)obj, (GameObject*)((GameObject*)obj)->childObjs[0]);
    }
    if (seqFlag != 0)
    {
        clearCurSeqNo();
    }
}

void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
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

    ObjSeqState* seq = ((GameObject*)obj)->extra;
    if ((seq->stateFlags & 4) != 0)
    {
        int* prm;
        s16* cam;
        Obj_BuildWorldTransformMatrix((GameObject*)obj, mWorld, 0);
        prm = *(int**)&((GameObject*)obj)->anim.placementData;
        PSMTXTrans(mTransPlayer, -(((AnimatedobjPlacement*)prm)->posX - playerMapOffsetX),
                   -((AnimatedobjPlacement*)prm)->posY,
                   -(((AnimatedobjPlacement*)prm)->posZ - playerMapOffsetZ));
        PSMTXConcat(mTransPlayer, mWorld, mWorldCombined);
        cam = (s16*)(*gCameraInterface)->getCamera();
        ((GameObject*)cam)->anim.rotY += 0x8000;
        ((GameObject*)cam)->anim.rootMotionScale = 1.0f;
        Obj_BuildWorldTransformMatrix((GameObject*)cam, mCam, 0);
        ((GameObject*)cam)->anim.rotY += 0x8000;
        ((GameObject*)cam)->anim.rootMotionScale = 0.0f;
        PSMTXTrans(mTransNeg, -mCam[3], -mCam[7], -mCam[11]);
        PSMTXRotRad(mRotY, 'y', 3.1415927f);
        PSMTXRotRad(mRotZ, 'z', 3.1415927f);
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


void animatedobj_update(int* obj)
{
    ObjSeqState* seq = ((GameObject*)obj)->extra;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if (params != NULL && ((AnimatedobjPlacement*)params)->loadKey != -1)
    {
        int res;
        int count;
        res = (*gObjectTriggerInterface)->update((u8*)obj, timeDelta);
        if (res != 0 && ((GameObject*)obj)->seqIndex == -2)
        {
            int slot8 = *(s8*)((char*)seq + 0x57);
            int* match = NULL;
            int* list;
            int slot;
            int cnt;
            list = ObjList_GetObjects(&res, &count);
            cnt = 0;
            res = 0;
            slot = slot8;
            slot |= slot8;
            for (; res < count; res++)
            {
                int* other = (int*)*list;
                if (((GameObject*)other)->seqIndex == slot8)
                {
                    match = other;
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
            ((GameObject*)obj)->objectFlags |= ANIMATEDOBJ_OBJFLAG_UPDATE_DISABLED;
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x774:
        {
            int i;
            for (i = 0; i < seq->eventCount; i++)
            {
                int b = seq->eventIds[i];
                switch (b)
                {
                case 0xa:
                    if ((u8)Obj_IsLoadingLocked() != 0)
                    {
                        void* alloc;
                        int* child;
                        alloc = (void*)Obj_AllocObjectSetup(0x18, ANIMATEDOBJ_CHILD_OBJ);
                        child = (int*)Obj_SetupObject((ObjPlacement*)alloc, 4, -1, -1, 0);
                        ObjLink_AttachChild((GameObject*)obj, (GameObject*)child, 0);
                        ObjAnim_SetCurrentMove((int)child, 0, 0.0f, 0);
                        ObjAnim_AdvanceCurrentMove(
                            (int)child, 1.0f, timeDelta, NULL);
                    }
                    break;
                case 0xb:
                    if (((GameObject*)obj)->childCount != 0)
                    {
                        Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
                        ObjLink_DetachChild((GameObject*)obj, (GameObject*)((GameObject*)obj)->childObjs[0]);
                    }
                    break;
                }
            }
            break;
        }
        }
    }
}


void animatedobj_init(int* obj, int* params)
{
    ObjSeqState* seq;
    int f4;
    objSetSlot((GameObject*)obj, 0x64);
    seq = ((GameObject*)obj)->extra;
    seq->gameBit = ((AnimatedobjPlacement*)params)->gameBit;
    seq->flags = -1;
    {
        f32 d = 1.0f;
        seq->posOffsetDecay = d / (d + (f32)(u32) * (u8*)((char*)params + 0x24));
    }
    seq->curveId = -1;
    seq->animEntries = NULL;
    seq->cmds = NULL;
    seq->baseRotX = 0;
    seq->baseRotY = 0;
    seq->freeCallback = NULL;
    f4 = ((GameObject*)obj)->userData1;
    if (f4 == 0 && ((AnimatedobjPlacement*)params)->loadKey != 1)
    {
        (*gObjectTriggerInterface)
            ->loadAnimData((u8*)seq, (u8*)params);
        ((GameObject*)obj)->userData1 = ((AnimatedobjPlacement*)params)->loadKey + 1;
    }
    else if (f4 != 0 && ((AnimatedobjPlacement*)params)->loadKey != f4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)seq);
        if (((AnimatedobjPlacement*)params)->loadKey != -1)
        {
            (*gObjectTriggerInterface)
                ->loadAnimData((u8*)seq, (u8*)params);
        }
        ((GameObject*)obj)->userData1 = ((AnimatedobjPlacement*)params)->loadKey + 1;
    }
    {
        ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
        if (modelState != NULL)
        {
            modelState->shadowTintA = 0x64;
            ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
        }
    }
    Obj_SetModelRenderOpAlpha(obj, 0xff);
}



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
