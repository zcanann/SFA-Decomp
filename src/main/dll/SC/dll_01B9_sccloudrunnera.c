/* DLL 0x01B9 (sccloudrunnera) — SC CloudRunner A level control [0x801DCC70-0x801DD170). */
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_02B1_cmbsrc.h"

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objSetSlot(int obj, int slot);
extern int* gTitleMenuControlInterfaceCopy;
extern u8 lbl_803DB411;    /* trigger-interface update parameter */
extern f32 lbl_803E55E0;   /* render fade alpha / posOffsetDecay base */

/* Child object spawned in sc_cloudrunnera_update case 0, cached in childObjs[0]
 * and attached via ObjLink_AttachChild. */
#define SCCLOUDRUNNERA_CHILD_OBJ 0x6e8

typedef struct ScCloudrunneraPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 animDataIndex; /* anim-data set selector (-1 = none); obj.unkF4 = animDataIndex+1 */
    s16 gameBit; /* GameBit id -> seq->gameBit */
    u8 pad1C[0x24 - 0x1C];
    u8 posOffsetDecayFactor; /* 0x24: decay input; posOffsetDecay = base/(base + this) */
    u8 pad25[0x28 - 0x25];
} ScCloudrunneraPlacement;

/* Obj_AllocObjectSetup buffer filled in sc_cloudrunnera_update (case 0).
 * File-local layout recovered from constant-offset stores. */
typedef struct ScCloudrunneraSetup
{
    u8 pad00[0x04];   /* 0x00 */
    u8 unk04;         /* 0x04 */
    u8 unk05;         /* 0x05 */
    u8 unk06;         /* 0x06 */
    u8 unk07;         /* 0x07 */
    u8 pad08[0x1B - 0x08];
    u8 unk1B;         /* 0x1B */
    u8 unk1C;         /* 0x1C */
    u8 unk1D;         /* 0x1D */
    u8 pad1E[0x20 - 0x1E];
    f32 unk20;        /* 0x20 */
    s16 unk24;        /* 0x24 */
    u8 unk26;         /* 0x26 */
    u8 unk27;         /* 0x27 */
    u8 unk28;         /* 0x28 */
    u8 unk29;         /* 0x29 */
    u8 unk2A;         /* 0x2A */
} ScCloudrunneraSetup;

int sc_cloudrunnera_getExtraSize(void) { return 0x140; }
int sc_cloudrunnera_getObjectTypeId(void) { return 0xb; }

void sc_cloudrunnera_free(int* obj)
{
    void* inner = ((GameObject*)obj)->extra;
    (*gObjectTriggerInterface)->freeState(inner);
    ((void (*)(int*, int, int, int, int))(*(int*)(*gTitleMenuControlInterfaceCopy + 0x8)))(obj, 0xffff, 0, 0, 0);
}

void sc_cloudrunnera_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes((GameObject*)p1, lbl_803E55E0);
}

void sc_cloudrunnera_hitDetect(void)
{
}

void sc_cloudrunnera_update(int obj)
{
    int i;
    ObjSeqState* seq = ((GameObject*)obj)->extra;
    void* sub;
    int idx, count;

    sub = ((GameObject*)obj)->anim.placementData;
    if (sub == NULL) return;
    if (((ScCloudrunneraPlacement*)sub)->animDataIndex == -1) return;
    idx = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)lbl_803DB411);
    if (idx != 0 && ((GameObject*)obj)->seqIndex == -2)
    {
        int found;
        register s32 mark = *(s8*)&seq->slot;
        int* arr;
        int n;
        int markCopy;
        int matchCount;

        found = 0;
        arr = ObjList_GetObjects(&idx, &count);
        matchCount = 0;
        idx = 0;
        markCopy = mark;
        n = count;
        for (; idx < n; idx++)
        {
            int o = *arr;
            s16 t = ((GameObject*)o)->seqIndex;
            if (t == mark)
            {
                found = o;
            }
            if (t == -2 && ((GameObject*)o)->anim.classId == 0x10)
            {
                seq = *(ObjSeqState**)&((GameObject*)o)->extra;
                if (markCopy == (s8)seq->slot)
                {
                    matchCount++;
                }
            }
            arr++;
        }
        if (matchCount <= 1 && (u32)found != 0 && ((GameObject*)found)->seqIndex != -1)
        {
            ((GameObject*)found)->seqIndex = -1;
            (*gObjectTriggerInterface)->endSequence(markCopy);
        }
        ((GameObject*)obj)->seqIndex = -1;
    }

    for (i = 0; i < seq->eventCount; i++)
    {
        switch (seq->eventIds[i])
        {
        case 0:
            {
                ScCloudrunneraSetup* setup;
                GameObject* newObj;
                if (*(void**)&((GameObject*)obj)->childObjs[0] != NULL)
                {
                    break;
                }
                if (Obj_IsLoadingLocked() == 0)
                {
                    break;
                }
                setup = (ScCloudrunneraSetup*)Obj_AllocObjectSetup(0x30, SCCLOUDRUNNERA_CHILD_OBJ);
                setup->unk1B = 0x9;
                setup->unk1C = 0;
                setup->unk1D = 0;
                setup->unk20 = lbl_803E55E0;
                setup->unk26 = 0xff;
                setup->unk27 = 0xff;
                setup->unk28 = 0xff;
                setup->unk24 = -1;
                setup->unk04 = 2;
                setup->unk05 = 1;
                setup->unk06 = 0xff;
                setup->unk07 = 0xff;
                setup->unk29 = 1;
                setup->unk2A = 0;
                newObj = Obj_SetupObject((ObjPlacement*)setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                         ((GameObject*)obj)->anim.parent);
                newObj->anim.flags = (s16)(newObj->anim.flags | OBJANIM_FLAG_HIDDEN);
                ObjLink_AttachChild(obj, (int)newObj, 0);
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c);
                break;
            }
        case 1:
            {
                if (*(void**)&((GameObject*)obj)->childObjs[0] != NULL)
                {
                    cmbsrc_setExternalActive(*(int*)&((GameObject*)obj)->childObjs[0], 0);
                }
                break;
            }
        case 2:
            {
                int innerSlot = *(int*)&((GameObject*)obj)->childObjs[0];
                if ((u32)innerSlot != 0)
                {
                    ObjLink_DetachChild((GameObject*)obj, innerSlot);
                    Obj_FreeObject((GameObject*)innerSlot);
                }
                break;
            }
        }
    }
    {
        int t = *(int*)&((GameObject*)obj)->childObjs[0];
        if ((u32)t != 0)
        {
            ((GameObject*)t)->anim.rotZ = ((GameObject*)obj)->anim.rotZ;
            ((GameObject*)*(int*)&((GameObject*)obj)->childObjs[0])->anim.rotY = (s16)(((GameObject*)obj)->anim.rotY + 0xe38);
            ((GameObject*)*(int*)&((GameObject*)obj)->childObjs[0])->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + -0x8000);
        }
    }
}

void sc_cloudrunnera_init(GameObject *obj, int def)
{
    ObjSeqState* seq;
    f32 base;
    s32 objF4;

    objSetSlot((int)obj, 0x64);
    seq = (obj)->extra;
    seq->gameBit = ((ScCloudrunneraPlacement*)def)->gameBit;
    seq->flags = -1;
    base = lbl_803E55E0;
    seq->posOffsetDecay = base / (base + (f32)(u32)((ScCloudrunneraPlacement*)def)->posOffsetDecayFactor);
    seq->curveId = -1;
    (obj)->unkF8 = 0;

    objF4 = (obj)->unkF4;
    if (objF4 == 0 && ((ScCloudrunneraPlacement*)def)->animDataIndex != 1)
    {
        (*gObjectTriggerInterface)
            ->loadAnimData((u8*)seq, (u8*)def);
        (obj)->unkF4 = ((ScCloudrunneraPlacement*)def)->animDataIndex + 1;
    }
    else if (objF4 != 0 && ((ScCloudrunneraPlacement*)def)->animDataIndex != objF4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)seq);
        if (((ScCloudrunneraPlacement*)def)->animDataIndex != -1)
        {
            (*gObjectTriggerInterface)
                ->loadAnimData((u8*)seq, (u8*)def);
        }
        (obj)->unkF4 = ((ScCloudrunneraPlacement*)def)->animDataIndex + 1;
    }
    if ((obj)->anim.modelState != NULL)
    {
        (obj)->anim.modelState->shadowTintA = 0x64;
        (obj)->anim.modelState->shadowTintB = 0x96;
    }
}

void sc_cloudrunnera_release(void)
{
}

void sc_cloudrunnera_initialise(void)
{
}
