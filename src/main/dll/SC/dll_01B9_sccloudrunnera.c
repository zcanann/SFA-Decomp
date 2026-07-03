/* DLL 0x01B9 (sccloudrunnera) — SC CloudRunner A level control [0x801DCC70-0x801DD170). */
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/audio/sfx_trigger_ids.h"

extern void objRenderFn_8003b8f4(f32);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int objectId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern void cmbsrc_setExternalActive(int obj, int active);
extern void Obj_FreeObject(int obj);
extern void objSetSlot(int obj, int slot);
extern int* gTitleMenuControlInterface;
extern u8 lbl_803DB411;    /* trigger-interface update parameter */
extern f32 lbl_803E55E0;   /* render fade alpha / posOffsetDecay base */

typedef struct ScCloudrunneraPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 animDataIndex; /* anim-data set selector (-1 = none); obj.unkF4 = animDataIndex+1 */
    s16 gameBit; /* GameBit id -> seq->gameBit */
    u8 pad1C[0x24 - 0x1C];
    u8 unk24;
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
    ((void (*)(int*, int, int, int, int))(*(int*)(*gTitleMenuControlInterface + 0x8)))(obj, 0xffff, 0, 0, 0);
}

void sc_cloudrunnera_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E55E0);
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
                int setup;
                int newObj;
                if (*(void**)&((GameObject*)obj)->childObjs[0] != NULL)
                {
                    break;
                }
                if (Obj_IsLoadingLocked() == 0)
                {
                    break;
                }
                setup = Obj_AllocObjectSetup(0x30, 0x6e8);
                ((ScCloudrunneraSetup*)setup)->unk1B = 0x9;
                ((ScCloudrunneraSetup*)setup)->unk1C = 0;
                ((ScCloudrunneraSetup*)setup)->unk1D = 0;
                ((ScCloudrunneraSetup*)setup)->unk20 = lbl_803E55E0;
                ((ScCloudrunneraSetup*)setup)->unk26 = 0xff;
                ((ScCloudrunneraSetup*)setup)->unk27 = 0xff;
                ((ScCloudrunneraSetup*)setup)->unk28 = 0xff;
                ((ScCloudrunneraSetup*)setup)->unk24 = -1;
                ((ScCloudrunneraSetup*)setup)->unk04 = 2;
                ((ScCloudrunneraSetup*)setup)->unk05 = 1;
                ((ScCloudrunneraSetup*)setup)->unk06 = 0xff;
                ((ScCloudrunneraSetup*)setup)->unk07 = 0xff;
                ((ScCloudrunneraSetup*)setup)->unk29 = 1;
                ((ScCloudrunneraSetup*)setup)->unk2A = 0;
                newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                         *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)newObj)->anim.flags = (s16)(((GameObject*)newObj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                ObjLink_AttachChild(obj, newObj, 0);
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
                    ObjLink_DetachChild(obj, innerSlot);
                    Obj_FreeObject(innerSlot);
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

void sc_cloudrunnera_init(int obj, int p2)
{
    ObjSeqState* seq;
    f32 base;
    s32 objF4;

    objSetSlot(obj, 0x64);
    seq = ((GameObject*)obj)->extra;
    seq->gameBit = ((ScCloudrunneraPlacement*)p2)->gameBit;
    seq->flags = -1;
    base = lbl_803E55E0;
    seq->posOffsetDecay = base / (base + (f32)(u32)((ScCloudrunneraPlacement*)p2)->unk24);
    seq->curveId = -1;
    ((GameObject*)obj)->unkF8 = 0;

    objF4 = ((GameObject*)obj)->unkF4;
    if (objF4 == 0 && ((ScCloudrunneraPlacement*)p2)->animDataIndex != 1)
    {
        (*gObjectTriggerInterface)
            ->loadAnimData((u8*)seq, (u8*)p2);
        ((GameObject*)obj)->unkF4 = ((ScCloudrunneraPlacement*)p2)->animDataIndex + 1;
    }
    else if (objF4 != 0 && ((ScCloudrunneraPlacement*)p2)->animDataIndex != objF4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)seq);
        if (((ScCloudrunneraPlacement*)p2)->animDataIndex != -1)
        {
            (*gObjectTriggerInterface)
                ->loadAnimData((u8*)seq, (u8*)p2);
        }
        ((GameObject*)obj)->unkF4 = ((ScCloudrunneraPlacement*)p2)->animDataIndex + 1;
    }
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->shadowTintA = 0x64;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
    }
}

void sc_cloudrunnera_release(void)
{
}

void sc_cloudrunnera_initialise(void)
{
}

int fn_801DD170(void);
