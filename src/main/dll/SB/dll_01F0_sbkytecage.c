/*
 * SB_KyteCage (DLL 0x1F0) - the cage on the galleon deck holding the captive
 * baby Cloudrunner, Kyte, in the ShipBattle prologue (SB = the retail
 * "ShipBattle" map). After Krystal lands on the deck she talks to the caged
 * Kyte (the SB_CageKyte child inside) to progress the level - Kyte is never
 * actually freed; talking simply opens the deck door behind the cage. The
 * cage attaches the loose Kyte child (objType 0x121) it finds in the object
 * list, swings on its parent chain, and - once the player triggers it -
 * disables input and runs the trigger sequence (a door choice picks trigger
 * 2 vs 1) that opens the deck door to the golden-key passage. On DLL free it
 * detaches the attached Kyte child.
 */
#include "main/dll/sbkytecagestate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objseq.h"
#include "main/objanim_update.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
extern f32 timeDelta;

STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);

extern int getLActions();
extern int ObjLink_DetachChild();
extern int ObjLink_AttachChild();
extern f32 lbl_803E5918; /* ObjAnim_AdvanceCurrentMove speed */

extern int* objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E591C; /* ObjAnim_SetCurrentMove blend time */

/* objType of the loose Kyte child the cage attaches */
#define SB_KYTE_OBJECT_TYPE 0x121

/* obj->objectFlags bits set at init */
#define SB_KYTECAGE_INIT_FLAGS 0x6000

/* gMapEvent action ids requested at init when GAMEBIT_KYTE_CAGED is unset */
enum
{
    SB_KYTECAGE_LACTION_A = 88,
    SB_KYTECAGE_LACTION_B = 109
};

/* trigger-sequence indices run by SB_KyteCage_update */
enum
{
    SB_KYTECAGE_TRIGGER_RELEASE_A = 1, /* doorChoice == 0 */
    SB_KYTECAGE_TRIGGER_RELEASE_B = 2, /* doorChoice != 0 */
    SB_KYTECAGE_TRIGGER_OPEN = 3
};

/* anim.currentMove ids selected from the parent's kind */
enum
{
    SB_KYTECAGE_MOVE_NEAR = 5, /* parent kind < 9 */
    SB_KYTECAGE_MOVE_FAR = 9   /* parent kind >= 9 */
};

/* game bits */
#define GAMEBIT_KYTE_CAGED 117
#define GAMEBIT_KYTE_OPENED 0x92a

/* anim.resetHitboxMode trigger bits */
enum
{
    SB_KYTECAGE_HIT_CLEAR = 0x8, /* cleared each tick */
    SB_KYTECAGE_HIT_OPEN = 0x4,  /* player opened the cage */
    SB_KYTECAGE_HIT_RELEASE = 0x1
};

void FUN_801e55c0(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
                  u64 param_6, u64 param_7, u64 param_8, u16* param_9, int param_10)
{
}

void SB_KyteCage_render(void)
{
}

void SB_KyteCage_hitDetect(void)
{
}

void SB_KyteCage_release(void)
{
}

void SB_KyteCage_initialise(void)
{
}

int SB_KyteCage_getExtraSize(void) { return sizeof(SBKyteCageState); }
int SB_KyteCage_getObjectTypeId(void) { return 0x0; }

/* SB_KyteCage_SeqFn anim-event opcodes (written into state->seqLatch) */
enum
{
    SB_KYTECAGE_SEQEV_LATCH_1 = 1,
    SB_KYTECAGE_SEQEV_LATCH_2 = 2
};

int SB_KyteCage_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    SBKyteCageState* state;
    int i;

    state = obj->extra;
    i = 0;
    while (i < animUpdate->eventCount)
    {
        u8 seqCode;

        seqCode = animUpdate->eventIds[i];
        if (seqCode == SB_KYTECAGE_SEQEV_LATCH_1)
        {
            state->seqLatch = 1;
        }
        else if (seqCode == SB_KYTECAGE_SEQEV_LATCH_2)
        {
            state->seqLatch = 2;
        }
        i++;
    }

    animUpdate->hitVolumePair = -4;
    if (obj->seqIndex != -1)
    {
        animUpdate->hitVolumePair &= ~4;
        if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E5918,
                                                                         timeDelta, NULL) != 0)
        {
            Sfx_PlayFromObject((int*)obj, SFXfend_rob_beep2);
        }
    }

    animUpdate->sequenceEventActive = 0;
    return 0;
}

void SB_KyteCage_free(GameObject* obj)
{
    void* child = ((SBKyteCageState*)obj->extra)->kyte;
    if (child != NULL)
    {
        ObjLink_DetachChild(obj, child);
    }
}

void SB_KyteCage_init(GameObject* obj, int* params)
{
    SBKyteCageState* state = obj->extra;
    obj->animEventCallback = SB_KyteCage_SeqFn;
    obj->anim.rotX = (s16)((s8) * (s8*)&((ObjHitsPriorityState*)params)->localPosZ << 8);
    obj->objectFlags = (u16)(obj->objectFlags | SB_KYTECAGE_INIT_FLAGS);
    state->seqLatch = 0;
    if ((u32)GameBit_Get(GAMEBIT_KYTE_CAGED) == 0u)
    {
        getLActions(obj, obj, SB_KYTECAGE_LACTION_A, 0, 0, 0);
        getLActions(obj, obj, SB_KYTECAGE_LACTION_B, 0, 0, 0);
    }
}

void SB_KyteCage_update(int obj)
{
    extern void* ObjList_GetObjects(int* outA, int* outB);
    extern void Sfx_PlayFromObject(int* obj, int sfxId);

    SBKyteCageState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.resetHitboxFlags =
        (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~SB_KYTECAGE_HIT_CLEAR);
    if (state->kyte == NULL)
    {
        int* head;
        int count;
        int i;
        head = ObjList_GetObjects(&i, &count);
        for (i = 0; i < count; i++)
        {
            int child = head[i];
            if (((GameObject*)child)->anim.seqId == SB_KYTE_OBJECT_TYPE)
            {
                state->kyte = (void*)child;
                ObjLink_AttachChild(obj, state->kyte, 1);
                i = count;
            }
        }
    }
    if ((((GameObject*)obj)->anim.resetHitboxFlags & SB_KYTECAGE_HIT_OPEN) != 0)
    {
        if (GameBit_Get(GAMEBIT_KYTE_OPENED) == 0)
        {
            buttonDisable(0, 0x100);
            (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
            (*gObjectTriggerInterface)->runSequence(SB_KYTECAGE_TRIGGER_OPEN, (void*)obj, -1);
            GameBit_Set(GAMEBIT_KYTE_OPENED, 1);
            return;
        }
    }
    if ((((GameObject*)obj)->anim.resetHitboxFlags & SB_KYTECAGE_HIT_RELEASE) != 0)
    {
        buttonDisable(0, 0x100);
        (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
        if (state->doorChoice != 0)
        {
            (*gObjectTriggerInterface)->runSequence(SB_KYTECAGE_TRIGGER_RELEASE_B, (void*)obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(SB_KYTECAGE_TRIGGER_RELEASE_A, (void*)obj, -1);
            state->doorChoice = 1;
        }
    }
    if (((GameObject*)obj)->anim.parent != NULL)
    {
        int kind = ((GameObject*)((GameObject*)obj)->anim.parent)->unkF4;
        int* mvec = objModelGetVecFn_800395d8(obj, 0);
        if (mvec != 0 && kind < 9 && ((GameObject*)obj)->anim.currentMove != SB_KYTECAGE_MOVE_NEAR)
        {
            *(s16*)((char*)mvec + 4) = ((GameObject*)((GameObject*)obj)->anim.parent)->anim.rotZ;
            ObjAnim_SetCurrentMove(obj, SB_KYTECAGE_MOVE_NEAR, lbl_803E591C, 0);
        }
        else if (mvec != 0 && kind >= 9 && ((GameObject*)obj)->anim.currentMove != SB_KYTECAGE_MOVE_FAR)
        {
            *(s16*)((char*)mvec + 4) = 0;
            ObjAnim_SetCurrentMove(obj, SB_KYTECAGE_MOVE_FAR, lbl_803E591C, 0);
        }
    }
    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5918,
                                                                     timeDelta, NULL) != 0)
    {
        Sfx_PlayFromObject((int*)obj, SFXfend_rob_beep2);
    }
}
