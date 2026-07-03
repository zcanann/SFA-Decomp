/*
 * tumbleweedbush (DLL 0x00D1)
 *
 * Tricky "growl/dig" action handler.
 *
 * trickyGrowl drives a four-step substate machine for the Tricky sidekick:
 *   0  growl windup  - barks (sfx 0x299), kicks off anim move 0x33
 *   1  face target   - turns toward the followed object (extra+0x28), with a
 *                      random chance to bark again, until anim flag + timer hit
 *   2  dig start     - if loading isn't locked, spawns seven child objects
 *                      (Obj_AllocObjectSetup/Obj_SetupObject into unk700..),
 *                      plays/loops the dig sfx (0x3db/0x3dc) and runs anim 0x34
 *   3  dig end       - on move progress >= threshold, resets child anim speed,
 *                      stops the dig loop, barks (sfx 0x29d) and clears the
 *                      action's state flags, returning to substate 0
 *
 * Barks are gated on bit 6 of TrickyGrowlState.unk58, the current anim move
 * being outside [0x29,0x30), and no sfx already playing on channel 0x10.
 */
#include "main/dll/tricky_state.h"
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/dll/baddie/trickyfollow.h"
#include "main/engine_shared.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct TrickyGrowlState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;            /* 0x08: target Z (paired with deref base for X) */
    u8 padC[0x58 - 0xC];
    u8 unk58;            /* 0x58: bit 6 suppresses barks */
    u8 pad59[0x60 - 0x59];
} TrickyGrowlState;

extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject(void* setup, int p2, int p3, int p4, void* p5);
extern int getAngle(float y, float x);
extern void objAudioFn_800393f8(void* obj, void* p2, int p3, int p4, int p5, int p6);
extern void objAnimFn_8013a3f0(void* obj, int p2, float p3, int p4);
extern int trickyTurnTowardYaw(u8* obj, s16 targetYaw);
extern void objSetAnimSpeedTo1(int* obj);
extern char lbl_8031D2E8[];  /* tricky debug-string blob */
extern f32 lbl_803E23DC;
extern f32 lbl_803E2444;
extern f32 lbl_803E24C8;
extern f32 lbl_803E24CC;
extern f32 lbl_803E24D0;

#define CHILD_OBJECT_COUNT 7

enum
{
    TRICKYGROWL_WINDUP = 0,
    TRICKYGROWL_FACE_TARGET = 1,
    TRICKYGROWL_DIG_START = 2,
    TRICKYGROWL_DIG_END = 3
};

#pragma opt_propagation off
void trickyGrowl(void* obj, void* trickyState)
{
    void* state;
    int i;
    int j;
    void* digState;
    void** slot;
    void* setup;
    void** slot2;
    char* strBase = lbl_8031D2E8;

    switch (((TrickyState*)trickyState)->substate)
    {
    case TRICKYGROWL_WINDUP:
        trickyDebugPrint(strBase + 0x558);
        if (trickyFn_8013b368(obj, lbl_803E24C8, trickyState) == 0)
        {
            state = ((GameObject*)obj)->extra;
            if ((((u32)((TrickyGrowlState*)state)->unk58 >> 6) & 1) == 0u)
            {
                s16 move = ((GameObject*)obj)->anim.currentMove;
                if (move >= 0x30 || move < 0x29)
                {
                    if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8(obj, (char*)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
            ((TrickyState*)trickyState)->substate = TRICKYGROWL_FACE_TARGET;
            objAnimFn_8013a3f0(obj, 0x33, lbl_803E2444, 0x4000000);
            *(int*)((char*)trickyState + 0x728) = 0;
        }
        break;
    case TRICKYGROWL_FACE_TARGET:
        trickyDebugPrint(strBase + 0x568);
        if (*(u8*)((TrickyState*)trickyState)->progressPtr != 0 && *(int*)((char*)trickyState + 0x728) != 0)
        {
            ((TrickyState*)trickyState)->substate = TRICKYGROWL_DIG_START;
        }
        else
        {
            void* target = ((TrickyState*)((GameObject*)obj)->extra)->unk28;
            trickyTurnTowardYaw(obj, getAngle(
                                    -(*(f32*)target - ((GameObject*)obj)->anim.worldPosX),
                                    -(((TrickyGrowlState*)target)->unk8 - ((GameObject*)obj)->anim.worldPosZ)));
            if (randomGetRange(0, 10) == 0)
            {
                state = ((GameObject*)obj)->extra;
                if (((((TrickyGrowlState*)state)->unk58 >> 6) & 1) == 0u)
                {
                    s16 move = ((GameObject*)obj)->anim.currentMove;
                    if (move >= 0x30 || move < 0x29)
                    {
                        if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
                        {
                            objAudioFn_800393f8(obj, (char*)state + 0x3a8, 0x299, 0x100, -1, 0);
                        }
                    }
                }
            }
        }
        break;
    case TRICKYGROWL_DIG_START:
        trickyDebugPrint(strBase + 0x57c);
        if (trickyFn_8013b368(obj, lbl_803E24CC, trickyState) == 0)
        {
            if ((u8)Obj_IsLoadingLocked() != 0)
            {
                ((TrickyState*)trickyState)->stateFlags = ((TrickyState*)trickyState)->stateFlags | 0x800;
                for (i = 0, slot = trickyState; i < CHILD_OBJECT_COUNT; slot++, i++)
                {
                    setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                    *(u8*)((char*)setup + 0x4) = 2;
                    *(u8*)((char*)setup + 0x5) = 1;
                    *(s16*)((char*)setup + 0x1a) = i;
                    slot[0x700 / 4] = (void*)Obj_SetupObject(
                        setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                        ((GameObject*)obj)->anim.parent);
                }
                Sfx_PlayFromObject((u32)obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((u32)obj, SFXTRIG_trpopn_c);
            }
            (*(u8*)((TrickyState*)trickyState)->progressPtr)--;
            objAnimFn_8013a3f0(obj, 0x34, lbl_803E2444, 0x4000000);
            ((TrickyState*)trickyState)->stateFlags = ((TrickyState*)trickyState)->stateFlags | 0x10;
            ((TrickyState*)trickyState)->substate = TRICKYGROWL_DIG_END;
            *(int*)((char*)trickyState + 0x728) = 0;
        }
        break;
    case TRICKYGROWL_DIG_END:
        trickyDebugPrint(strBase + 0x590);
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E24D0)
        {
            ((TrickyState*)trickyState)->stateFlags &= ~0x800LL;
            ((TrickyState*)trickyState)->stateFlags = ((TrickyState*)trickyState)->stateFlags | 0x1000;
            for (j = 0, slot2 = trickyState; j < CHILD_OBJECT_COUNT; slot2++, j++)
            {
                objSetAnimSpeedTo1(slot2[0x700 / 4]);
            }
            Sfx_RemoveLoopedObjectSound((u32)obj, SFXTRIG_trpopn_c);
            digState = ((GameObject*)obj)->extra;
            if (((((TrickyGrowlState*)digState)->unk58 >> 6) & 1) == 0u)
            {
                s16 move = ((GameObject*)obj)->anim.currentMove;
                if (move >= 0x30 || move < 0x29)
                {
                    if (Sfx_IsPlayingFromObjectChannel((u32)(int)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8(obj, (char*)digState + 0x3a8, 0x29d, 0, -1, 0);
                    }
                }
            }
            ((TrickyState*)trickyState)->unk08 = 1;
            ((TrickyState*)trickyState)->substate = TRICKYGROWL_WINDUP;
            {
                f32 resetValue = lbl_803E23DC;
                ((TrickyState*)trickyState)->unk71C = resetValue;
                ((TrickyState*)trickyState)->unk720 = resetValue;
            }
            ((TrickyState*)trickyState)->stateFlags &= ~0x10LL;
            ((TrickyState*)trickyState)->stateFlags &= ~0x10000LL;
            ((TrickyState*)trickyState)->stateFlags &= ~0x20000LL;
            ((TrickyState*)trickyState)->stateFlags &= ~0x40000LL;
            {
                s8 mm = -1;
                ((TrickyState*)trickyState)->unkD = mm;
            }
        }
        else
        {
            void* target = ((TrickyState*)((GameObject*)obj)->extra)->unk28;
            trickyTurnTowardYaw(obj, getAngle(
                                    -(*(f32*)target - ((GameObject*)obj)->anim.worldPosX),
                                    -(((TrickyGrowlState*)target)->unk8 - ((GameObject*)obj)->anim.worldPosZ)));
        }
        break;
    }
}
#pragma opt_propagation reset

