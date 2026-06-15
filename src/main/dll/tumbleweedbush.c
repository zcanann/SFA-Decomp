#include "main/dll/tricky_state.h"
#include "main/audio/sfx.h"
#include "main/game_object.h"

typedef struct TrickyGrowlState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    u8 padC[0x58 - 0xC];
    u8 unk58;
    u8 pad59[0x60 - 0x59];
} TrickyGrowlState;

extern int trickyDebugPrint(const char* fmt, ...);
extern int trickyFn_8013b368(void* param_1, float threshold, void* param_2);
extern void* Obj_AllocObjectSetup(int p1, int p2);
extern int Obj_SetupObject(void* setup, int p2, int p3, int p4, void* p5);
extern int Obj_IsLoadingLocked(void);
extern int randomGetRange(int lo, int hi);
extern int getAngle(float x, float z);
extern void objAudioFn_800393f8(void* obj, void* p2, int p3, int p4, int p5, int p6);
extern void objAnimFn_8013a3f0(void* obj, int p2, float p3, int p4);
extern void trickyTurnTowardYaw(void* obj, s16 angle);
extern void objSetAnimSpeedTo1(void* obj);

extern char lbl_8031D2E8[];

extern f32 lbl_803E23DC;
extern f32 lbl_803E2444;
extern f32 lbl_803E24C8;
extern f32 lbl_803E24CC;
extern f32 lbl_803E24D0;

void trickyGrowl(void* obj, void* trickyState)
{
    void* state;
    int i;
    void** slot;
    void* setup;
    char* strBase = lbl_8031D2E8;

    switch (((TrickyState*)trickyState)->substate)
    {
    case 0:
        trickyDebugPrint(strBase + 0x558);
        if (trickyFn_8013b368(obj, lbl_803E24C8, trickyState) == 0)
        {
            state = ((GameObject*)obj)->extra;
            if ((((uint)((TrickyGrowlState*)state)->unk58 >> 6) & 1) == 0u)
            {
                s16 a0 = ((GameObject*)obj)->anim.currentMove;
                if (a0 >= 0x30 || a0 < 0x29)
                {
                    if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8(obj, (char*)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
            ((TrickyState*)trickyState)->substate = 1;
            objAnimFn_8013a3f0(obj, 0x33, lbl_803E2444, 0x4000000);
            *(int*)((char*)trickyState + 0x728) = 0;
        }
        break;
    case 1:
        trickyDebugPrint(strBase + 0x568);
        if (*(u8*)*(int*)trickyState != 0 && *(int*)((char*)trickyState + 0x728) != 0)
        {
            ((TrickyState*)trickyState)->substate = 2;
        }
        else
        {
            void* target = *(void**)((char*)((GameObject*)obj)->extra + 0x28);
            trickyTurnTowardYaw(obj, (s16)getAngle(
                                    -(*(f32*)target - ((GameObject*)obj)->anim.worldPosX),
                                    -(((TrickyGrowlState*)target)->unk8 - ((GameObject*)obj)->anim.worldPosZ)));
            if (randomGetRange(0, 10) == 0)
            {
                state = ((GameObject*)obj)->extra;
                if (((((TrickyGrowlState*)state)->unk58 >> 6) & 1) == 0u)
                {
                    s16 a0 = ((GameObject*)obj)->anim.currentMove;
                    if (a0 >= 0x30 || a0 < 0x29)
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
    case 2:
        trickyDebugPrint(strBase + 0x57c);
        if (trickyFn_8013b368(obj, lbl_803E24CC, trickyState) == 0)
        {
            if ((u8)Obj_IsLoadingLocked() != 0)
            {
                ((TrickyState*)trickyState)->stateFlags = ((TrickyState*)trickyState)->stateFlags | 0x800;
                for (i = 0, slot = (void**)trickyState; i < 7; slot++, i++)
                {
                    setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                    *(u8*)((char*)setup + 0x4) = 2;
                    *(u8*)((char*)setup + 0x5) = 1;
                    *(s16*)((char*)setup + 0x1a) = (s16)i;
                    slot[0x700 / 4] = (void*)Obj_SetupObject(
                        setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                        ((GameObject*)obj)->anim.parent);
                }
                Sfx_PlayFromObject((u32)obj, 0x3db);
                Sfx_AddLoopedObjectSound((u32)obj, 0x3dc);
            }
            (*(u8*)*(int*)trickyState)--;
            objAnimFn_8013a3f0(obj, 0x34, lbl_803E2444, 0x4000000);
            ((TrickyState*)trickyState)->stateFlags = ((TrickyState*)trickyState)->stateFlags | 0x10;
            ((TrickyState*)trickyState)->substate = 3;
            *(int*)((char*)trickyState + 0x728) = 0;
        }
        break;
    case 3:
        trickyDebugPrint(strBase + 0x590);
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E24D0)
        {
            ((TrickyState*)trickyState)->stateFlags &= ~0x800LL;
            ((TrickyState*)trickyState)->stateFlags = ((TrickyState*)trickyState)->stateFlags | 0x1000;
            for (i = 0, slot = (void**)trickyState; i < 7; slot++, i++)
            {
                objSetAnimSpeedTo1(slot[0x700 / 4]);
            }
            Sfx_RemoveLoopedObjectSound((u32)obj, 0x3dc);
            state = ((GameObject*)obj)->extra;
            if (((((TrickyGrowlState*)state)->unk58 >> 6) & 1) == 0u)
            {
                s16 a0 = ((GameObject*)obj)->anim.currentMove;
                if (a0 >= 0x30 || a0 < 0x29)
                {
                    if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8(obj, (char*)state + 0x3a8, 0x29d, 0, -1, 0);
                    }
                }
            }
            ((TrickyState*)trickyState)->unk08 = 1;
            ((TrickyState*)trickyState)->substate = 0;
            {
                f32 resetValue = lbl_803E23DC;
                ((TrickyState*)trickyState)->unk71C = resetValue;
                ((TrickyState*)trickyState)->unk720 = resetValue;
            }
            ((TrickyState*)trickyState)->stateFlags &= ~0x10LL;
            ((TrickyState*)trickyState)->stateFlags &= ~0x10000LL;
            ((TrickyState*)trickyState)->stateFlags &= ~0x20000LL;
            ((TrickyState*)trickyState)->stateFlags &= ~0x40000LL;
            ((TrickyState*)trickyState)->unkD = -1;
        }
        else
        {
            void* target = *(void**)((char*)((GameObject*)obj)->extra + 0x28);
            trickyTurnTowardYaw(obj, (s16)getAngle(
                                    -(*(f32*)target - ((GameObject*)obj)->anim.worldPosX),
                                    -(((TrickyGrowlState*)target)->unk8 - ((GameObject*)obj)->anim.worldPosZ)));
        }
        break;
    }
}
