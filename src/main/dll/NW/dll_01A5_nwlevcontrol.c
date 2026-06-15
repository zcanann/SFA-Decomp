#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/objseq.h"
#include "main/sky_interface.h"

extern undefined4 Music_Trigger();
extern byte gameTimerIsRunning();
extern f32 fn_80014668(void);
extern void timerSetToCountUp(void);
extern void gameTimerInit(s8 flags, int minutes);
extern uint GameBit_Get();
extern undefined4 GameBit_Set();
extern undefined4 SCGameBitLatch_Update();
extern u8* Obj_GetPlayerObject(void);
extern void gameTextShow(int p);
extern f32 lbl_803E5278;
extern f32 lbl_803E527C;
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern f32 timeDelta;
extern int isGameTimerDisabled(void);

extern uint GameBit_Get(int id);
extern f32 lbl_803E5280;
extern void fn_80088870(char* a, char* b, char* c, char* d);
extern int getSaveGameLoadStatus(void);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void getEnvfxAct(int a, int b, int c, int d);
extern int ObjList_FindObjectById(int objectId);
extern int ObjTrigger_IsSetById();
extern void gameTimerStop(void);

void nw_levcontrol_update(int objArg)
{
    int obj;
    short* player;
    u8 mode;
    int val;
    uint bitVal;
    uint bitVal3;
    byte flag;
    int bitVal2;
    uint bitVal4;
    float* state;

    obj = objArg;
    state = (float*)((GameObject*)obj)->extra;
    player = (short*)Obj_GetPlayerObject();
    if (*state > lbl_803E5278)
    {
        gameTextShow(0x435);
        *state = *state - timeDelta;
        if (*state < lbl_803E5278)
        {
            *state = *(f32 *)&lbl_803E5278;
        }
    }
    mode = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    if (mode != '\x01')
    {
        (*gMapEventInterface)->setMapAct((int)((GameObject*)obj)->anim.mapEventSlot, 1);
    }
    mode = (*gMapEventInterface)->getMapAct(7);
    if (mode == '\x01')
    {
        (*gMapEventInterface)->setMapAct(7, 2);
        GameBit_Set(0xf22, 1);
        GameBit_Set(0xf23, 1);
        GameBit_Set(0xf24, 1);
        GameBit_Set(0xf25, 1);
    }
    val = (*gSkyInterface)->getSunPosition(0);
    if (val != 0)
    {
        if (*(short*)(state + 4) != -1)
        {
            *(short*)(state + 4) = -1;
            if ((*((int*)state + 2) & 0x10) != 0)
            {
                Music_Trigger((int*)0x1a, 0);
            }
        }
    }
    else
    {
        if (*(short*)(state + 4) != 0x1a)
        {
            *(short*)(state + 4) = 0x1a;
            if ((*((int*)state + 2) & 0x10) != 0)
            {
                Music_Trigger((int*)0x1a, 1);
            }
        }
    }
    SCGameBitLatch_Update(state + 2, 8, -1, -1, 0x3a0, (int*)0x35);
    SCGameBitLatch_Update(state + 2, 0x10, -1, -1, 0x3a1, (int*)(int)*(short*)(state + 4));
    SCGameBitLatch_Update(state + 2, 0x20, -1, -1, 0x393, (int*)0x36);
    SCGameBitLatch_Update(state + 2, 0x40, -1, -1, 0xcbb, (int*)0xc4);
    bitVal4 = 0;
    bitVal = GameBit_Get(0x19f);
    bitVal3 = GameBit_Get(0x19d);
    if ((bitVal3 != bitVal) && (flag = gameTimerIsRunning(), flag != 0))
    {
        bitVal4 = 1;
    }
    GameBit_Set(0xf31, bitVal4);
    SCGameBitLatch_Update(state + 2, 0x80, -1, -1, 0xf31, (int*)0xaf);
    bitVal = GameBit_Get(0x398);
    if ((bitVal != 0) &&
        (mode = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1f), mode == '\0')
    )
    {
        (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1f, 1);
    }
    if (((*((int*)state + 2) & 2) != 0) && isGameTimerDisabled() != 0)
    {
        Sfx_PlayFromObject(0, SFXsc_clubhit02);
        (*gMapEventInterface)->gotoRestartPoint();
    }
    else
    {
        switch (*(undefined*)(state + 1))
        {
        case 0:
            bitVal = GameBit_Get(0x19d);
            if (bitVal != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                *(undefined*)(state + 1) = 2;
                GameBit_Set(0xecd, 1);
            }
            break;
        case 1:
            (*gObjectTriggerInterface)->preempt(obj, 0x64a);
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 0x20);
            *(undefined*)(state + 1) = 2;
            GameBit_Set(0xecd, 1);
            break;
        case 2:
            obj = fn_801CFD68((u8*)state);
            if (obj != 0)
            {
                *(undefined*)((int)state + 5) = 0x32;
                *((uint*)state + 2) = *((uint*)state + 2) | 1;
            }
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
            fn_801CFD68((u8*)state);
            break;
        case 8:
            obj = fn_801CFD68((u8*)state);
            if (obj == 1)
            {
                *((uint*)state + 2) = *((uint*)state + 2) | 4;
            }
            break;
        case 9:
            if ((*(u16*)(player + 0x58) & 0x1000) != 0)
            {
                *(undefined*)(state + 1) = 10;
            }
            break;
        case 10:
            if ((*(u16*)(player + 0x58) & 0x1000) == 0)
            {
                bitVal2 = *((int*)state + 2);
                if ((bitVal2 & 1) != 0)
                {
                    *((uint*)state + 2) = bitVal2 & ~1;
                    *((uint*)state + 2) = *((uint*)state + 2) | 2;
                    gameTimerInit(0x15, (uint) * (byte*)((int)state + 5));
                    timerSetToCountUp();
                    (*gMapEventInterface)->savePoint((int)(player + 6), (int)*player, 0, 0);
                }
                else if ((bitVal2 & 4) != 0)
                {
                    *((uint*)state + 2) = bitVal2 & 0xfffffffd;
                    *((uint*)state + 2) = *((uint*)state + 2) & 0xfffffffb;
                    gameTimerStop();
                    Music_Trigger((int*)0xaf, 0);
                    GameBit_Set(0x19f, 1);
                }
                else
                {
                    val = (int)(fn_80014668() / lbl_803E527C);
                    gameTimerStop();
                    gameTimerInit(0x15, (uint) * (byte*)((int)state + 5) + val);
                    timerSetToCountUp();
                }
                (*gObjectTriggerInterface)->runSequence(*(u8*)(state + 3), (void*)obj,
                                                        -1);
                *(undefined*)(state + 1) = *(undefined*)((int)state + 0xd);
            }
            break;
        case 0xb:
            bitVal = GameBit_Get(0xecd);
            if (bitVal != 0)
            {
                GameBit_Set(0xecd, 0);
            }
            break;
        case 0xc:
            (*gObjectTriggerInterface)->preempt(obj, 0x5a);
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, 8);
            *(undefined*)(state + 1) = 0xb;
        }
    }
    return;
}

int sh_tricky_getExtraSize(void);

void nw_levcontrol_init(int* obj)
{
    extern void envFxActFn_800887f8(int id);
    extern char lbl_803269F8[];
    char* base = lbl_803269F8;
    u8* state = ((GameObject*)obj)->extra;

    Obj_GetPlayerObject();
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);

    if (GameBit_Get(0x19f) != 0)
    {
        state[4] = 0xc;
    }
    else if (GameBit_Get(0x19d) != 0)
    {
        state[4] = 1;
    }
    else
    {
        state[4] = 0;
    }

    *(f32*)state = lbl_803E5280;

    fn_80088870(base + 0x8c, base + 0x54, base + 0xc4, base + 0xfc);

    if (getSaveGameLoadStatus() != 0)
    {
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediately(0, 0, 0x23c, 0);
    }
    else
    {
        envFxActFn_800887f8(0x1f);
        getEnvfxAct(0, 0, 0x23c, 0);
    }

    (*gMapEventInterface)->setObjGroupStatus(7, 0, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 2, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 5, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 10, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 0x1c, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 9, 1);
}

int fn_801CFD68(u8* state)
{
    extern s32 lbl_803269F8[];
    s32* table;
    int obj;

    table = lbl_803269F8;
    obj = ObjList_FindObjectById(table[state[0xe]]);
    if (ObjTrigger_IsSetById(obj, 0x1ee) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        state[4] = 9;
        state[0xc] = table[state[0xe] + 7];
        state[0xd] = table[state[0xe] + 0xe];
        state[0xe]++;
        state[5] = 0x1e;
        return 1;
    }

    if (state[0xe] != 0)
    {
        obj = ObjList_FindObjectById(table[state[0xe] - 1]);
        if (ObjTrigger_IsSetById(obj, 0x1ee) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            state[4] = 9;
            state[0xc] = table[state[0xe] + 6];
            state[5] = 0;
            return 2;
        }
    }

    return 0;
}

int nw_levcontrol_getExtraSize(void)
{
    return 0x14;
}

/* EN v1.0 0x801CFECC  size: 84b  nw_levcontrol_free: dispatches the object's
 * map event slot through gMapEventInterface; when the call returns 0 also fires
 * envFxActFn_800887f8(0); always tails into gameTimerStop. */
void nw_levcontrol_free(GameObject* obj)
{
    extern void envFxActFn_800887f8(s32);
    s8 v = obj->anim.mapEventSlot;
    int ret = (*gMapEventInterface)->getObjGroupStatus((s32)v, 0);
    if ((u8)ret == 0)
    {
        envFxActFn_800887f8(0);
    }
    gameTimerStop();
}
