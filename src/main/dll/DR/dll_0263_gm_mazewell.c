#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct GmmazewellClearPendingTriggerCallbackState
{
    u8 pad0[0x4 - 0x0];
    s32 unk4;
} GmmazewellClearPendingTriggerCallbackState;


typedef struct GmmazewellState
{
    u8 pad0[0x4 - 0x0];
    s32 unk4;
} GmmazewellState;


int gmmazewell_getExtraSize(void) { return 0x8; }

void gmmazewell_render(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6978);
}

void gmmazewell_free(void)
{
    GameBit_Set(0xefc, 0);
    Music_Trigger(0x36, 0);
}

void gmmazewell_init(int obj)
{
    u8* p = ((GameObject*)obj)->extra;
    p[0] = 0;
    GameBit_Set(0xefc, 1);
    Music_Trigger(0x36, 1);
    ((GameObject*)obj)->animEventCallback = (void*)gmmazewell_clearPendingTriggerCallback;
}

int gmmazewell_clearPendingTriggerCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* p = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1 && *(int*)(p + 0x4) != -1)
        {
            (*gGameUIInterface)->showNpcDialogue(((GmmazewellClearPendingTriggerCallbackState*)p)->unk4, 0x14, 0x8c, 0);
            ((GmmazewellClearPendingTriggerCallbackState*)p)->unk4 = -1;
        }
    }
    return 0;
}

typedef struct
{
    s16 unlockBits[28];
    s32 itemIds[9];
} MazewellTable;

void gmmazewell_update(void* obj)
{
    s16* base = lbl_8032A730;
    s32* base32 = (s32*)base;
    u8* runtime = ((GameObject*)obj)->extra;
    u8* player;
    int value;
    s16* p;
    int i;
    if (runtime[1] == 0)
    {
        player = (u8*)Obj_GetPlayerObject();
        if (player != 0)
        {
            (*gMapEventInterface)->triggerEvent((int)(player + 0xc), *(s16*)player, 0,
                                                getCurMapLayer());
            runtime[1] = 1;
        }
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
    for (i = 0, p = base; (u32)i < 9; i++)
    {
        if (GameBit_Get(*p) != 0)
        {
            value = base[i];
            goto checkValue;
        }
        p++;
    }
    value = 0;
checkValue:
    if (value != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
    {
        int found;
        for (i = 0, p = base; (u32)i < 9; i++)
        {
            if ((*gGameUIInterface)->isEventReady(*p) != 0)
            {
                if (lbl_803DC968 != 0)
                {
                    runtime = ((GameObject*)obj)->extra;
                    switch (i)
                    {
                    case 0:
                    case 1:
                    case 2:
                        GameBit_Set(base[i + 10], 1);
                        saveFileStruct_unlockCheat((u8)i);
                        break;
                    }
                    ((GmmazewellState*)runtime)->unk4 = base32[i + 14];
                    GameBit_Set(base[i + 20], 1);
                }
                else
                {
                    runtime = ((GameObject*)obj)->extra;
                    *(int*)(runtime + 4) = base32[i + 14];
                    switch (i)
                    {
                    case 3:
                        ((GmmazewellState*)runtime)->unk4 = 1316;
                    /* fall through */
                    case 0:
                    case 1:
                    case 2:
                        GameBit_Set(base[i + 10], 1);
                        saveFileStruct_unlockCheat((u8)i);
                        break;
                    }
                    GameBit_Set(base[i + 20], 1);
                }
                found = 1;
                goto checkFound;
            }
            p++;
        }
        found = 0;
    checkFound:
        if (found != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            buttonDisable(0, 256);
        }
    }
    objRenderFn_80041018((int)obj);
}
