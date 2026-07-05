/*
 * shswapston / WarpStone (DLL 0x1B0) - the talking WarpStone hub object.
 *
 * It runs the WarpStone's idle/look-at-target animation behaviour
 * (warpstone_update), drives the warp menu sequence object that lets the
 * player pick a destination (warpstone_updateMenuAnimObj +
 * warpstone_handleMenuOptionInput, keyed off analog stick / button input
 * and the player's Krazoa-spirit count), and renders the player model
 * standing on the stone during the menu. Map loads/locks and warps are
 * issued through the map-event interface.
 */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim_update.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/audio/sfx_trigger_ids.h"

#define PAD_BUTTON_B 0x200

typedef struct WarpstoneUpdateMenuAnimObjState
{
    u8 pad0[0x8 - 0x0];
    u8 pathPointIndex; /* 0x8: path point used to seat the player on the stone */
    u8 unk9;        /* 0x9: toggled bit0 on event 0xa */
    u8 flagsA;      /* 0xa: input/hit flags (bit0 player, bit1 hit) */
    u8 padB[0xE - 0xB];
    s16 gameBitE;   /* 0xe: GameBit id (get/set) */
    u8 padE[0xD4 - 0x10];
    u8 flagsD4;     /* 0xd4: bit2 set on event 0x17 */
} WarpstoneUpdateMenuAnimObjState;

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern u32 getButtonsJustPressed(int port);
extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern int playerHasKrazoaSpirit();
extern void padGetAnalogInput(int controller, s8* horizontal, s8* vertical);
extern int lbl_803DC050;
extern int lbl_803DDBF4;

int warpstone_getExtraSize(void)
{
    return 0xd8;
}

int warpstone_getObjectTypeId(void)
{
    return 0x48;
}

extern void loadUiDll(int index);
void warpstone_loadBaseUi(void) { loadUiDll(0x1); }

extern void ObjLink_DetachChild(int obj, int child);
extern void Obj_FreeObject(int obj);

void warpstone_free(int obj, int mode)
{
    int* state = ((GameObject*)obj)->extra;
    if (*(void**)state != NULL && mode == 0)
    {
        ObjLink_DetachChild(obj, state[0]);
        Obj_FreeObject(state[0]);
    }
}

extern int randFn_80080100(int n);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E54A0;

void warpstone_hitDetect(int obj)
{
    extern void objAudioFn_800393f8(int obj, int* p, int a, int b, int c, int d);
    int* state = ((GameObject*)obj)->extra;
    f32 pos[3];
    f32 lightPos[3];

    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &pos[0], &pos[1], &pos[2]) != 0)
    {
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        objLightFn_8009a1dc((void*)obj, lbl_803E54A0, lightPos, 1, 0);
        if (randFn_80080100(3) != 0)
        {
            Sfx_PlayFromObject(obj, SFXbaddie_haga_death);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXbaddie_haga_death);
        }
        objAudioFn_800393f8(obj, state + 5, 171, -1280, -1, 0);
    }
}

extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int Obj_GetPlayerObject(void);
extern int fn_80296464(void);
extern int* Obj_GetActiveModel(int player);
extern void fn_80295B2C(int player, f32 x, f32 y, f32 z);
extern void playerRender(int obj, int a, int b, int c, int d, s8 flag);
extern f32 lbl_803E549C;

void warpstone_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void* player;
    int* state = ((GameObject*)obj)->extra;
    int* model;
    f32 z;
    f32 y;
    f32 x;
    s32 v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E549C);
        player = (void*)Obj_GetPlayerObject();
        if (player != NULL && fn_80296464() != 0)
        {
            model = Obj_GetActiveModel((int)player);
            *(u16*)((char*)model + 24) = (u16)(*(u16*)((char*)model + 24) & ~0x8);
            ObjPath_GetPointWorldPosition(obj, ((WarpstoneUpdateMenuAnimObjState*)state)->pathPointIndex, &x, &y, &z, 0);
            fn_80295B2C((int)player, x, y, z);
            playerRender((int)player, p2, p3, p4, p5, -1);
        }
    }
}

extern int loadMapAndParent(int mapId);
extern int unlockLevel(s32 val, int idx, int flag);
extern int mapGetDirIdx(int idx);
extern int lockLevel(s32 val, int idx);
extern int mapUnload(int mapId, int flags);

#define WARPSTONE_MAP_EVENT_SET(mapId, value) \
    (*gMapEventInterface)->setMapAct((mapId), (value))
#define WARPSTONE_MAP_EVENT_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setObjGroupStatus((mapId), (eventId), (value))

int warpstone_handleMenuOptionInput(u32 p1, u32 p2, int option)
{
    s8 horizontal;
    s8 vertical;

    Obj_GetPlayerObject();
    padGetAnalogInput(0, &horizontal, &vertical);

    switch (option)
    {
    case 0x14:
        if (horizontal < 0)
        {
            loadMapAndParent(0x42);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0x42), 0);
            lockLevel(mapGetDirIdx(7), 1);
            WARPSTONE_MAP_EVENT_SET(0x42, 1);
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x15:
        if (vertical > 0 && lbl_803DC050 == 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x16:
        if (horizontal > 0 && playerHasKrazoaSpirit(1, 0) != 0)
        {
            loadMapAndParent(0x42);
            lockLevel(mapGetDirIdx(0x42), 0);
            lockLevel(mapGetDirIdx(7), 1);
            if (GameBit_Get(0xbfd) != 0)
            {
                WARPSTONE_MAP_EVENT_SET(0x42, 2);
            }
            else if (GameBit_Get(0xff) != 0)
            {
                WARPSTONE_MAP_EVENT_SET(0x42, 2);
            }
            else if (GameBit_Get(0xc6e) != 0)
            {
                WARPSTONE_MAP_EVENT_SET(0x42, 2);
            }
            else if (GameBit_Get(0xc85) != 0)
            {
                WARPSTONE_MAP_EVENT_SET(0x42, 2);
            }
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x17:
        {
            int hasSpirit = playerHasKrazoaSpirit(1, 0);
            if (horizontal > 0 && hasSpirit == 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
                return 1;
            }
            break;
        }

    case 0x18:
        lbl_803DDBF4 = 1;
        if (vertical > 0)
        {
            loadMapAndParent(9);
            lockLevel(mapGetDirIdx(9), 0);
            lockLevel(mapGetDirIdx(7), 1);
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x19:
        if ((getButtonsJustPressed(0) & PAD_BUTTON_B) != 0)
        {
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            mapUnload(mapGetDirIdx(0x17), 0x20000000);
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down);
            return 1;
        }
        break;
    }

    return 0;
}

extern int animatedObjGetSeqId(int obj);
extern int fn_80080360(int obj, int seqId);
extern int getCurUiDll(void);
extern void AudioStream_CancelPrepared(void);
extern void seqClearTaskTexts(void);
extern void doNothing_8000CF54(int unused);
extern void CMenu_SetFadeCounter(s16 v);
extern void warpToMap(int idx, s8 transType);
extern int getDLL16(void);
extern void SHthorntail_updateDustEffects(int obj);
extern f32 timeDelta;

int warpstone_updateMenuAnimObj(int obj, u32 p2, int animObj)
{
    extern int playerFn_801d6d58(void);
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    int child;
    u8 command;
    ObjAnimUpdateState* animUpdate = (ObjAnimUpdateState*)animObj;

    if (animatedObjGetSeqId(animObj) == 0x35f)
    {
        fn_80080360(animObj, 0x2648);
        if (getCurUiDll() != 0x10)
        {
            loadUiDll(0x10);
        }
    }

    child = *(int*)state;
    if ((void*)child != NULL)
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        (child, ((GameObject*)obj)->anim.currentMoveProgress -
         ((GameObject*)child)->anim.currentMoveProgress,
         timeDelta, NULL);
    }

    animUpdate->conditionCallback = (ObjAnimSequenceConditionCallback)warpstone_handleMenuOptionInput;
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)warpstone_loadBaseUi;

    if ((s8)animUpdate->sequenceEventActive != 0)
    {
        ((WarpstoneUpdateMenuAnimObjState*)state)->flagsA = ((WarpstoneUpdateMenuAnimObjState*)state)->flagsA & ~3;
        if (playerFn_801d6d58() != 0)
        {
            ((WarpstoneUpdateMenuAnimObjState*)state)->flagsA = ((WarpstoneUpdateMenuAnimObjState*)state)->flagsA | 1;
        }
        {
            int hit;
            if (GameBit_Get(0x2e8) != 0)
            {
                hit = 1;
            }
            else if (GameBit_Get(0x123) != 0)
            {
                hit = 1;
            }
            else
            {
                hit = 0;
            }
            if (hit)
            {
                ((WarpstoneUpdateMenuAnimObjState*)state)->flagsA = ((WarpstoneUpdateMenuAnimObjState*)state)->flagsA | 2;
            }
        }
        animUpdate->sequenceEventActive = 0;

        if (GameBit_Get(((WarpstoneUpdateMenuAnimObjState*)state)->gameBitE) != 0 && animatedObjGetSeqId(animObj) == 0x35f)
        {
            AudioStream_CancelPrepared();
            seqClearTaskTexts();
            doNothing_8000CF54(0);
            animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        }
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        command = animUpdate->eventIds[i];
        switch (command)
        {
        case 0x17:
            ((WarpstoneUpdateMenuAnimObjState*)state)->flagsD4 = ((WarpstoneUpdateMenuAnimObjState*)state)->flagsD4 | 4;
            Sfx_PlayFromObject(0, SFXTRIG_id_420);
            break;

        case 3:
            ((WarpstoneUpdateMenuAnimObjState*)state)->pathPointIndex = 0;
            break;

        case 4:
            ((WarpstoneUpdateMenuAnimObjState*)state)->pathPointIndex = 1;
            break;

        case 6:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            warpToMap(0x7e, 1);
            break;

        case 7:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            GameBit_Set(0x884, 1);
            warpToMap(0x7e, 1);
            break;

        case 0xa:
            ((WarpstoneUpdateMenuAnimObjState*)state)->unk9 = ((WarpstoneUpdateMenuAnimObjState*)state)->unk9 ^ 1;
            break;

        case 9:
            WARPSTONE_MAP_EVENT_SET(0x17, 1);
            WARPSTONE_MAP_EVENT_SET(0xe, 2);
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            break;

        case 0xc:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            warpToMap(0x33, 0);
            break;

        case 0xd:
            subtitleFn_8001b700();
        case 0xe:
        case 0xf:
        case 0x10:
            if (getCurUiDll() == 0x10)
            {
                int dll16 = getDLL16();
                (*(void (**)(int))(*(int*)dll16 + 0x10))(animUpdate->eventIds[i] - 0xd);
            }
            GameBit_Set(((WarpstoneUpdateMenuAnimObjState*)state)->gameBitE, 1);
            GameBit_Set(0x887, 1);
            break;

        case 0x12:
            WARPSTONE_MAP_EVENT_ANIM(7, 0xa, 0);
            break;

        case 0x14:
            unlockLevel(0, 0, 1);
            break;

        case 0x15:
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            break;

        case 0x16:
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            break;
        }
    }

    SHthorntail_updateDustEffects(obj);
    return 0;
}

#include "main/dll/SC/SClantern.h"
#include "main/audio/sfx.h"

typedef struct WarpstoneState
{
    u8 pad0[0xC - 0x0];
    u8 activated;
    u8 padD[0xE - 0xD];
    s16 gameBitE;   /* 0xe: GameBit id stored at init */
    s16 gameBit10;
    u8 pad12[0x18 - 0x12];
} WarpstoneState;

extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern void fn_8003ADC4(int obj, int target, void* state, int a, int b, int c);
extern s16* objModelGetVecFn_800395d8(int obj, int index);
extern s16 Obj_GetYawDeltaToObject(int obj, int target, int flags);

extern void objAnimFn_80038f38(int obj, int* animState);
extern void characterDoEyeAnims(int obj, void* state);
extern s16 lbl_803DC044;
extern s16 lbl_803DDBF0;
extern s16 lbl_803DDBF2;
extern int lbl_803DC038;
extern int lbl_803DC03C;
extern int lbl_803DC040;
extern int lbl_803DC048;
extern int lbl_803DC04C;
extern f32 lbl_803E5460;
extern f32 lbl_803E546C;
extern f32 lbl_803E54A4;
extern f32 lbl_803E54A8;
extern f32 lbl_803E54AC;

typedef struct WarpstoneFlags
{
    u8 b7 : 1;
    u8 lookAtPlayer : 1;
    u8 b5 : 1;
    u8 sfxFired : 1;
    u8 lo : 4;
} WarpstoneFlags;

void warpstone_update(int obj)
{
    extern void objAudioFn_800393f8(int obj, void* state, int sfxId, int a, int b, int c);
    int state;
    int child;
    int advanceResult;
    int target;
    s16* modelVec;
    s16 yawDelta;
    int moveId;

    state = *(int*)&((GameObject*)obj)->extra;
    child = *(int*)state;
    if ((void*)child != NULL)
    {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(*(int*)state);
        *(int*)state = 0;
    }

    {
        extern u32 SClantern_advanceAnimEvents(int obj, f32 moveStepScale);
        advanceResult = SClantern_advanceAnimEvents(obj, lbl_803E54A4);
    }
    if (((GameObject*)obj)->anim.currentMove == 0)
    {
        if (randFn_80080100(100) != 0)
        {
            objAudioFn_800393f8(obj, (void*)(state + 0x14), 0xab, -0x100, -1, 0);
        }
        if (randFn_80080100(500) != 0)
        {
            objAudioFn_800393f8(obj, (void*)(state + 0x14), 0x417, -0x500, -1, 0);
        }
    }

    if (GameBit_Get(0xc7d) != 0)
    {
        if (randFn_80080100(lbl_803DC038) != 0)
        {
            ((WarpstoneFlags*)(state + 0xd5))->lookAtPlayer = (((WarpstoneFlags*)(state + 0xd5))->lookAtPlayer == 0);
        }
        if (((WarpstoneFlags*)(state + 0xd5))->lookAtPlayer == 0)
        {
            ((WarpstoneFlags*)(state + 0xd5))->lookAtPlayer = GameBit_Get(0xa45);
        }
    }

    if (((WarpstoneFlags*)(state + 0xd5))->lookAtPlayer != 0)
    {
        target = Obj_GetPlayerObject();
    }
    else
    {
        target = ObjGroup_FindNearestObject(8, obj, 0);
    }

    ((GameObject*)obj)->anim.localPosY += lbl_803DC040;
    fn_8003ADC4(obj, target, (void*)(state + 0x74), 0x23, 1, lbl_803DC03C);
    modelVec = objModelGetVecFn_800395d8(obj, 0);
    ((GameObject*)obj)->anim.localPosY -= lbl_803DC040;

    if (modelVec != NULL)
    {
        modelVec[1] = modelVec[1] + lbl_803DDBF2;
        modelVec[0] = 0;
        modelVec[0] += lbl_803DC044;
    }

    if (advanceResult != 0)
    {
        ((WarpstoneFlags*)(state + 0xd5))->sfxFired = 0;
        yawDelta = Obj_GetYawDeltaToObject(obj, target, 0);
        yawDelta = yawDelta - lbl_803DDBF0;
        {
            int mag = yawDelta - 0x8000;
            mag = (mag >= 0) ? mag : -mag;
            if (mag > 0x18e3)
        {
            if (yawDelta > 0)
            {
                if (yawDelta > 0xe38)
                {
                    moveId = 0x17;
                }
                else
                {
                    moveId = 0x16;
                }
            }
            else if (yawDelta < -0xe38)
            {
                moveId = 0x19;
            }
            else
            {
                moveId = 0x18;
            }
            if (((GameObject*)obj)->anim.currentMove != moveId)
            {
                ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                    (obj, moveId, lbl_803E5460, 0);
            }
        }
        else if (((GameObject*)obj)->anim.currentMove != 0)
        {
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, 0, lbl_803E5460, 0);
            Sfx_StopFromObject(obj, SFXTRIG_swapstone_move_long);
        }
        else if (randFn_80080100(lbl_803DC048) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_mumble);
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, 0x1b, lbl_803E5460, 0);
        }
        else if (randFn_80080100(lbl_803DC04C) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_long);
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, 0x1a, lbl_803E5460, 0);
        }
        }
    }

    objAnimFn_80038f38(obj, (int*)(state + 0x14));
    characterDoEyeAnims(obj, (void*)(state + 0x44));
    if (GameBit_Get(0x887) == 0)
    {
        ((WarpstoneState*)state)->activated = 0;
    }
    if (((WarpstoneFlags*)(state + 0xd5))->sfxFired != 0)
    {
        return;
    }

    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x17:
    case 0x19:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E546C)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_long);
            ((WarpstoneFlags*)(state + 0xd5))->sfxFired = 1;
        }
        break;
    case 0x16:
    case 0x18:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E546C)
        {
            Sfx_PlayFromObject(obj, SFXbaddie_haga_death);
            ((WarpstoneFlags*)(state + 0xd5))->sfxFired = 1;
        }
        break;
    case 0x1a:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E54A8)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_yawn);
            ((WarpstoneFlags*)(state + 0xd5))->sfxFired = 1;
        }
        break;
    case 0x1b:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E54AC)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_short);
            ((WarpstoneFlags*)(state + 0xd5))->sfxFired = 1;
        }
        break;
    }
}

void warpstone_release(void)
{
}

void warpstone_initialise(void)
{
}

void warpstone_init(int obj, u8* setup)
{
    int state;
    s16 setupYaw;

    state = *(int*)&((GameObject*)obj)->extra;
    setupYaw = (s16)(setup[0x1a] << 8);
    ((GameObject*)obj)->anim.rotX = setupYaw;
    ((GameObject*)obj)->animEventCallback = warpstone_updateMenuAnimObj;
    ((WarpstoneState*)state)->gameBitE = 0x15a;
    ((WarpstoneState*)state)->gameBit10 = 0x886;
    ObjHits_EnableObject((u32)obj);
    if (GameBit_Get(0x887) != 0 && GameBit_Get(0x15a) != 0)
    {
        ((WarpstoneState*)state)->activated = 1;
    }
    else
    {
        ((WarpstoneState*)state)->activated = 0;
    }
    GameBit_Set(((WarpstoneState*)state)->gameBit10, 0);
    *(int*)state = 0;
}
