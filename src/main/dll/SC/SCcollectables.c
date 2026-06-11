#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/SC/SCcollectables.h"
#include "main/objanim.h"
#include "main/objanim_update.h"
#include "main/objfx.h"

typedef struct WarpstoneUpdateMenuAnimObjState
{
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 pad9[0x10 - 0x9];
} WarpstoneUpdateMenuAnimObjState;


extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006bb4();
extern uint FUN_80006c00();
extern uint GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern uint getButtonsJustPressed(int controller);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined8 FUN_80043030();
extern undefined4 FUN_80044404();
extern int playerHasKrazoaSpirit();
extern void padGetAnalogInput(int controller, s8* horizontal, s8* vertical);
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294cd0();

extern undefined DAT_803adca8;
extern undefined4 DAT_803adcb6;
extern undefined4 DAT_803adcba;
extern undefined4 DAT_803adcc3;
extern int lbl_803DC050;
extern int lbl_803DDBF4;
extern undefined4 DAT_803dccb8;
extern undefined4 DAT_803de874;
extern f64 DOUBLE_803e6128;
extern f32 lbl_803DC074;
extern f32 lbl_803E60F8;
extern f32 lbl_803E60FC;
extern f32 lbl_803E6100;
extern f32 lbl_803E6104;
extern f32 lbl_803E6108;
extern f32 lbl_803E610C;
extern f32 lbl_803E6110;
extern f32 lbl_803E6114;
extern f32 lbl_803E6118;
extern f32 lbl_803E611C;
extern f32 lbl_803E6120;
extern f32 lbl_803E6130;

/*
 * --INFO--
 *
 * Function: warpstone_getExtraSize
 * EN v1.0 Address: 0x801D7468
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int warpstone_getExtraSize(void)
{
    return 0xd8;
}

/*
 * --INFO--
 *
 * Function: warpstone_getObjectTypeId
 * EN v1.0 Address: 0x801D7470
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int warpstone_getObjectTypeId(void)
{
    return 0x48;
}

/* void f() { fn_X(N); } pattern. */
extern void loadUiDll(s32);
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

extern int ObjHits_GetPriorityHitWithPosition(int obj, int a, int b, int c, f32* x, f32* y, f32* z);
extern int randFn_80080100(int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objAudioFn_800393f8(int obj, int* p, int a, int b, int c, int d);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E54A0;

void warpstone_hitDetect(int obj)
{
    int* state = ((GameObject*)obj)->extra;
    f32 pos[3];
    int p[3];

    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &pos[0], &pos[1], &pos[2]) != 0)
    {
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        objLightFn_8009a1dc((void*)obj, lbl_803E54A0, p, 1, 0);
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

extern void objRenderFn_8003b8f4(f32);
extern int Obj_GetPlayerObject(void);
extern int fn_80296464(void);
extern int* Obj_GetActiveModel(int player);
extern void fn_80295B2C(int player, f32 x, f32 y, f32 z);
extern void playerRender(int player, int p2, int p3, int p4, int p5, int last);
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
        objRenderFn_8003b8f4(lbl_803E549C);
        player = (void*)Obj_GetPlayerObject();
        if (player != NULL && fn_80296464() != 0)
        {
            model = Obj_GetActiveModel((int)player);
            *(u16*)((char*)model + 24) = (u16)(*(u16*)((char*)model + 24) & ~0x8);
            ObjPath_GetPointWorldPosition(obj, ((WarpstoneUpdateMenuAnimObjState*)state)->unk8, &x, &y, &z, 0);
            fn_80295B2C((int)player, x, y, z);
            playerRender((int)player, p2, p3, p4, p5, -1);
        }
    }
}

extern void loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int locked);
extern void mapUnload(int dirIdx, int flags);
extern MapEventInterface** gMapEventInterface;

#define WARPSTONE_MAP_EVENT_SET(mapId, value) \
    (*gMapEventInterface)->setMode((mapId), (value))
#define WARPSTONE_MAP_EVENT_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setAnimEvent((mapId), (eventId), (value))

int warpstone_handleMenuOptionInput(undefined4 p1, undefined4 p2, int option)
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
            Sfx_PlayFromObject(0, 0x418);
            return 1;
        }
        break;

    case 0x15:
        if (vertical > 0 && lbl_803DC050 == 0)
        {
            Sfx_PlayFromObject(0, 0x418);
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
            Sfx_PlayFromObject(0, 0x418);
            return 1;
        }
        break;

    case 0x17:
        {
            int hasSpirit = playerHasKrazoaSpirit(1, 0);
            if (horizontal > 0 && hasSpirit == 0)
            {
                Sfx_PlayFromObject(0, 0x418);
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
            Sfx_PlayFromObject(0, 0x418);
            return 1;
        }
        break;

    case 0x19:
        if ((getButtonsJustPressed(0) & 0x200) != 0)
        {
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            mapUnload(mapGetDirIdx(0x17), 0x20000000);
            Sfx_PlayFromObject(0, 0x419);
            return 1;
        }
        break;
    }

    return 0;
}

extern int animatedObjGetSeqId(int obj);
extern int fn_80080360(int obj, int seqId);
extern int getCurUiDll(void);
extern int playerFn_801d6d58(void);
extern void AudioStream_CancelPrepared(void);
extern void seqClearTaskTexts(void);
extern void doNothing_8000CF54(int unused);
extern void CMenu_SetFadeCounter(s16 counter);
extern void warpToMap(int mapId, int spawnId);
extern void subtitleFn_8001b700(void);
extern int getDLL16(void);
extern void SHthorntail_updateDustEffects(int obj);
extern f32 timeDelta;

int warpstone_updateMenuAnimObj(int obj, undefined4 p2, int animObj)
{
    int i;
    int child;
    u8 command;
    int state = *(int*)&((GameObject*)obj)->extra;
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
        *(u8*)(state + 0xa) = *(u8*)(state + 0xa) & ~3;
        if (playerFn_801d6d58() != 0)
        {
            *(u8*)(state + 0xa) = *(u8*)(state + 0xa) | 1;
        }
        {
            int hit = (GameBit_Get(0x2e8) != 0 || GameBit_Get(0x123) != 0) ? 1 : 0;
            if (hit)
            {
                *(u8*)(state + 0xa) = *(u8*)(state + 0xa) | 2;
            }
        }
        animUpdate->sequenceEventActive = 0;

        if (GameBit_Get(*(s16*)(state + 0xe)) != 0 && animatedObjGetSeqId(animObj) == 0x35f)
        {
            AudioStream_CancelPrepared();
            seqClearTaskTexts();
            doNothing_8000CF54(0);
            animUpdate->sequenceControlFlags |= 4;
        }
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        command = animUpdate->eventIds[i];
        switch (command)
        {
        case 0x17:
            *(u8*)(state + 0xd4) = *(u8*)(state + 0xd4) | 4;
            Sfx_PlayFromObject(0, 0x420);
            break;

        case 3:
            ((WarpstoneUpdateMenuAnimObjState*)state)->unk8 = 0;
            break;

        case 4:
            ((WarpstoneUpdateMenuAnimObjState*)state)->unk8 = 1;
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
            *(u8*)(state + 9) = *(u8*)(state + 9) ^ 1;
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
                (*(void (**)(int))(*(int*)dll16 + 0x10))(command - 0xd);
            }
            GameBit_Set(*(s16*)(state + 0xe), 1);
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
