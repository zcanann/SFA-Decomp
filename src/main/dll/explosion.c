#include "main/dll/explosion_state.h"
#include "main/dll/explosion.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct Dll197State
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    u8 pad6[0x8 - 0x6];
    s16 unk8;
    s16 unkA;
    u8 unkC;
    u8 unkD;
    u8 unkE;
    u8 unkF;
    u8 unk10;
    u8 pad11[0x18 - 0x11];
} Dll197State;


extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_8003b818();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f64 DOUBLE_803e5de0;
extern f32 lbl_803E5DD0;
extern f32 lbl_803E5DD4;
extern f32 lbl_803E5DD8;
extern f32 lbl_803E5DDC;

/*
 * --INFO--
 *
 * Function: dll_197_init
 * EN v1.0 Address: 0x801CA5B4
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801CA6BC
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E513C;
extern f32 lbl_803E5140;
extern f32 lbl_803E5144;
extern f64 lbl_803E5148;



/*
 * --INFO--
 *
 * Function: FUN_801caa30
 * EN v1.0 Address: 0x801CAA30
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CAB68
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801cacd4
 * EN v1.0 Address: 0x801CACD4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CAE40
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cacd4(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801caeac
 * EN v1.0 Address: 0x801CAEAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CAEF8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801caeb0
 * EN v1.0 Address: 0x801CAEB0
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801CAF74
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off


void nwsh_levcon_hitDetect(void)
{
}

void nwsh_levcon_release(void)
{
}

void nwsh_levcon_initialise(void)
{
}


/* 8b "li r3, N; blr" returners. */
int nwsh_levcon_getExtraSize(void) { return 0x0; }
int nwsh_levcon_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5150;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5158;

void nwsh_levcon_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5150);
}


extern void Music_Trigger(int track, int param);
extern int GameBit_Set(int eventId, int value);

void nwsh_levcon_free(int obj)
{
    Music_Trigger(6, 0);
    GameBit_Set(3837, 0);
}

extern int mapGetDirIdx(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(int a, int b, int c, int d);

void nwsh_levcon_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        if (((GameObject*)obj)->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct(0, 0, 0xd1, 0);
            getEnvfxAct(0, 0, 0xd6, 0);
            getEnvfxAct(0, 0, 0x222, 0);
        }
    }
}

void nwsh_levcon_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = (void*)NWSH_levcon_SeqFn;
    unlockLevel(mapGetDirIdx(0x28), 1, 0);
    Music_Trigger(6, 1);
    ((GameObject*)obj)->unkF4 = 1;
    GameBit_Set(0xea2, 1);
    GameBit_Set(0xefd, 1);
}

extern ModgfxInterface** gModgfxInterface;
extern void* gTitleMenuControlInterface;

void dll_199_free(int* obj);

extern void* Obj_GetPlayerObject(void);
extern void fn_80296518(void* player, int a, int b);
extern int getButtonsHeld(int pad);
extern int return0_8005669C(int p);
extern int lbl_803DB610;
extern u32 lbl_803DDBD8;

int NWSH_levcon_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    void* player;
    int i;

    player = Obj_GetPlayerObject();
    if (player != 0)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] != 1)
            {
            }
            else
            {
                fn_80296518(player, 0x10, 1);
                GameBit_Set(0x174, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 4, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 0x1d, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 0x1e, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 0x1f, 1);
                (*gMapEventInterface)->setMode(0xb, 6);
            }
        }
    }
    return 0;
}

int dll_199_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate);
