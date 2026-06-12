#include "main/game_object.h"
#include "main/objseq.h"

typedef struct ShLevelcontrolState
{
    u8 pad0[0x5 - 0x0];
    u8 unk5;
    u8 pad6[0xC - 0x6];
    f32 unkC;
    s16 unk10;
    s16 unk12;
    u8 pad14[0x18 - 0x14];
} ShLevelcontrolState;


extern u32 GameBit_Get(u32 id);
extern void GameBit_Set(u32 id, u32 value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int Obj_GetPlayerObject(void);
extern void buttonDisable(int a, int b);
extern void padClearAnalogInputY(int a);
extern void padClearAnalogInputX(int a);
extern void gameTextShow(int a);
extern void fn_80088870(void* a, void* b, void* c, void* d);
extern void envFxActFn_800887f8(int a);
extern void skyFn_80088e54(int a, f32 b);
extern void getEnvfxAct(int a, int b, int c, int d);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void SH_LevelControl_setMusic(uint * param_1);
extern void SH_LevelControl_runBloopEvent(int param_1, uint* param_2);
extern void SH_LevelControl_doThornTailEvents(int param_1, uint* param_2);
extern void SH_LevelControl_doEarlyScenes(int param_1, uint* param_2);
extern void objRenderFn_8003b8f4(f32);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 lbl_803E54B4;
extern f32 lbl_803E54C8;
extern f32 timeDelta;
extern u8 lbl_80327618[0x104];

/*
 * --INFO--
 *
 * Function: sh_levelcontrol_update
 * EN v1.0 Address: 0x801D8D20
 * EN v1.0 Size: 2452b
 * EN v1.1 Address: 0x801D90F0
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
void warpstonelift_free(void)
{
}

void warpstonelift_hitDetect(void)
{
}

void warpstonelift_release(void)
{
}

void warpstonelift_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int warpstonelift_getExtraSize(void) { return 0x1; }
int warpstonelift_getObjectTypeId(void) { return 0x0; }
int sh_staff_getExtraSize(void);

extern s32 lbl_803DC058[2];
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern void Music_Trigger(int track, int param);
extern int getSaveGameLoadStatus(void);
extern void timeOfDayFn_80055000(void);
extern f32 lbl_803E54C0;
extern s16 lbl_80327618_ids[];

void sh_levelcontrol_init(int obj);

void warpstonelift_init(int obj, s8* def)
{
    int* state = ((GameObject*)obj)->extra;
    int i;
    *(s16*)obj = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->unkF4 = 0;
    for (i = 0; i < 2; i++)
    {
        if (GameBit_Get(lbl_803DC058[i]) != 0)
        {
            *(u8*)state = (u8)(i + 1);
        }
    }
    switch (*(u8*)state)
    {
    case 0:
    case 2:
        fn_8002B6D8((int)obj, 0, 0, 0, 0, 3);
        break;
    case 1:
        fn_8002B6D8((int)obj, 0, 0, 0, 0, 4);
        break;
    }
}

extern void getYButtonItem(s16 * out);
extern int cMenuGetSelectedItem(void);
extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);

void warpstonelift_update(u8* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    int off;
    char* p;
    int found = 0;
    int count;
    int i;
    s16 item;

    p = *(char**)(obj + 0x58);
    count = *(s8*)(p + 0x10F);
    if (count > 0)
    {
        off = 0;
        for (i = 0; i < count; i++)
        {
            char* o = *(char**)((int)p + (off + 0x100));
            if (*(s16*)(o + 0x44) == 1)
            {
                found = 1;
            }
            off += 4;
        }
    }
    if (found)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
        switch (*state)
        {
        case 0:
        case 1:
            getYButtonItem(&item);
            if ((GameBit_Get(0xC7C) != 0 && cMenuGetSelectedItem() != -1) || item == 0xC7C)
            {
                fn_8002B6D8((int)obj, 0, 0, 0, 0, 4);
            }
            else
            {
                fn_8002B6D8((int)obj, 0, 0, 0, 0, 2);
            }
            if (ObjTrigger_IsSetById((int)obj, 0xC7C) != 0)
            {
                GameBit_Set(0x886, 1);
                GameBit_Set(0xC7D, 1);
                *state = 2;
                fn_8002B6D8((int)obj, 0, 0, 0, 0, 3);
            }
            else if (ObjTrigger_IsSet((int)obj) != 0)
            {
                GameBit_Set(0xC7E, 1);
            }
            break;
        case 2:
            if (ObjTrigger_IsSet((int)obj) != 0)
            {
                GameBit_Set(0x886, 1);
            }
            break;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
    }
}

/* render-with-objRenderFn_8003b8f4 pattern. */
void warpstonelift_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E54C8);
}

void sh_staff_free(int* obj, int p2);
