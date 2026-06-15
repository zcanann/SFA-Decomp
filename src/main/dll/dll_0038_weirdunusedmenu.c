#include "main/audio/sfx_ids.h"
#include "main/dll/debug/dimenu.h"

typedef struct WeirdMenuWork
{
    u8 pad0[0x16 - 0x0];
    u16 unk16;
    u8 pad18[0x52 - 0x18];
    u16 unk52;
    u8 pad54[0x78 - 0x54];
} WeirdMenuWork;

extern undefined8 FUN_80006b84();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80053c98();
extern void saveGame_save();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de3a8;

extern int* gTitleMenuLinkInterface;
extern u32 gameTextGet(int textId);

extern void loadUiDll(int id);
extern u8 framesThisStep;
extern void Sfx_PlayFromObject(int obj, int sfxId);

extern void textureFree(u32);
extern u32 lbl_803DD714, lbl_803DD718, lbl_803DD71C;
extern void warpToMap(int mapId, int spawnId);
extern void cutsceneExit(void);
extern void buttonDisable(int index, int flags);
extern f32 timeDelta;
extern f32 lbl_803E1DF0;
extern s8 lbl_803DD712;
extern s16 lbl_803DD710;
extern u8 lbl_803DD713;
extern u32 lbl_8031AD20[];
extern u32 lbl_803DD720;
extern u32 lbl_8031AD98[];
extern u32 textureLoadAsset(int);

void FUN_8011daf8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

undefined4
FUN_8011dafc(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    byte bVar1;
    undefined8 uVar2;

    FUN_80017a98();
    bVar1 = DAT_803dc070;
    if (3 < DAT_803dc070)
    {
        bVar1 = 3;
    }
    if (('\0' < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - bVar1, DAT_803de3a8 < '\x01'))
    {
        uVar2 = FUN_80006b84(1);
        FUN_80053c98(uVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x60, '\x01', param_11,
                     param_12, param_13, param_14, param_15, param_16);
    }
    return 0;
}

void OptionsScreen_frameEnd(void);

void WeirdUnusedMenu_render(void)
{
}

void WeirdUnusedMenu_frameEnd(void)
{
}

void Dummy39_render(void);

#pragma scheduling off
#pragma peephole off
int WeirdUnusedMenu_run(void)
{
    int selection;
    int action;

    if (lbl_803DD713 == 0)
    {
        selection = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0xc)))();
        action = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x14)))();
        if (selection == 1)
        {
            if (action == 0)
            {
                Sfx_PlayFromObject(0, SFXqu_longsob2);
                loadUiDll(1);
                cutsceneExit();
                buttonDisable(0, 0x300);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXqu_shortsob1);
                lbl_803DD712 = 0;
                lbl_803DD713 = 1;
                ((WeirdMenuWork*)lbl_8031AD20)->unk16 =
                    (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk16 | 0x1000);
                ((WeirdMenuWork*)lbl_8031AD20)->unk52 =
                    (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk52 | 0x1000);
                (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x2c)))();
            }
        }
        else if (selection == 0)
        {
            Sfx_PlayFromObject(0, 0x419);
            loadUiDll(1);
            cutsceneExit();
            buttonDisable(0, 0x300);
        }
    }
    else if (lbl_803DD713 == 1)
    {
        if ((s8)lbl_803DD712 == 0)
        {
            saveGame_save();
        }
        *(char*)&lbl_803DD712 = (int)
        ((f32)(s8)
        lbl_803DD712 + timeDelta
        )
        ;
        if ((f32)(s8)lbl_803DD712 >= lbl_803E1DF0
        )
        {
            lbl_803DD713 = 0;
            ((WeirdMenuWork*)lbl_8031AD20)->unk16 =
                (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk16 & ~0x1000);
            ((WeirdMenuWork*)lbl_8031AD20)->unk52 =
                (u16)(((WeirdMenuWork*)lbl_8031AD20)->unk52 & ~0x1000);
            (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x2c)))();
            (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + 0x18)))(0);
        }
    }

    lbl_803DD710 = (s16)(lbl_803DD710 + (framesThisStep << 3));
    if (lbl_803DD710 > 0x8c)
    {
        lbl_803DD710 = 0x8c;
    }
    return 0;
}

void WeirdUnusedMenu_release(void)
{
    textureFree(lbl_803DD71C);
    textureFree(lbl_803DD718);
    textureFree(lbl_803DD714);
    warpToMap(0, 1);
    (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + 0x8)))();
}

#pragma peephole on
void WeirdUnusedMenu_initialise(void)
{
    lbl_803DD71C = textureLoadAsset(0x31e);
    lbl_803DD718 = textureLoadAsset(0x310);
    lbl_803DD714 = textureLoadAsset(0x31f);
    lbl_803DD720 = gameTextGet(0);
    (*(void (*)(u32*, int, int, u32*, int, int, int, int, int, int, int, int))(*(int*)(*gTitleMenuLinkInterface +
        0x4)))(
        lbl_8031AD20, 2, 0, lbl_8031AD98, 0, 0, 0x5b, 0x45, 0x30, 0xff, 0xd7, 0x3d);
    lbl_803DD710 = 0;
    lbl_803DD713 = 0;
}
