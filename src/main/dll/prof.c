/*
 * prof - title-screen Options menu panel builders.
 *
 * Two entry points populate the Options sub-menus through the title-menu
 * link/item interfaces (gTitleMenuLink/Item). openAudioPanel builds the
 * Audio panel (surround/stereo/mono toggle, music/sfx/voice sliders, and
 * a cheat-gated extra entry); openGeneralPanel builds the General panel,
 * unlocking option/cheat entries based on isCheatUnlocked() and toggling
 * the per-entry "disabled" flag (0x4000) accordingly.
 *
 * lbl_803DBA28 tracks which panel is currently open (-1 = none); a switch
 * away first tears down the previous link (slot +8). Built item handles
 * are cached in lbl_803A87D0[]. lbl_803DD706 is set to 2 by both builders;
 * its exact role is unconfirmed.
 */
#include "main/dll/debug/prof.h"
#include "main/engine_shared.h"
extern int saveFileStruct_isCheatActive();
extern int isCheatUnlocked(u8);
extern int Rcp_GetColorFilterEnabled(void);
extern int* gTitleMenuLinkInterface;
extern int* gTitleMenuItemInterface;
extern s8 lbl_803DBA28;
extern u8 lbl_803DD706;
extern u8* lbl_803DD708;
extern int lbl_803A87D0[8];

typedef struct OptionsMenuPanels
{
    u8 pad00[0x10];
    s8* audioEntries;
    u32 unk_14;
    u8 audioCount;
    u8 pad19[0x20 - 0x19];
    s8* optionEntries;
    u32 unk_24;
    u8 optionCount;
} OptionsMenuPanels;

extern OptionsMenuPanels lbl_8031ACB8;

/* per-entry flag word (entry+0x16): set to grey-out / disable an entry */
#define OPTION_ENTRY_DISABLED 0x4000

void optionsMenu_openAudioPanel(void)
{
    OptionsMenuPanels* panels;
    int item;

    if (lbl_803DBA28 != -1)
    {
        (*(void (**)(void))(*gTitleMenuLinkInterface + 8))();
    }
    lbl_803DBA28 = 1;
    panels = &lbl_8031ACB8;

    if (isCheatUnlocked(2) != 0)
    {
        panels->audioEntries[0x10b] = 5;
        *(u16*)(panels->audioEntries + 0x142) =
            (u16)(*(u16*)(panels->audioEntries + 0x142) & ~OPTION_ENTRY_DISABLED);
        panels->audioEntries[0x146] = 4;
    }
    else
    {
        panels->audioEntries[0x10b] = -1;
        *(u16*)(panels->audioEntries + 0x142) =
            (u16)(*(u16*)(panels->audioEntries + 0x142) | OPTION_ENTRY_DISABLED);
    }

    (*(void (**)(s8*, u8, int, int, int, int, int, int, int, int, int, int))(
        *gTitleMenuLinkInterface + 4))(panels->audioEntries, panels->audioCount, 0, 0, 0, 0,
                                       0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);

    if (OSGetSoundMode() == 1)
    {
        item = (*(int (**)(int, int, int, int, u8))(*gTitleMenuItemInterface + 0xc))(
            0x36c, 0x22, 0, 3, lbl_803DD708[9]);
    }
    else
    {
        item = (*(int (**)(int, int, int, int, int))(*gTitleMenuItemInterface + 0xc))(
            0x36c, 0x22, 0, 3, 2);
    }
    lbl_803A87D0[0] = item;
    lbl_803A87D0[1] =
        (*(int (**)(int, int, int, int, u8, int))(*gTitleMenuItemInterface + 4))(
            0x124, 0xb2, 0, 0x7f, lbl_803DD708[10], 0x3e);
    lbl_803A87D0[2] =
        (*(int (**)(int, int, int, int, u8, int))(*gTitleMenuItemInterface + 4))(
            0x124, 0xcc, 0, 0x7f, lbl_803DD708[11], 0x3e);
    lbl_803A87D0[3] =
        (*(int (**)(int, int, int, int, u8, int))(*gTitleMenuItemInterface + 4))(
            0x124, 0xe6, 0, 0x7f, lbl_803DD708[12], 0x3e);
    *(u8*)(lbl_803A87D0[3] + 4) = (u8)(*(u8*)(lbl_803A87D0[3] + 4) | 0x40);
    lbl_803A87D0[4] = 0;
    lbl_803A87D0[5] = 0;

    if (isCheatUnlocked(2) != 0)
    {
        lbl_803A87D0[5] =
            (*(int (**)(int, int, int, int, int))(*gTitleMenuItemInterface + 0xc))(
                0x3cb, 0x27, 0, (s16)(return0x64_8000A378() - 1), 0);
        *(u8*)(lbl_803A87D0[5] + 4) = (u8)(*(u8*)(lbl_803A87D0[5] + 4) | 0x80);
    }

    (*(void (**)(int, int))(*gTitleMenuItemInterface + 0x20))(lbl_803A87D0[0], 1);
    lbl_803DD706 = 2;
}

void optionsMenu_openGeneralPanel(void)
{
    OptionsMenuPanels* panels;
    int lastUnlocked;
    int entryOffset;
    int cheatId;
    int* slot;
    int cheatId2;
    int entryOffset2;
    int lastUnlocked2;

    if (lbl_803DBA28 != -1)
    {
        (*(void (**)(void))(*gTitleMenuLinkInterface + 8))();
    }
    lbl_803DBA28 = 2;
    panels = &lbl_8031ACB8;

    lastUnlocked = -1;
    cheatId = 3;
    entryOffset = 0xb4;
    do
    {
        if (isCheatUnlocked((u8)(cheatId - 2)) != 0)
        {
            panels->optionEntries[entryOffset - 0x21] = cheatId;
            *(u16*)(panels->optionEntries + entryOffset + 0x16) =
                (u16)(*(u16*)(panels->optionEntries + entryOffset + 0x16) & ~OPTION_ENTRY_DISABLED);
            lastUnlocked = cheatId;
        }
        else
        {
            panels->optionEntries[entryOffset - 0x21] = lastUnlocked;
            *(u16*)(panels->optionEntries + entryOffset + 0x16) =
                (u16)(*(u16*)(panels->optionEntries + entryOffset + 0x16) | OPTION_ENTRY_DISABLED);
        }
        entryOffset -= 0x3c;
        cheatId--;
    }
    while (cheatId > 1);

    lastUnlocked2 = 1;
    cheatId2 = 2;
    entryOffset2 = 0x78;
    do
    {
        if (isCheatUnlocked((u8)(cheatId2 - 2)) != 0)
        {
            panels->optionEntries[entryOffset2 + 0x1a] = lastUnlocked2;
            *(u16*)(panels->optionEntries + entryOffset2 + 0x16) =
                (u16)(*(u16*)(panels->optionEntries + entryOffset2 + 0x16) & ~OPTION_ENTRY_DISABLED);
            lastUnlocked2 = cheatId2;
        }
        entryOffset2 += 0x3c;
        cheatId2++;
    }
    while (cheatId2 < 4);

    (*(void (**)(s8*, u8, int, int, int, int, int, int, int, int, int, int))(
        *gTitleMenuLinkInterface + 4))(panels->optionEntries, panels->optionCount, 0, 0, 0, 0,
                                       0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);

    lbl_803A87D0[0] =
        (*(int (**)(int, int, int, int, u8))(*gTitleMenuItemInterface + 0xc))(
            0x366, 0x22, 0, 1, lbl_803DD708[6]);
    slot = &lbl_803A87D0[0];
    slot[1] =
        (*(int (**)(int, int, int, int, s16))(*gTitleMenuItemInterface + 0xc))(
            0x36b, 0x23, 0, 1, (s16)(lbl_803DD708[8] == 0));

    cheatId = 0;
    do
    {
        if (isCheatUnlocked((u8)cheatId) != 0)
        {
            if (cheatId == 1)
            {
                slot[2] = (*(int (**)(int, int, int, int, s16))(*gTitleMenuItemInterface + 0xc))(
                    0x507, cheatId + 0x24, 0, 1, Rcp_GetColorFilterEnabled());
            }
            else
            {
                slot[2] = (*(int (**)(int, int, int, int, s16))(*gTitleMenuItemInterface + 0xc))(
                    0x36b, cheatId + 0x24, 0, 1, (s16)(saveFileStruct_isCheatActive((u8)cheatId) == 0));
            }
        }
        slot++;
        cheatId++;
    }
    while (cheatId <= 1);

    (*(void (**)(int, int))(*gTitleMenuItemInterface + 0x20))(lbl_803A87D0[0], 1);
    lbl_803DD706 = 2;
}
