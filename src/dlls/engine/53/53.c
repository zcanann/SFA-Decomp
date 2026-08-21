#include "dlls/object_descriptor.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/FRONT/frontend_control.h"
#include "main/dll/dll_0035_saveselectscreen.h"
#include "main/textrender_api.h"
#include "track/intersect_hud_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/pad.h"
#include "main/screen_transition.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/frame_timing.h"
#include "main/audio/music_api.h"
#include "main/dll/FRONT/title_menu.h"
#include "main/texture.h"
#include "main/mm.h"
#include "main/debug.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/dll/front_game_text_box_api.h"
#include "main/gametext_api.h"
#include "main/gametext_show_api.h"
#include "main/model_engine.h"
#include "main/map_load.h"
#include "main/fileio.h"
#include "main/mapEventTypes.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/savegame.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/dll/player_status.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "string.h"
#include "main/audio/sfx_play_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_str_api.h"
#include "main/pad.h"
#include "main/dll/dll_43.h"

/*
 * frontend_control - save-file-select screen behaviour for the front end.
 *
 * saveFileSelect_checkCheatCodes() watches controller 0 while a button
 * (mask 0x10) is held and matches input against two nibble-packed button
 * sequences: a debug-text unlock sequence and a per-slot save cheat. Each
 * sequence is 5 entries long; a 16-frame input timer resets a partial
 * match. Completing the debug sequence sets enableDebugText; completing
 * the save sequence stamps chaptersUnlocked=5 on the current save slot.
 *
 * saveSelect_drawText() renders the selected slot's summary: the two side
 * textures, the slot name, completion percent, formatted play time
 * (HH:MM:SS derived from playTimeSeconds), life count and magic count.
 */

#define CHEAT_SEQUENCE_LEN  5
#define CHEAT_INPUT_TIMEOUT 0xF
#define SECONDS_PER_HOUR    3600
#define SECONDS_PER_MINUTE  60

extern void* gSaveSelectTextures[4];

void saveFileSelect_checkCheatCodes(void)
{
    u32 held;
    u32 pressed;
    u32 nibbles;
    u32 hi;
    u32 midHi;
    u32 low;
    u32 midLow;

    if (saveFileSelect_debugCheatProgress != 0 || saveFileSelect_saveCheatProgress != 0)
    {
        saveFileSelect_cheatInputTimer++;
        if (saveFileSelect_cheatInputTimer > CHEAT_INPUT_TIMEOUT)
        {
            saveFileSelect_debugCheatProgress = 0;
            saveFileSelect_saveCheatProgress = 0;
            saveFileSelect_cheatInputTimer = 0;
        }
    }
    held = getButtonsHeld(0);
    if ((held & PAD_TRIGGER_Z) == 0)
        return;

    if (saveFileSelect_saveCheatProgress == 0)
    {
        pressed = (u16)getButtonsJustPressed(0);
        hi = (int)(pressed & 0xF000) >> 8;
        midHi = (pressed & 0xF00) << 4;
        low = (pressed & 0xF) << 8;
        midLow = (int)(pressed & 0xF0) >> 4;
        nibbles = hi | (midHi | (low | midLow));
        if ((int)(nibbles & saveFileSelect_debugCheatSequence[saveFileSelect_debugCheatProgress]) != 0)
        {
            saveFileSelect_debugCheatProgress++;
            saveFileSelect_cheatInputTimer = 0;
        }
        if (saveFileSelect_debugCheatProgress == CHEAT_SEQUENCE_LEN)
        {
            enableDebugText = 1;
            Sfx_PlayFromObject(0, SFXTRIG_cam90_c);
        }
    }
    if (saveFileSelect_debugCheatProgress != 0)
        return;

    pressed = (u16)getButtonsJustPressed(0);
    hi = (int)(pressed & 0xF000) >> 8;
    midHi = (pressed & 0xF00) << 4;
    low = (pressed & 0xF) << 8;
    midLow = (int)(pressed & 0xF0) >> 4;
    nibbles = hi | (midHi | (low | midLow));
    if ((int)(nibbles & saveFileSelect_slotCheatSequence[saveFileSelect_saveCheatProgress]) != 0)
    {
        saveFileSelect_saveCheatProgress++;
        saveFileSelect_cheatInputTimer = 0;
    }
    if (saveFileSelect_saveCheatProgress == CHEAT_SEQUENCE_LEN)
    {
        saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].chaptersUnlocked = 5;
        saveFileSelect_saveDirty = 1;
        Sfx_PlayFromObject(0, SFXTRIG_cam90_c);
    }
}

void saveSelect_drawText(int unused, int alpha)
{
    char buf[16];
    u32 secs;
    u32 hours;
    int rem;
    int minutes;
    int seconds;

    drawTexture(gSaveSelectTextures[1], 282.0f, 142.0f, alpha, 0x100);
    drawTexture(gSaveSelectTextures[2], 322.0f, 142.0f, alpha, 0x100);
    gameTextSetColor(0xff, 0xff, 0xff, alpha);

    saveFileSelect_saveSlots =
        saveFileSelect_saveSlotsBase; /* retail draw path resets the working slot pointer to the base */
    gameTextShowStr((char*)&saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex], 0x41, 0, 0);

    sprintf(buf, sFrontendCompletionPercentFormat,
            saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].completionPercent);
    gameTextShowStr(buf, 0x42, 0, 0);

    secs = saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].playTimeSeconds;
    hours = secs / SECONDS_PER_HOUR;
    rem = secs - hours * SECONDS_PER_HOUR;
    minutes = rem / SECONDS_PER_MINUTE;
    minutes = (u8)minutes; /* truncation must persist into the seconds remainder below */
    seconds = rem - minutes * SECONDS_PER_MINUTE;
    sprintf(buf, sFrontendTimeFormat, hours, (u32)(u8)minutes, (u32)(u8)seconds);
    gameTextShowStr(buf, 0x43, 0, 0);

    sprintf(buf, sFrontendSingleDigitFormat, saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].rankB);
    gameTextShowStr(buf, 0x44, 0, 0);

    sprintf(buf, sFrontendSingleDigitFormat, saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].rankA);
    gameTextShowStr(buf, 0x45, 0, 0);
}

/*
 * dll_43 - save-select "confirm slot" action (companion to the save-select
 * screen DLL 0x35).
 *
 * saveSelectSetSlot() is invoked from saveSelectScreen when the player
 * confirms a slot. Slot 0 is the "back" choice: if a save already exists
 * (gSaveGameEnabled) it returns to the choose-slot screen, otherwise it plays
 * the rotation sfx, kicks off screen transition 0x14, and arms the
 * pending-action flags (gSaveSelectQuitPending/CF). Any other slot starts a new
 * game: it flags the choice, plays the confirm sfx, runs transition 0x14,
 * tears down the four title-menu control sub-objects via vtable slot 7,
 * and records the chosen value (gSaveSelectChapter).
 *
 * The lbl_803DD6xx / gSaveGameEnabled state words are shared with DLL 0x35
 * (its home TU); 0x23 here matches that TU's pending-action value.
 */

extern u8 gSaveSelectChapter;
extern u8 gSaveSelectQuitPending;
extern u8 gSaveSelectLaunchPending;
extern s8 gSaveSelectExitTimer;

void saveSelectSetSlot(int slot, int value)
{
    if (slot == 0)
    {
        if (gSaveGameEnabled != 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down); /* back sfx (unnamed in sfx_ids.h) */
            saveSelectGoToChooseSlot(0);
        }
        else
        {
            Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
            (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_HUD);
            gSaveSelectExitTimer = 0x23;
            gSaveSelectQuitPending = 1;
        }
    }
    else
    {
        gSaveSelectLaunchPending = 1;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up); /* confirm sfx (unnamed in sfx_ids.h) */
        (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_BLACK);
        gTitleMenuControlInterface->vtable->func0A(0);
        gTitleMenuControlInterface->vtable->func0A(1);
        gTitleMenuControlInterface->vtable->func0A(2);
        gTitleMenuControlInterface->vtable->func0A(3);
        gSaveSelectExitTimer = 0x23;
        gSaveSelectChapter = value;
    }
}

u16 gSaveSelectSlotTextIds[4] = {0x23, 0x24, 0x25, 0};
u8 gSaveSelectInfoTextIds[3] = {0x21, 0x20, 0x1F};
s8 gSaveSelectPanelIndex = -1;
int gSaveSelectInfoStartSlot[1] = {0};
int lbl_803DBA00[1] = {0};
s16 gSaveSelectTextureIds[4] = {0x31D, 0x31F, 0x31E, 0};
char sFrontendCompletionPercentFormat[] = "%1d%";
char sFrontendSingleDigitFormat[] = "%1d";
char sFrontendFoxName[] = "FOX";
char sFrontendStringFormat[] = "%s";
char lbl_803DBA20[4] = "";
char sFrontendPercentFormat[] = "%d%";

typedef enum SaveSelectPanelId
{
    SAVE_SELECT_PANEL_CHOOSE_SLOT = 0,
    SAVE_SELECT_PANEL_OPEN_FILE = 1,
    SAVE_SELECT_PANEL_SLOT_ACTION = 2,
    SAVE_SELECT_PANEL_CONFIRM_ERASE = 3,
    SAVE_SELECT_PANEL_CHAPTER_SELECT = 4
} SaveSelectPanelId;

typedef struct SaveSelectPanel
{
    TitleMenuTextEntry* entries;
    u8 count;
    u8 pad5;
    u16 textIdA;
    u16 textIdB;
    u8 unkA[2];
} SaveSelectPanel;

#define SAVE_SELECT_TEXT_BUFFER_COUNT 10

#define SAVESELECTSCREEN_TEXTURE_ID 0x2dd

s8 gSaveSelectExitTimer;
s8 gSaveSelectRefreshCounter;
u8 gSaveSelectLaunchPending;
u8 gSaveSelectQuitPending;
void* gSaveSelectTexture;
u8 gSaveSelectMenuItemActive;
u8 gSaveSelectChapter;
int gSaveSelectLastSlot;
u8 saveFileSelect_cheatInputTimer;
u8 saveFileSelect_saveCheatProgress;
u8 saveFileSelect_debugCheatProgress;
TitleMenuItem* gSaveSelectMenuItem;
u8 lbl_803DD6B4;
FrontendSaveSlot* saveFileSelect_saveSlots;
void* lbl_803DD6AC;
FrontendSaveSlot* saveFileSelect_saveSlotsBase;
u8 saveFileSelect_saveDirty;
s8 saveFileSelect_currentSlotIndex;
void* gSaveSelectCachedText;
extern void* lbl_8031A804[4];
extern SaveSelectPanel gSaveSelectPanels[];
extern u8 lbl_8031A7F8[];
static void saveSelectGoToChapterSelect(void);

void* gSaveSelectTextBuffers[SAVE_SELECT_TEXT_BUFFER_COUNT];
extern char sSaveGameBinPathFormat[];

static void saveSelectOpenFile(int sel, int slot)
{
    TitleMenuTextEntry** pp;
    int off;

    off = gSaveSelectPanelIndex * 0xc;
    pp = (TitleMenuTextEntry**)gSaveSelectPanels;
    if (sel == 0)
    {
        if (gSaveSelectMenuItem != NULL)
        {
            gTitleMenuItemInterface->vtable->free(gSaveSelectMenuItem);
            gSaveSelectMenuItem = NULL;
        }
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down);
        saveSelectGoToChooseSlot(0);
    }
    else
    {
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
        if (gSaveSelectMenuItemActive == 0)
        {
            if (slot == 0)
            {
                saveSelectGoToChapterSelect();
            }
            else
            {
                (*(TitleMenuTextEntry**)((char*)pp + off))->flags =
                    (u16)((*(TitleMenuTextEntry**)((char*)pp + off))->flags | TITLE_MENU_TEXT_ENTRY_HIDDEN);
                (*(TitleMenuTextEntry**)((char*)pp + off))[1].upLink = -1;
                (*(TitleMenuTextEntry**)((char*)pp + off))[1].textId = 984;
                gSaveSelectMenuItemActive = 1;
                gSaveSelectMenuItem = gTitleMenuItemInterface->vtable->createWithWindow(983, 41, 0, 1, 0);
                gTitleMenuItemInterface->vtable->setEnabled(gSaveSelectMenuItem, 1);
                gTitleMenuLinkInterface->vtable->copyItems(*(TitleMenuTextEntry**)((char*)pp + off));
            }
        }
        else
        {
            if ((u8)gTitleMenuItemInterface->vtable->getValue(gSaveSelectMenuItem) == 1)
            {
                gplaySaveGame((u8)saveFileSelect_currentSlotIndex);
            }
            gTitleMenuItemInterface->vtable->free(gSaveSelectMenuItem);
            gSaveSelectMenuItem = NULL;
            saveSelectGoToChooseSlot(0);
        }
    }
}
static void saveFileSelect_init(int sel, int slot)
{
    int i;

    saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
    if (sel == 0)
    {
        Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
        (*gScreenTransitionInterface)->start(20, SCREEN_TRANSITION_HUD);
        gSaveSelectExitTimer = 0x23;
        gSaveSelectQuitPending = 1;
    }
    else if (sel != -1)
    {
        if (sel == 1)
        {
            saveFileSelect_currentSlotIndex = slot;
            i = (s8)(u8)(s8)slot;
            if (saveFileSelect_saveSlots[i].isOccupied == 0)
            {
                loadUiDll(6);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
                if (gSaveSelectPanelIndex != -1)
                {
                    gTitleMenuLinkInterface->vtable->free();
                }
                gSaveSelectPanelIndex = SAVE_SELECT_PANEL_OPEN_FILE;
                gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries[0].flags =
                    (u16)(gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries[0].flags &
                          ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
                gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries[1].upLink = 0;
                gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries[1].textId = 982;
                gSaveSelectMenuItemActive = 0;
                gTitleMenuLinkInterface->vtable->setup(gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries,
                                                       gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].count, 0, NULL,
                                                       5, 4, 20, 200, 255, 255, 255, 255);
                gTitleMenuLinkInterface->vtable->setSelected(0);
                saveFileSelect_debugCheatProgress = 0;
                saveFileSelect_saveCheatProgress = 0;
                saveFileSelect_cheatInputTimer = 0;
                gSaveSelectRefreshCounter = 2;
            }
        }
    }
}

static void saveSelectSetupMenuItems(SaveSelectPanel* p)
{
    int i;

    for (i = 0; i < p->count; i++)
    {
        saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
        if (saveFileSelect_saveSlots[i].isOccupied == 0)
        {
            p->entries[i].textId = 0x39d;
            p->entries[i].flags = (u16)(p->entries[i].flags & ~0x1);
            p->entries[i].flags = (u16)(p->entries[i].flags | 0x2);
            p->entries[i].textureAssetId = -1;
        }
        else
        {
            p->entries[i].textId = i;
            p->entries[i].flags = (u16)(p->entries[i].flags & ~0x2);
            p->entries[i].flags = (u16)(p->entries[i].flags | 0x1);
            p->entries[i].textureAssetId = -1;
        }
    }
}

static void saveSelectGoToChapterSelect(void)
{
    int i;
    SaveSelectPanel* panel;

    if (gSaveSelectPanelIndex != -1)
    {
        gTitleMenuLinkInterface->vtable->free();
    }
    if (saveFileSelect_saveDirty != 0 || gSaveGameEnabled == 0)
    {
        gSaveSelectPanelIndex = SAVE_SELECT_PANEL_CHAPTER_SELECT;
        panel = &gSaveSelectPanels[SAVE_SELECT_PANEL_CHAPTER_SELECT];
        for (i = 0; i < 6; i++)
        {
            if (i > saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].chaptersUnlocked)
            {
                panel->entries[i].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
            }
            else
            {
                panel->entries[i].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;
            }
            if (i <= saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].chaptersUnlocked + -1 && i < 5)
            {
                panel->entries[i].downLink = (s8)(i + 1);
            }
            else
            {
                panel->entries[i].downLink = -1;
            }
        }
        gTitleMenuLinkInterface->vtable->setup(panel->entries, panel->count, 0, lbl_8031A7F8, 5, 4, 0, 0, 0, 0, 0,
                                               0);
        gSaveSelectRefreshCounter = 2;
    }
    else
    {
        gSaveSelectLaunchPending = 1;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
        (*gScreenTransitionInterface)->start(20, SCREEN_TRANSITION_BLACK);
        gTitleMenuControlInterface->vtable->func0A(0);
        gTitleMenuControlInterface->vtable->func0A(1);
        gTitleMenuControlInterface->vtable->func0A(2);
        gTitleMenuControlInterface->vtable->func0A(3);
        gSaveSelectExitTimer = 0x23;
        gSaveSelectChapter = 0;
    }
}
static void saveSelect_loadSlotSummaries(void)
{
    int i;
    FrontendSaveSlot* slots = saveFileSelect_saveSlotsBase;
    saveFileSelect_saveSlots = slots;
    gSaveSelectInfoStartSlot[0] = 0;
    if (gSaveGameEnabled != 0)
    {
        saveSelect_getInfo(slots);
        if (gSaveGameEnabled != 0)
        {
            gSaveSelectInfoStartSlot[0] = 3;
        }
    }
    for (i = gSaveSelectInfoStartSlot[0]; i < 3; i++)
    {
        sprintf(saveFileSelect_saveSlots[i].name, sFrontendStringFormat, lbl_803DBA20);
        saveFileSelect_saveSlots[i].rankA = 0;
        saveFileSelect_saveSlots[i].rankB = 0;
        saveFileSelect_saveSlots[i].completionPercent = 0;
        saveFileSelect_saveSlots[i].playTimeSeconds = 0;
        saveFileSelect_saveSlots[i].chaptersUnlocked = 0;
    }
}

void saveSelectGoToChooseSlot(int arg)
{
    SaveSelectPanel* p;
    u8 i;

    if (gSaveSelectPanelIndex != -1)
    {
        gTitleMenuLinkInterface->vtable->free();
    }
    gSaveSelectPanelIndex = SAVE_SELECT_PANEL_CHOOSE_SLOT;
    saveFileSelect_currentSlotIndex = 0;
    {
        SaveSelectPanel* tmp = (SaveSelectPanel*)(&gSaveSelectPanels[SAVE_SELECT_PANEL_CHOOSE_SLOT]);
        p = tmp;
    }

    saveSelect_loadSlotSummaries();
    saveSelectSetupMenuItems(p);

    for (i = 0; i < 1; i++)
    {
        if (gSaveSelectInfoStartSlot[i] != 3)
        {
            p->entries[0].upLink = 3;
        }
        else
        {
            p->entries[0].upLink = -1;
        }
    }

    gTitleMenuLinkInterface->vtable->setup(p->entries, p->count, 0, NULL, 5, 4, 0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);

    gTitleMenuLinkInterface->vtable->setSelected(0);

    gSaveSelectRefreshCounter = 2;
    if (gSaveGameEnabled == 0)
    {
        saveSelectGoToChapterSelect();
    }
}
static void saveSelectScreenFree(int runExitCallback)
{
    void** p;
    int i;
    void* zero;

    if (lbl_8031A804[0] != NULL)
    {
        mm_free(lbl_8031A804[0]);
        lbl_8031A804[0] = NULL;
    }
    gSaveSelectCachedText = 0;
    if (gSaveSelectPanelIndex != -1)
    {
        gTitleMenuLinkInterface->vtable->free();
        gSaveSelectPanelIndex = -1;
    }
    if (saveFileSelect_saveSlotsBase != NULL)
    {
        mm_free(saveFileSelect_saveSlotsBase);
        saveFileSelect_saveSlotsBase = NULL;
    }
    if (lbl_803DD6AC != NULL)
    {
        mm_free(lbl_803DD6AC);
        lbl_803DD6AC = NULL;
    }

    p = gSaveSelectTextures;
    zero = NULL;
    for (i = 0; i < 4; i++)
    {
        if (p[i] != NULL)
        {
            textureFree((Texture*)(p[i]));
            p[i] = zero;
        }
    }

    textureFree((Texture*)(gSaveSelectTexture));
    if (runExitCallback != 0)
    {
        doNothing_onSaveSelectScreenExit();
    }
    if (gSaveSelectMenuItem != NULL)
    {
        gTitleMenuItemInterface->vtable->free(gSaveSelectMenuItem);
        gSaveSelectMenuItem = NULL;
    }
}

void SaveSelectScreen_render(int param);
void SaveSelectScreen_frameEnd_nop(void);
int SaveSelectScreen_run(void);
void SaveSelectScreen_release(void);
void SaveSelectScreen_initialise(void);

void SaveSelectScreen_render(int param)
{
    SaveSelectPanel* panel;
    int progress;
    int alpha;
    u8 fadeAlpha;

    panel = &gSaveSelectPanels[gSaveSelectPanelIndex];
    gameTextSetDrawFunc(titleScreenTextDrawFunc);
    progress = (int)(255.0f - (*gScreenTransitionInterface)->getProgress());
    if ((u8)progress < 0x80) {
        f32 conv = (f32)(int)((u8)progress * 0x86);
        titleScreenPositionElements(40.0f, 254.0f - conv / 128.0f);
        alpha = 0;
    } else {
        titleScreenPositionElements(40.0f, 120.0f);
        alpha = ((int)((u8)progress & 0x7f) << 1) & 0xff;
    }
    titleScreenDrawMenuFrame(alpha, (u8)(gSaveSelectPanelIndex == SAVE_SELECT_PANEL_CONFIRM_ERASE), 0);
    switch (gSaveSelectPanelIndex)
    {
    case SAVE_SELECT_PANEL_OPEN_FILE:
    {
        u8* infoTextIds;
        int taskTextOffset;
        int slotCount;
        int infoIndex;
        FrontendSaveSlot* slot;

        saveSelect_drawText(param, alpha);
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        slotCount = 0;
        slot = &saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex];
        while (slotCount < 3 && slot->taskTexts[slotCount] != NULL)
        {
            slotCount++;
        }
        infoIndex = 0;
        infoTextIds = gSaveSelectInfoTextIds + (u8)(3 - slotCount);
        taskTextOffset = 0;
        while (infoIndex < slotCount)
        {
            gameTextAppendStr(
                ((FrontendSaveSlot*)((char*)saveFileSelect_saveSlots +
                                     saveFileSelect_currentSlotIndex * 0x24 + taskTextOffset))
                    ->taskTexts[0],
                *infoTextIds);
            infoTextIds++;
            taskTextOffset += 4;
            infoIndex++;
        }
        if (gSaveSelectMenuItem != NULL)
        {
            gTitleMenuItemInterface->vtable->render(gSaveSelectMenuItem, 0, alpha);
        }
        break;
    }
    case SAVE_SELECT_PANEL_CONFIRM_ERASE:
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextShow(0x324);
        break;
    case SAVE_SELECT_PANEL_CHOOSE_SLOT:
    {
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gTitleMenuLinkInterface->vtable->getSelected();
        if (gSaveGameEnabled != 0)
        {
            int slotIndex;
            int slotOffset;

            saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
            slotIndex = 0;
            slotOffset = 0;
            do
            {
                sprintf(gSaveSelectTextBuffers[slotIndex], sFrontendPercentFormat,
                        ((FrontendSaveSlot*)((u8*)saveFileSelect_saveSlots + slotOffset))->completionPercent);
                gameTextSetColor(0xff, 0xff, 0xff, alpha);
                gameTextAppendStr(gSaveSelectTextBuffers[slotIndex], gSaveSelectSlotTextIds[slotIndex]);
                slotOffset += sizeof(FrontendSaveSlot);
                slotIndex++;
            } while (slotIndex < FRONTEND_SAVE_SLOT_COUNT);
        }
        break;
    }
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    if (panel->textIdA != 0xffff)
    {
        fadeAlpha = alpha;
        if (fadeAlpha < 0x7f)
        {
            gameTextSetColor(0xff, 0xff, 0xff, (u8)(0xff - (fadeAlpha << 1)));
            gameTextShow(0x331);
        }
        else
        {
            gameTextSetColor(0xff, 0xff, 0xff, (u8)((fadeAlpha - 0x7f) << 1));
            gameTextShow(panel->textIdA);
        }
    }
    if (panel->textIdB != 0xffff)
    {
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextShow(panel->textIdB);
    }
    gTitleMenuLinkInterface->vtable->setOpacity(progress);
    gTitleMenuLinkInterface->vtable->render(param);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(0);
    if ((gSaveSelectRefreshCounter -= 1) < 0)
    {
        gSaveSelectRefreshCounter = 0;
    }
}

void SaveSelectScreen_frameEnd_nop(void)
{
}

int SaveSelectScreen_run(void)
{
    char buf[32];
    s8 timer;
    int frames;
    int sel;
    int slot;
    int prev;
    char* data;
    SaveSelectPanel* panel;
    int btn;
    SaveGameCharacterPosition* flagPtr;

    timer = gSaveSelectExitTimer;
    frames = framesThisStep;
    if (frames > 3)
    {
        frames = 3;
    }
    if (timer > 0)
    {
        gSaveSelectExitTimer -= frames;
    }
    if ((*gScreenTransitionInterface)->isFinished() == 0)
    {
        gTitleMenuLinkInterface->vtable->resetTimers();
        gSaveSelectRefreshCounter = 4;
    }
    if (gSaveSelectLaunchPending != 0 || gSaveSelectQuitPending != 0)
    {
        if ((timer <= 12 || gSaveSelectExitTimer > 12) && gSaveSelectExitTimer <= 0)
        {
            if (gSaveSelectLaunchPending != 0)
            {
                n_attractmode_releaseMovieBuffers();
                if (gSaveGameEnabled != 0)
                {
                    trySaveGame(*(u8*)&saveFileSelect_currentSlotIndex);
                }
                else
                {
                    gplayNewGame(0, -1);
                }
                saveSelectScreenFree(1);
                titleScreenDisableActors();
                prev = mmSetFreeDelay(0);
                mapUnload(0x3d, 0x20000000);
                mmSetFreeDelay(prev);
                Music_Trigger(MUSICTRIG_cldrnr_tune1_be, 0);
                Music_Trigger(MUSICTRIG_windydocks, 0);
                if (gSaveSelectChapter != 0)
                {
                    gplayNewGame(sFrontendFoxName, *(u8*)&saveFileSelect_currentSlotIndex);
                    (*gMapEventInterface)->setCharacter(1);
                    flagPtr = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
                    flagPtr->mapDataFileId = -1;
                }
                if (gSaveSelectChapter > 1)
                {
                    sprintf(buf, sSaveGameBinPathFormat, gSaveSelectChapter);
                    data = loadFileByPath(buf, 0, 0);
                    if (data != NULL)
                    {
                        memcpy(gSaveGameWorkBuffer, data, 0x6ec);
                    }
                }
                else
                {
                    saveSetOverrideHealth(0);
                }
                (*gMapEventInterface)->gotoSavegame();
            }
            else
            {
                saveSelectScreenFree(0);
                gSaveGameEnabled = 0xfe;
                loadUiDll(4);
            }
        }
        return gSaveSelectExitTimer <= 12;
    }
    if (gSaveSelectPanelIndex == SAVE_SELECT_PANEL_CONFIRM_ERASE)
    {
        btn = getButtonsJustPressed(0);
        if (btn & PAD_BUTTON_A)
        {
            saveSelectGoToChapterSelect();
        }
        else if (btn & PAD_BUTTON_B)
        {
            (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_HUD);
            gSaveSelectExitTimer = 0x23;
            gSaveSelectQuitPending = 1;
        }
    }
    else
    {
        sel = gTitleMenuLinkInterface->vtable->update();
        slot = gTitleMenuLinkInterface->vtable->getSelected();
        if (slot != gSaveSelectLastSlot)
        {
            Sfx_PlayFromObject(0, SFXTRIG_warningloop);
        }
        gSaveSelectLastSlot = slot;
        if (gSaveSelectMenuItem != NULL)
        {
            gTitleMenuItemInterface->vtable->update(gSaveSelectMenuItem);
        }
        if (sel != -1 || gSaveSelectPanelIndex == SAVE_SELECT_PANEL_CHOOSE_SLOT)
        {
            switch (gSaveSelectPanelIndex)
            {
            case SAVE_SELECT_PANEL_CHOOSE_SLOT:
                saveFileSelect_init(sel, slot);
                break;
            case SAVE_SELECT_PANEL_OPEN_FILE:
                saveSelectOpenFile(sel, slot);
                break;
            case SAVE_SELECT_PANEL_SLOT_ACTION:
                if (sel == 0)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down);
                    saveFileSelect_currentSlotIndex = slot;
                    if (gSaveSelectPanelIndex != -1)
                    {
                        gTitleMenuLinkInterface->vtable->free();
                    }
                    gSaveSelectPanelIndex = SAVE_SELECT_PANEL_OPEN_FILE;
                    panel = &gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE];
                    panel->entries[0].flags = (u16)(panel->entries[0].flags & ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
                    panel->entries[1].upLink = 0;
                    panel->entries[1].textId = 0x3d6;
                    gSaveSelectMenuItemActive = 0;
                    gTitleMenuLinkInterface->vtable->setup(panel->entries, panel->count, 0, NULL, 5, 4, 0x14, 0xc8,
                                                           0xff, 0xff, 0xff, 0xff);
                    gTitleMenuLinkInterface->vtable->setSelected(0);
                    saveFileSelect_debugCheatProgress = 0;
                    saveFileSelect_saveCheatProgress = 0;
                    saveFileSelect_cheatInputTimer = 0;
                    gSaveSelectRefreshCounter = 2;
                }
                else if (sel == 1)
                {
                    gSaveSelectLaunchPending = 1;
                    (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_HUD);
                    gTitleMenuControlInterface->vtable->func0A(0);
                    gTitleMenuControlInterface->vtable->func0A(1);
                    gTitleMenuControlInterface->vtable->func0A(2);
                    gTitleMenuControlInterface->vtable->func0A(3);
                    gSaveSelectExitTimer = 0x23;
                }
                break;
            case SAVE_SELECT_PANEL_CHAPTER_SELECT:
                saveSelectSetSlot(sel, slot);
                break;
            }
        }
    }
    if (gSaveSelectPanelIndex == SAVE_SELECT_PANEL_OPEN_FILE)
    {
        saveFileSelect_checkCheatCodes();
    }
    return 0;
}

void SaveSelectScreen_release(void)
{
    int i;
    void* zero;

    zero = NULL;
    i = 0;
    do
    {
        mm_free(gSaveSelectTextBuffers[i]);
        gSaveSelectTextBuffers[i] = zero;
        i++;
    } while (i < SAVE_SELECT_TEXT_BUFFER_COUNT);
}

void SaveSelectScreen_initialise(void)
{
    int i;
    SaveSelectPanel* panel;

    saveFileSelect_saveSlotsBase = mmAlloc(sizeof(FrontendSaveSlot) * FRONTEND_SAVE_SLOT_COUNT, 5, 0);
    lbl_803DD6AC = mmAlloc(sizeof(FrontendSaveSlot) * FRONTEND_SAVE_SLOT_COUNT, 5, 0);
    gSaveSelectTexture = textureLoadAsset(SAVESELECTSCREEN_TEXTURE_ID);
    gameTextLoadDir(0x15);

    if (gSaveSelectCachedText == 0)
    {
        gSaveSelectCachedText = gameTextGet(0xec);
    }

    for (i = 0; i < 4; i++)
    {
        gSaveSelectTextures[i] = textureLoadAsset(gSaveSelectTextureIds[i]);
    }

    if (getPrevUiDll() != 6)
    {
        if (getPrevUiDll() != 5)
        {
            (*gScreenTransitionInterface)->step(0x14, SCREEN_TRANSITION_HUD);
        }
        saveSelectGoToChooseSlot(1);
    }
    else
    {
        saveSelect_loadSlotSummaries();
        saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
        if (gSaveSelectPanelIndex != -1)
        {
            gTitleMenuLinkInterface->vtable->free();
        }

        gSaveSelectPanelIndex = SAVE_SELECT_PANEL_OPEN_FILE;
        panel = &gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE];
        panel->entries[0].flags = (u16)(panel->entries[0].flags & ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
        panel->entries[1].upLink = 0;
        panel->entries[1].textId = 0x3d6;
        gSaveSelectMenuItemActive = 0;
        gTitleMenuLinkInterface->vtable->setup(panel->entries, panel->count, 0, NULL, 5, 4, 0x14, 0xc8, 0xff, 0xff,
                                               0xff, 0xff);
        gTitleMenuLinkInterface->vtable->setSelected(0);
        saveFileSelect_debugCheatProgress = 0;
        saveFileSelect_saveCheatProgress = 0;
        saveFileSelect_cheatInputTimer = 0;
    }

    gSaveSelectQuitPending = 0;
    gSaveSelectLaunchPending = 0;
    gSaveSelectExitTimer = 0;
    gSaveSelectRefreshCounter = 4;
    lbl_803DD6B4 = 0;

    for (i = 0; i < SAVE_SELECT_TEXT_BUFFER_COUNT; i++)
    {
        gSaveSelectTextBuffers[i] = mmAlloc(5, 5, 0);
    }
}

TitleMenuTextEntry gSaveSelectChooseSlotEntries[3] = {
    {
        0xFFFF,
        0x0018,
        130,
        178,
        320,
        89,
        170,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        -1,
        1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0xFFFF,
        0x0019,
        130,
        204,
        320,
        89,
        196,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        0,
        2,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0xFFFF,
        0x001A,
        130,
        230,
        320,
        89,
        222,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        1,
        -1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
};

TitleMenuTextEntry gSaveSelectOpenFileEntries[2] = {
    {
        0x03D5,
        0x001D,
        58,
        339,
        0,
        58,
        327,
        {0, 0},
        -1,
        0x0000,
        0x0000,
        {0x05, 0x04},
        -1,
        1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0x03D6,
        0x001E,
        58,
        339,
        0,
        58,
        327,
        {0, 0},
        -1,
        0x0000,
        0x0000,
        {0x05, 0x04},
        0,
        -1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
};

TitleMenuTextEntry gSaveSelectConfirmEraseEntries[1] = {
    {
        0xFFFF,
        0x0002,
        58,
        339,
        0,
        58,
        327,
        {0, 0},
        -1,
        0x0000,
        0x0000,
        {0x05, 0x04},
        -1,
        -1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
};

TitleMenuTextEntry gSaveSelectSlotActionEntries[1] = {
    {
        0xFFFF,
        0x0002,
        320,
        382,
        0,
        320,
        370,
        {0, 0},
        -1,
        0x0000,
        0x0400,
        {0x05, 0x04},
        -1,
        -1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
};

TitleMenuTextEntry gSaveSelectChapterSelectEntries[6] = {
    {
        0x03D5,
        0x0017,
        130,
        178,
        320,
        89,
        170,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        -1,
        1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0x039E,
        0x0019,
        130,
        178,
        320,
        89,
        170,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        0,
        2,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0x039F,
        0x001A,
        130,
        204,
        320,
        89,
        196,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        1,
        3,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0x03A0,
        0x001B,
        130,
        230,
        320,
        89,
        222,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        2,
        4,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0x03A1,
        0x001C,
        130,
        230,
        320,
        89,
        222,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        3,
        5,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0x03A2,
        0x001D,
        130,
        230,
        320,
        89,
        222,
        {0, 0},
        -1,
        0x0140,
        0x0000,
        {0x00, 0x00},
        4,
        -1,
        -1,
        -1,
        -1,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
};

SaveSelectPanel gSaveSelectPanels[] = {
    {gSaveSelectChooseSlotEntries, 3, 0, 0x0379, 0x0367, {2, 0}}, {gSaveSelectOpenFileEntries, 2, 0, 0x0379, 0x0367, {2, 0}},
    {gSaveSelectSlotActionEntries, 1, 0, 0x037A, 0xFFFF, {2, 0}}, {gSaveSelectConfirmEraseEntries, 1, 0, 0x0379, 0x0367, {2, 0}},
    {gSaveSelectChapterSelectEntries, 6, 0, 0x0450, 0x0367, {2, 0}},
};

u8 lbl_8031A7F8[12] = {0, 0, 5, 213, 0, 0, 5, 214, 0, 0, 5, 212};
void* lbl_8031A804[4] = {(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000};
u16 saveFileSelect_debugCheatSequence[6] = {0x4000, 0x8000, 0x4000, 0x8000, 4, 0};
u16 saveFileSelect_slotCheatSequence[6] = {0x400, 0x800, 0x8000, 0x8000, 2, 0};
typedef struct SaveSelectScreenDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback run;
    ObjectDescriptorCallback frameEnd_nop;
    ObjectDescriptorCallback render;
} SaveSelectScreenDllInterface;

SaveSelectScreenDllInterface SaveSelectScreen_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)SaveSelectScreen_initialise,
    (ObjectDescriptorCallback)SaveSelectScreen_release,
    0,
    (ObjectDescriptorCallback)SaveSelectScreen_run,
    (ObjectDescriptorCallback)SaveSelectScreen_frameEnd_nop,
    (ObjectDescriptorCallback)SaveSelectScreen_render,
};
char sFrontendTimeFormat[14] = "%3d:%02d:%02d";
char sSaveGameBinPathFormat[] = "/savegame/save%d.bin";

void* gSaveSelectTextures[4];
