/*
 * saveselectscreen (DLL 0x35) - the front-end save-file / save-slot
 * screen reached from the title menu.
 *
 * It drives several sub-panels selected by the current panel index
 * gSaveSelectPanelIndex (0 = choose-slot, 1 = open-file, 2 = slot-action,
 * 3 = confirm/erase prompt, 4 = chapter-select), each backed by an
 * entry in the gSaveSelectPanels panel table. _initialise allocates the
 * save-slot buffers and textures, _run polls menu input and dispatches
 * to the per-panel handlers, _render draws the panel text with a
 * transition-driven fade, and _release/_Free tear the screen down.
 * Selecting a slot can start a new game, load/save, or hand off to
 * other UI DLLs via loadUiDll.
 */
#include "main/audio/sfx_ids.h"
#include "main/frame_timing.h"
#include "main/audio/music_api.h"
#include "main/dll/dll_0035_saveselectscreen.h"
#include "main/dll/FRONT/frontend_control.h"
#include "main/dll/FRONT/title_menu.h"
#include "main/screen_transition.h"
#include "main/texture.h"
#include "main/gameloop_api.h"
#include "main/mm.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/dll/dll_43.h"
#include "main/pad.h"
#include "main/audio/sfx.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/dll/dll_02C0_front.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/dll/front_game_text_box_api.h"
#include "main/gametext_api.h"
#include "main/gametext_show_api.h"
#include "main/mm.h"
#include "main/model_engine.h"
#include "main/map_load.h"
#include "main/fileio.h"
#include "main/mapEventTypes.h"
#include "main/textrender_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/savegame.h"
#include "main/dll/player_status.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "string.h"

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

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200

/* gSaveSelectPanelIndex: current sub-panel (index into gSaveSelectPanels; -1 = none). */
typedef enum SaveSelectPanelId
{
    SAVE_SELECT_PANEL_CHOOSE_SLOT = 0,   /* pick a save slot */
    SAVE_SELECT_PANEL_OPEN_FILE = 1,     /* opened file: continue / save */
    SAVE_SELECT_PANEL_SLOT_ACTION = 2,   /* copy / erase slot action */
    SAVE_SELECT_PANEL_CONFIRM_ERASE = 3, /* confirm-erase prompt */
    SAVE_SELECT_PANEL_CHAPTER_SELECT = 4 /* chapter (act) select */
} SaveSelectPanelId;

typedef struct SaveSelectPanel
{
    TitleMenuTextEntry* entries;
    u8 count;
    u8 pad5;
    u16 textIdA;
    u16 textIdB;
    u8 padA[2];
} SaveSelectPanel;

/* TitleMenuTextEntry.flags (at offset 0x16): row is hidden / non-selectable. */
#define TITLE_MENU_TEXT_ENTRY_HIDDEN 0x4000

/* count of gSaveSelectTextBuffers scratch allocations (symbol size 0x28 / 4). */
#define SAVE_SELECT_TEXT_BUFFER_COUNT 10

/* texture asset loaded into gSaveSelectTexture */
#define SAVESELECTSCREEN_TEXTURE_ID 0x2dd

s8 lbl_803DD6CF;
s8 gSaveSelectRefreshCounter;
u8 lbl_803DD6CD;
u8 lbl_803DD6CC;
void* gSaveSelectTexture;
u8 gSaveSelectMenuItemActive;
u8 lbl_803DD6C4;
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
void* lbl_803A8680[4];
extern SaveSelectPanel gSaveSelectPanels[];
extern u8 lbl_8031A7F8[];
void saveSelectGoToChapterSelect(void);

void* gSaveSelectTextBuffers[SAVE_SELECT_TEXT_BUFFER_COUNT];
extern f32 lbl_803E1D64;
extern f32 lbl_803E1D68;
extern f32 lbl_803E1D6C;
extern f32 gSaveSelectPositionScale;
extern f32 lbl_803E1D74;
extern void* lbl_803DD498;
char sSaveGameBinPathFormat[] = "/savegame/save%d.bin";

void saveSelectOpenFile(int sel, int slot)
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
                (*(TitleMenuTextEntry**)((char*)pp + off))[1].pad18[2] = -1;
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
void saveFileSelect_init(int sel, int slot)
{
    int i;

    saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
    if (sel == 0)
    {
        Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
        (*gScreenTransitionInterface)->start(20, 5);
        lbl_803DD6CF = 0x23;
        lbl_803DD6CC = 1;
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
                if ((s8)gSaveSelectPanelIndex != -1)
                {
                    gTitleMenuLinkInterface->vtable->free();
                }
                gSaveSelectPanelIndex = SAVE_SELECT_PANEL_OPEN_FILE;
                gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries[0].flags =
                    (u16)(gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries[0].flags &
                          ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
                gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE].entries[1].pad18[2] = 0;
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

void saveSelectSetupMenuItems(SaveSelectPanel* p)
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
            p->entries[i].actionParam = -1;
        }
        else
        {
            p->entries[i].textId = i;
            p->entries[i].flags = (u16)(p->entries[i].flags & ~0x2);
            p->entries[i].flags = (u16)(p->entries[i].flags | 0x1);
            p->entries[i].actionParam = -1;
        }
    }
}

void saveSelectGoToChapterSelect(void)
{
    int i;
    SaveSelectPanel* panel;

    if ((s8)gSaveSelectPanelIndex != -1)
    {
        gTitleMenuLinkInterface->vtable->free();
    }
    if (saveFileSelect_saveDirty != 0 || lbl_803DB424 == 0)
    {
        gSaveSelectPanelIndex = SAVE_SELECT_PANEL_CHAPTER_SELECT;
        panel = &gSaveSelectPanels[SAVE_SELECT_PANEL_CHAPTER_SELECT];
        for (i = 0; i < 6; i++)
        {
            if (i > saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].cheatFlag)
            {
                panel->entries[i].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
            }
            else
            {
                panel->entries[i].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;
            }
            if (i <= saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].cheatFlag + -1 && i < 5)
            {
                panel->entries[i].pad18[3] = (s8)(i + 1);
            }
            else
            {
                panel->entries[i].pad18[3] = -1;
            }
        }
        gTitleMenuLinkInterface->vtable->setup(panel->entries, panel->count, 0, lbl_8031A7F8, 5, 4, 0, 0, 0, 0, 0,
                                               0);
        gSaveSelectRefreshCounter = 2;
    }
    else
    {
        lbl_803DD6CD = 1;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
        (*gScreenTransitionInterface)->start(20, 1);
        gTitleMenuControlInterface->vtable->func0A(0);
        gTitleMenuControlInterface->vtable->func0A(1);
        gTitleMenuControlInterface->vtable->func0A(2);
        gTitleMenuControlInterface->vtable->func0A(3);
        lbl_803DD6CF = 0x23;
        lbl_803DD6C4 = 0;
    }
}
void saveSelectFn_8011a70c(void)
{
    int i;
    FrontendSaveSlot* slots = saveFileSelect_saveSlotsBase;
    saveFileSelect_saveSlots = slots;
    gSaveSelectInfoStartSlot[0] = 0;
    if (lbl_803DB424 != 0)
    {
        saveSelect_getInfo(slots);
        if (lbl_803DB424 != 0)
        {
            gSaveSelectInfoStartSlot[0] = 3;
        }
    }
    for (i = gSaveSelectInfoStartSlot[0]; i < 3; i++)
    {
        sprintf(saveFileSelect_saveSlots[i].name, sFrontendStringFormat, lbl_803DBA20);
        saveFileSelect_saveSlots[i].magicCount = 0;
        saveFileSelect_saveSlots[i].lifeCount = 0;
        saveFileSelect_saveSlots[i].completionPercent = 0;
        saveFileSelect_saveSlots[i].playTimeSeconds = 0;
        saveFileSelect_saveSlots[i].cheatFlag = 0;
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
        void* tmp = &gSaveSelectPanels[SAVE_SELECT_PANEL_CHOOSE_SLOT];
        p = (SaveSelectPanel*)tmp;
    }

    saveSelectFn_8011a70c();
    saveSelectSetupMenuItems(p);

    for (i = 0; i < 1; i++)
    {
        if (gSaveSelectInfoStartSlot[i] != 3)
        {
            p->entries[0].pad18[2] = 3;
        }
        else
        {
            p->entries[0].pad18[2] = -1;
        }
    }

    gTitleMenuLinkInterface->vtable->setup(p->entries, p->count, 0, NULL, 5, 4, 0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);

    gTitleMenuLinkInterface->vtable->setSelected(0);

    gSaveSelectRefreshCounter = 2;
    if (lbl_803DB424 == 0)
    {
        saveSelectGoToChapterSelect();
    }
}
void saveSelectScreenFree(int runExitCallback)
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

    p = lbl_803A8680;
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

void SaveSelectScreen_render(int param)
{
    SaveSelectPanel* panel;
    int progress;
    int alpha;
    int i;
    int slotCount;
    int off;
    char* p;
    u8* strs;
    void** arr;
    u16* ptrs;

    panel = &gSaveSelectPanels[gSaveSelectPanelIndex];
    gameTextSetDrawFunc(titleScreenTextDrawFunc);
    progress = (int)(lbl_803E1D64 - (*gScreenTransitionInterface)->getProgress());
    if ((u8)progress < 0x80)
    {
        f32 conv = (f32)(int)((u8)progress * 0x86);
        titleScreenPositionElements(lbl_803E1D68, lbl_803E1D6C - conv * gSaveSelectPositionScale);
        alpha = 0;
    }
    else
    {
        titleScreenPositionElements(lbl_803E1D68, lbl_803E1D74);
        alpha = ((u8)progress & 0x7f) << 1;
        alpha &= 0xff;
    }
    gameTextBoxFn_80134d40(alpha, (u8)(gSaveSelectPanelIndex == SAVE_SELECT_PANEL_CONFIRM_ERASE), 0);
    switch (gSaveSelectPanelIndex)
    {
    case SAVE_SELECT_PANEL_OPEN_FILE:
        saveSelect_drawText(param, alpha);
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        slotCount = 0;
        p = (char*)saveFileSelect_saveSlots + saveFileSelect_currentSlotIndex * 0x24;
        while (slotCount < 3 && *(void**)(p + 0xc) != NULL)
        {
            p += 4;
            slotCount++;
        }
        i = 0;
        strs = gSaveSelectInfoTextIds + (u8)(3 - slotCount);
        off = 0;
        while (i < slotCount)
        {
            gameTextAppendStr(
                *(char**)((char*)saveFileSelect_saveSlots + saveFileSelect_currentSlotIndex * 0x24 + off + 0xc), *strs);
            strs++;
            off += 4;
            i++;
        }
        if (gSaveSelectMenuItem != NULL)
        {
            gTitleMenuItemInterface->vtable->render(gSaveSelectMenuItem, 0, alpha);
        }
        break;
    case SAVE_SELECT_PANEL_CONFIRM_ERASE:
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextShow(0x324);
        break;
    case SAVE_SELECT_PANEL_CHOOSE_SLOT:
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gTitleMenuLinkInterface->vtable->getSelected();
        if (lbl_803DB424 != 0)
        {
            saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
            arr = gSaveSelectTextBuffers;
            ptrs = gSaveSelectSlotTextIds;
            for (i = 0; i < 3; i++)
            {
                sprintf(arr[i], sFrontendPercentFormat, saveFileSelect_saveSlots[i].completionPercent);
                gameTextSetColor(0xff, 0xff, 0xff, alpha);
                gameTextAppendStr(arr[i], ptrs[i]);
            }
        }
        break;
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    if (panel->textIdA != 0xffff)
    {
        if ((u8)alpha < 0x7f)
        {
            gameTextSetColor(0xff, 0xff, 0xff, (u8)(0xff - (alpha << 1)));
            gameTextShow(0x331);
        }
        else
        {
            gameTextSetColor(0xff, 0xff, 0xff, (u8)((alpha - 0x7f) << 1));
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
    s8* flagPtr;

    timer = lbl_803DD6CF;
    frames = framesThisStep;
    if (frames > 3)
    {
        frames = 3;
    }
    if (timer > 0)
    {
        lbl_803DD6CF -= frames;
    }
    if ((*gScreenTransitionInterface)->isFinished() == 0)
    {
        gTitleMenuLinkInterface->vtable->resetTimers();
        gSaveSelectRefreshCounter = 4;
    }
    if (lbl_803DD6CD != 0 || lbl_803DD6CC != 0)
    {
        if ((timer <= 12 || lbl_803DD6CF > 12) && lbl_803DD6CF <= 0)
        {
            if (lbl_803DD6CD != 0)
            {
                n_attractmode_releaseMovieBuffers();
                if (lbl_803DB424 != 0)
                {
                    trySaveGame(*(u8*)&saveFileSelect_currentSlotIndex);
                }
                else
                {
                    gplayNewGame(0, -1);
                }
                saveSelectScreenFree(1);
                titleScreenFn_801368d4();
                prev = mmSetFreeDelay(0);
                mapUnload(0x3d, 0x20000000);
                mmSetFreeDelay(prev);
                Music_Trigger(MUSICTRIG_cldrnr_tune1_be, 0);
                Music_Trigger(MUSICTRIG_windydocks, 0);
                if (lbl_803DD6C4 != 0)
                {
                    gplayNewGame(sFrontendFoxName, *(u8*)&saveFileSelect_currentSlotIndex);
                    (*gMapEventInterface)->setCharacter(1);
                    flagPtr = (s8*)(*gMapEventInterface)->getCurCharPos();
                    flagPtr[0xe] = -1;
                }
                if (lbl_803DD6C4 > 1)
                {
                    sprintf(buf, sSaveGameBinPathFormat, lbl_803DD6C4);
                    data = loadFileByPath(buf, 0, 0);
                    if (data != NULL)
                    {
                        memcpy(lbl_803DD498, data, 0x6ec);
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
                lbl_803DB424 = 0xfe;
                loadUiDll(4);
            }
        }
        return lbl_803DD6CF <= 12;
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
            (*gScreenTransitionInterface)->start(0x14, 5);
            lbl_803DD6CF = 0x23;
            lbl_803DD6CC = 1;
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
                    panel->entries[1].pad18[2] = 0;
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
                    lbl_803DD6CD = 1;
                    (*gScreenTransitionInterface)->start(0x14, 5);
                    gTitleMenuControlInterface->vtable->func0A(0);
                    gTitleMenuControlInterface->vtable->func0A(1);
                    gTitleMenuControlInterface->vtable->func0A(2);
                    gTitleMenuControlInterface->vtable->func0A(3);
                    lbl_803DD6CF = 0x23;
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

    saveFileSelect_saveSlotsBase = mmAlloc(0x6c, 5, 0);
    lbl_803DD6AC = mmAlloc(0x6c, 5, 0);
    gSaveSelectTexture = textureLoadAsset(SAVESELECTSCREEN_TEXTURE_ID);
    gameTextLoadDir(0x15);

    if (gSaveSelectCachedText == 0)
    {
        gSaveSelectCachedText = gameTextGet(0xec);
    }

    for (i = 0; i < 4; i++)
    {
        lbl_803A8680[i] = textureLoadAsset(gSaveSelectTextureIds[i]);
    }

    if (getUiDllFn_80014930() != 6)
    {
        if (getUiDllFn_80014930() != 5)
        {
            (*gScreenTransitionInterface)->step(0x14, 5);
        }
        saveSelectGoToChooseSlot(1);
    }
    else
    {
        saveSelectFn_8011a70c();
        saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
        if (gSaveSelectPanelIndex != -1)
        {
            gTitleMenuLinkInterface->vtable->free();
        }

        gSaveSelectPanelIndex = SAVE_SELECT_PANEL_OPEN_FILE;
        panel = &gSaveSelectPanels[SAVE_SELECT_PANEL_OPEN_FILE];
        panel->entries[0].flags = (u16)(panel->entries[0].flags & ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
        panel->entries[1].pad18[2] = 0;
        panel->entries[1].textId = 0x3d6;
        gSaveSelectMenuItemActive = 0;
        gTitleMenuLinkInterface->vtable->setup(panel->entries, panel->count, 0, NULL, 5, 4, 0x14, 0xc8, 0xff, 0xff,
                                               0xff, 0xff);
        gTitleMenuLinkInterface->vtable->setSelected(0);
        saveFileSelect_debugCheatProgress = 0;
        saveFileSelect_saveCheatProgress = 0;
        saveFileSelect_cheatInputTimer = 0;
    }

    lbl_803DD6CC = 0;
    lbl_803DD6CD = 0;
    lbl_803DD6CF = 0;
    gSaveSelectRefreshCounter = 4;
    lbl_803DD6B4 = 0;

    for (i = 0; i < SAVE_SELECT_TEXT_BUFFER_COUNT; i++)
    {
        gSaveSelectTextBuffers[i] = mmAlloc(5, 5, 0);
    }
}

extern TitleMenuTextEntry lbl_8031A4B0[];
extern TitleMenuTextEntry lbl_8031A564[];
extern TitleMenuTextEntry lbl_8031A618[];
extern TitleMenuTextEntry lbl_8031A5DC[];
extern TitleMenuTextEntry lbl_8031A654[];

SaveSelectPanel gSaveSelectPanels[] = {
    {lbl_8031A4B0, 3, 0, 0x0379, 0x0367, {2, 0}}, {lbl_8031A564, 2, 0, 0x0379, 0x0367, {2, 0}},
    {lbl_8031A618, 1, 0, 0x037A, 0xFFFF, {2, 0}}, {lbl_8031A5DC, 1, 0, 0x0379, 0x0367, {2, 0}},
    {lbl_8031A654, 6, 0, 0x0450, 0x0367, {2, 0}},
};

u8 lbl_8031A7F8[12] = {0, 0, 5, 213, 0, 0, 5, 214, 0, 0, 5, 212};
void* lbl_8031A804[4] = {(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000};
u16 saveFileSelect_debugCheatSequence[6] = {0x4000, 0x8000, 0x4000, 0x8000, 4, 0};
u16 saveFileSelect_slotCheatSequence[6] = {0x400, 0x800, 0x8000, 0x8000, 2, 0};
void* lbl_8031A82C[10] = {(void*)0x00000000,      (void*)0x00000000,           (void*)0x00000000,
                          (void*)0x00050000,      SaveSelectScreen_initialise, SaveSelectScreen_release,
                          (void*)0x00000000,      SaveSelectScreen_run,        SaveSelectScreen_frameEnd_nop,
                          SaveSelectScreen_render};
char sFrontendTimeFormat[14] = "%3d:%02d:%02d";
