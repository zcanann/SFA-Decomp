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
#include "main/dll/dll_0035_saveselectscreen.h"
#include "main/dll/FRONT/frontend_control.h"
#include "main/dll/FRONT/title_menu.h"
#include "main/screen_transition.h"
#include "main/texture.h"
#include "main/gameplay_runtime.h"
#include "main/mm.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/dll/dll_43.h"
#include "main/pad.h"
#include "main/audio/sfx.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "sfa_light_decls.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200

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

extern void gameTextLoadDir(int dirId);
extern void* gameTextGet(int textId);

extern s8 gSaveSelectPanelIndex;
extern u8 lbl_803DB424;
extern s8 saveFileSelect_currentSlotIndex;
extern u8 saveFileSelect_saveDirty;
extern u8 saveFileSelect_debugCheatProgress;
extern u8 saveFileSelect_saveCheatProgress;
extern u8 saveFileSelect_cheatInputTimer;
extern TitleMenuControl* gTitleMenuControlInterface;
extern TitleMenuControl* gTitleMenuLinkInterface;
extern TitleMenuControl* gTitleMenuItemInterface;
extern void* gSaveSelectCachedText;
extern void* lbl_803DD6AC;
extern void* gSaveSelectMenuItem;
extern u8 lbl_803DD6B4;
extern int gSaveSelectLastSlot;
extern void* gSaveSelectTexture;
extern u8 gSaveSelectMenuItemActive;
extern u8 lbl_803DD6CC;
extern u8 lbl_803DD6CD;
extern s8 gSaveSelectRefreshCounter;
extern s8 lbl_803DD6CF;
extern u8 lbl_803DD6C4;
extern void* lbl_8031A804[4];
extern void* lbl_803A8680[4];
extern SaveSelectPanel gSaveSelectPanels[];
extern u8 lbl_8031A7F8[];
extern s16 gSaveSelectTextureIds;
extern void gplaySaveGame();
void saveSelectGoToChapterSelect(void);

extern void* gSaveSelectTextBuffers[SAVE_SELECT_TEXT_BUFFER_COUNT];
extern FrontendSaveSlot* saveFileSelect_saveSlotsBase;
extern FrontendSaveSlot* saveFileSelect_saveSlots;
extern int gSaveSelectInfoStartSlot;
extern char sFrontendStringFormat;
extern char lbl_803DBA20;
extern int saveSelect_getInfo(void* outPtr);


extern void titleScreenPositionElements(f32 a, f32 b);
extern void gameTextBoxFn_80134d40(u8 a, u8 b, int c);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextAppendStr(char* str, int arg2);
extern void gameTextShow(int a);
extern void titleScreenShowCopyright(u8 arg);
extern u8 gSaveSelectInfoTextIds;
extern u16 gSaveSelectSlotTextIds[4];
extern char sFrontendPercentFormat;
extern f32 lbl_803E1D64;
extern f32 lbl_803E1D68;
extern f32 lbl_803E1D6C;
extern f32 gSaveSelectPositionScale;
extern f32 lbl_803E1D74;
extern u8 framesThisStep;
extern int mmSetFreeDelay(int v);
extern void Music_Trigger(int id, int arg);
extern void trySaveGame(int slot);
extern int gplayNewGame(char* name, int slot);
extern char* loadFileByPath(char* path, int a, int b);
extern void* memcpy(void* dst, void* src, int n);
extern void fn_80296B70(int arg);
extern TitleMenuControl* gMapEventInterface;
extern void* lbl_803DD498;
extern char sFrontendFoxName;
char sSaveGameBinPathFormat[] = "/savegame/save%d.bin";

#pragma dont_inline on
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
            ((void (**)(void*))gTitleMenuItemInterface->vtable)[4](gSaveSelectMenuItem);
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
                gSaveSelectMenuItem =
                    ((void *(**)(int, int, int, int, int))gTitleMenuItemInterface->vtable)[3]
                    (983, 41, 0, 1, 0);
                ((void (**)(void*, int))gTitleMenuItemInterface->vtable)[8](gSaveSelectMenuItem, 1);
                ((void (**)(TitleMenuTextEntry*))gTitleMenuLinkInterface->vtable)[11](
                    *(TitleMenuTextEntry**)((char*)pp + off));
            }
        }
        else
        {
            if (((u8 (**)(void*))gTitleMenuItemInterface->vtable)[9](gSaveSelectMenuItem) == 1)
            {
                gplaySaveGame((u8)saveFileSelect_currentSlotIndex);
            }
            ((void (**)(void*))gTitleMenuItemInterface->vtable)[4](gSaveSelectMenuItem);
            gSaveSelectMenuItem = NULL;
            saveSelectGoToChooseSlot(0);
        }
    }
}
#pragma dont_inline reset

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
    }
    while (i < SAVE_SELECT_TEXT_BUFFER_COUNT);
}

#pragma dont_inline on
void saveFileSelect_init(int sel, int slot)
{
    int i;

    saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
    if (sel == 0)
    {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
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
                    ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
                }
                gSaveSelectPanelIndex = 1;
                gSaveSelectPanels[1].entries[0].flags =
                    (u16)(gSaveSelectPanels[1].entries[0].flags & ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
                gSaveSelectPanels[1].entries[1].pad18[2] = 0;
                gSaveSelectPanels[1].entries[1].textId = 982;
                gSaveSelectMenuItemActive = 0;
                ((void (**)(void*, u8, int, int, int, int, int, int, int, int, int, int))
                    gTitleMenuLinkInterface->vtable)[1]
                (gSaveSelectPanels[1].entries, gSaveSelectPanels[1].count, 0, 0, 5, 4, 20, 200,
                 255, 255, 255, 255);
                ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);
                saveFileSelect_debugCheatProgress = 0;
                saveFileSelect_saveCheatProgress = 0;
                saveFileSelect_cheatInputTimer = 0;
                gSaveSelectRefreshCounter = 2;
            }
        }
    }
}
#pragma dont_inline reset
void saveSelectSetupMenuItems(SaveSelectPanel* p)
{
    int i;
    char* base;

    for (i = 0; i < p->count; i++)
    {
        base = (char*)saveFileSelect_saveSlotsBase;
        saveFileSelect_saveSlots = (FrontendSaveSlot*)base;
        if (*(u8*)(base + i * 0x24 + 0x20) == 0)
        {
            *(u16*)((char*)p->entries + i * 0x3c) = 0x39d;
            *(u16*)((char*)p->entries + i * 0x3c + 0x16) = (u16)(*(u16*)((char*)p->entries + i * 0x3c + 0x16) & ~0x1);
            *(u16*)((char*)p->entries + i * 0x3c + 0x16) = (u16)(*(u16*)((char*)p->entries + i * 0x3c + 0x16) | 0x2);
            *(int*)((char*)p->entries + i * 0x3c + 0x10) = -1;
        }
        else
        {
            *(u16*)((char*)p->entries + i * 0x3c) = i;
            *(u16*)((char*)p->entries + i * 0x3c + 0x16) = (u16)(*(u16*)((char*)p->entries + i * 0x3c + 0x16) & ~0x2);
            *(u16*)((char*)p->entries + i * 0x3c + 0x16) = (u16)(*(u16*)((char*)p->entries + i * 0x3c + 0x16) | 0x1);
            *(int*)((char*)p->entries + i * 0x3c + 0x10) = -1;
        }
    }
}

void saveSelectGoToChapterSelect(void)
{
    int off;
    int i;
    SaveSelectPanel* panel;

    if ((s8)gSaveSelectPanelIndex != -1)
    {
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
    }
    if (saveFileSelect_saveDirty != 0 || lbl_803DB424 == 0)
    {
        gSaveSelectPanelIndex = 4;
        panel = &gSaveSelectPanels[4];
        for (i = 0, off = 0; i < 6; i++)
        {
            if (i > saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].cheatFlag)
            {
                *(u16*)((char*)panel->entries + off + 22) |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
            }
            else
            {
                *(u16*)((char*)panel->entries + off + 22) &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;
            }
            if (i <= saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].cheatFlag + -1 && i < 5)
            {
                *(s8*)((char*)panel->entries + off + 27) = (s8)(i + 1);
            }
            else
            {
                *(s8*)((char*)panel->entries + off + 27) = -1;
            }
            off += 60;
        }
        ((void (**)(void*, u8, int, void*, int, int, int, int, int, int, int, int))
            gTitleMenuLinkInterface->vtable)[1]
        (panel->entries, panel->count, 0, lbl_8031A7F8, 5, 4, 0, 0,
         0, 0, 0, 0);
        gSaveSelectRefreshCounter = 2;
    }
    else
    {
        lbl_803DD6CD = 1;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
        (*gScreenTransitionInterface)->start(20, 1);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](0);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](1);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](2);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](3);
        lbl_803DD6CF = 0x23;
        lbl_803DD6C4 = 0;
    }
}

#pragma dont_inline on
#pragma opt_dead_assignments off
void saveSelectFn_8011a70c(void)
{
    int i;
    FrontendSaveSlot* slots = saveFileSelect_saveSlotsBase;
    saveFileSelect_saveSlots = slots;
    gSaveSelectInfoStartSlot = 0;
    if (lbl_803DB424 != 0)
    {
        saveSelect_getInfo(slots);
        if (lbl_803DB424 != 0)
        {
            gSaveSelectInfoStartSlot = 3;
        }
    }
    {
        struct SaveSlotRec
        {
            char name[4];
            u8 f4, f5, f6, pad7;
            int f8;
            u8 padc[0x15];
            u8 f21;
            u8 pad22[2];
        };
        for (i = gSaveSelectInfoStartSlot; i < 3; i++)
        {
            sprintf(((struct SaveSlotRec*)saveFileSelect_saveSlots)[i].name, &sFrontendStringFormat, &lbl_803DBA20);
            ((struct SaveSlotRec*)saveFileSelect_saveSlots)[i].f5 = 0;
            ((struct SaveSlotRec*)saveFileSelect_saveSlots)[i].f6 = 0;
            ((struct SaveSlotRec*)saveFileSelect_saveSlots)[i].f4 = 0;
            ((struct SaveSlotRec*)saveFileSelect_saveSlots)[i].f8 = 0;
            ((struct SaveSlotRec*)saveFileSelect_saveSlots)[i].f21 = 0;
        }
    }
}
#pragma opt_dead_assignments reset
#pragma dont_inline reset
#pragma dont_inline on
void saveSelectGoToChooseSlot(int arg)
{
    SaveSelectPanel* p;
    u8 i;

    if (gSaveSelectPanelIndex != -1)
    {
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
    }
    gSaveSelectPanelIndex = 0;
    saveFileSelect_currentSlotIndex = 0;
    {
        void* tmp = &gSaveSelectPanels[0];
        p = (SaveSelectPanel*)tmp;
    }

    saveSelectFn_8011a70c();
    saveSelectSetupMenuItems(p);

    for (i = 0; i < 1; i++)
    {
        if ((&gSaveSelectInfoStartSlot)[i] != 3)
        {
            p->entries[0].pad18[2] = 3;
        }
        else
        {
            p->entries[0].pad18[2] = -1;
        }
    }

    ((void (**)(TitleMenuTextEntry*, int, int, int, int, int, int, int, int, int, int, int))
        gTitleMenuLinkInterface->vtable)[1](
        p->entries, p->count, 0, 0, 5, 4, 0x14, 0xc8,
        0xff, 0xff, 0xff, 0xff);

    ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);

    gSaveSelectRefreshCounter = 2;
    if (lbl_803DB424 == 0)
    {
        saveSelectGoToChapterSelect();
    }
}
#pragma dont_inline reset

#pragma dont_inline on
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
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
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
            textureFree(p[i]);
            p[i] = zero;
        }
    }

    textureFree(gSaveSelectTexture);
    if (runExitCallback != 0)
    {
        doNothing_onSaveSelectScreenExit();
    }
    if (gSaveSelectMenuItem != NULL)
    {
        ((void (**)(void*))gTitleMenuItemInterface->vtable)[4](gSaveSelectMenuItem);
        gSaveSelectMenuItem = NULL;
    }
}
#pragma dont_inline reset

void SaveSelectScreen_render(int param)
{
    SaveSelectPanel* panel;
    int v;
    u8 alpha;
    int i;
    int n;
    int off;
    char* p;
    u8* strs;
    void** arr;
    u16* ptrs;

    panel = &gSaveSelectPanels[gSaveSelectPanelIndex];
    gameTextSetDrawFunc(titleScreenTextDrawFunc);
    v = (int)(lbl_803E1D64 -
        (*gScreenTransitionInterface)->getProgress());
    if ((u8)v < 0x80)
    {
        f32 conv = (f32)(int)((u8)v * 0x86);
        titleScreenPositionElements(lbl_803E1D68, lbl_803E1D6C - conv * gSaveSelectPositionScale);
        alpha = 0;
    }
    else
    {
        titleScreenPositionElements(lbl_803E1D68, lbl_803E1D74);
        alpha = (u8)(((u8)v & 0x7f) << 1);
    }
    gameTextBoxFn_80134d40(alpha, (u8)(gSaveSelectPanelIndex == 3), 0);
    switch (gSaveSelectPanelIndex)
    {
    case 1:
        ((void (*)(int, u8))saveSelect_drawText)(param, alpha);
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        n = 0;
        p = (char*)saveFileSelect_saveSlots + saveFileSelect_currentSlotIndex * 0x24;
        while (n < 3 && *(void**)(p + 0xc) != NULL)
        {
            p += 4;
            n++;
        }
        i = 0;
        strs = &gSaveSelectInfoTextIds + (u8)(3 - n);
        off = 0;
        while (i < n)
        {
            gameTextAppendStr(
                *(char**)((char*)saveFileSelect_saveSlots + saveFileSelect_currentSlotIndex * 0x24 + off + 0xc), *strs);
            strs++;
            off += 4;
            i++;
        }
        if (gSaveSelectMenuItem != NULL)
        {
            ((void (**)(void*, int, u8))gTitleMenuItemInterface->vtable)[6](gSaveSelectMenuItem, 0, alpha);
        }
        break;
    case 3:
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextShow(0x324);
        break;
    case 0:
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[5]();
        if (lbl_803DB424 != 0)
        {
            saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
            arr = gSaveSelectTextBuffers;
            ptrs = gSaveSelectSlotTextIds;
            for (i = 0; i < 3; i++)
            {
                sprintf(arr[i], &sFrontendPercentFormat, saveFileSelect_saveSlots[i].completionPercent);
                gameTextSetColor(0xff, 0xff, 0xff, alpha);
                gameTextAppendStr(arr[i], ptrs[i]);
            }
        }
        break;
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    if (panel->textIdA != 0xffff)
    {
        if (alpha < 0x7f)
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
    ((void (**)(int))gTitleMenuLinkInterface->vtable)[12](v);
    ((void (**)(int))gTitleMenuLinkInterface->vtable)[4](param);
    gameTextSetDrawFunc(0);
    titleScreenShowCopyright(0);
    if ((gSaveSelectRefreshCounter -= 1) < 0)
    {
        gSaveSelectRefreshCounter = 0;
    }
}

int SaveSelectScreen_run(void)
{
    char buf[32];
    s8 timer;
    int n;
    int sel;
    int slot;
    int prev;
    char* data;
    SaveSelectPanel* panel;
    int btn;
    s8* flagPtr;

    timer = lbl_803DD6CF;
    n = framesThisStep;
    if (n > 3)
    {
        n = 3;
    }
    if (timer > 0)
    {
        lbl_803DD6CF -= n;
    }
    if ((*gScreenTransitionInterface)->isFinished() == 0)
    {
        ((void (**)(void))gTitleMenuLinkInterface->vtable)[13]();
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
                    gplayNewGame(&sFrontendFoxName, *(u8*)&saveFileSelect_currentSlotIndex);
                    ((void (**)(int))gMapEventInterface->vtable)[30](1);
                    flagPtr = (s8*)((int (**)(void))gMapEventInterface->vtable)[36]();
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
                    fn_80296B70(0);
                }
                ((void (**)(void))gMapEventInterface->vtable)[8]();
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
    if (gSaveSelectPanelIndex == 3)
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
        sel = ((int (**)(void))gTitleMenuLinkInterface->vtable)[3]();
        slot = ((int (**)(void))gTitleMenuLinkInterface->vtable)[5]();
        if (slot != gSaveSelectLastSlot)
        {
            Sfx_PlayFromObject(0, SFXTRIG_warningloop);
        }
        gSaveSelectLastSlot = slot;
        if (gSaveSelectMenuItem != NULL)
        {
            ((void (**)(void*))gTitleMenuItemInterface->vtable)[5](gSaveSelectMenuItem);
        }
        if (sel != -1 || gSaveSelectPanelIndex == 0)
        {
            switch (gSaveSelectPanelIndex)
            {
            case 0:
                saveFileSelect_init(sel, slot);
                break;
            case 1:
                saveSelectOpenFile(sel, slot);
                break;
            case 2:
                if (sel == 0)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down);
                    saveFileSelect_currentSlotIndex = slot;
                    if (gSaveSelectPanelIndex != -1)
                    {
                        ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
                    }
                    gSaveSelectPanelIndex = 1;
                    panel = &gSaveSelectPanels[1];
                    panel->entries[0].flags = (u16)(panel->entries[0].flags & ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
                    panel->entries[1].pad18[2] = 0;
                    panel->entries[1].textId = 0x3d6;
                    gSaveSelectMenuItemActive = 0;
                    ((void (**)(TitleMenuTextEntry*, u8, int, int, int, int, int, int, int, int, int, int))
                            gTitleMenuLinkInterface->vtable)[1]
                        (panel->entries, panel->count, 0, 0, 5, 4, 0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);
                    ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);
                    saveFileSelect_debugCheatProgress = 0;
                    saveFileSelect_saveCheatProgress = 0;
                    saveFileSelect_cheatInputTimer = 0;
                    gSaveSelectRefreshCounter = 2;
                }
                else if (sel == 1)
                {
                    lbl_803DD6CD = 1;
                    (*gScreenTransitionInterface)->start(0x14, 5);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](0);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](1);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](2);
                    ((void (**)(int))gTitleMenuControlInterface->vtable)[7](3);
                    lbl_803DD6CF = 0x23;
                }
                break;
            case 4:
                saveSelectSetSlot(sel, slot);
                break;
            }
        }
    }
    if (gSaveSelectPanelIndex == 1)
    {
        saveFileSelect_checkCheatCodes();
    }
    return 0;
}

void SaveSelectScreen_initialise(void)
{
    int i;
    SaveSelectPanel* panel;

    saveFileSelect_saveSlotsBase = mmAlloc(0x6c, 5, 0);
    lbl_803DD6AC = mmAlloc(0x6c, 5, 0);
    gSaveSelectTexture = textureLoadAsset(0x2dd);
    gameTextLoadDir(0x15);

    if (gSaveSelectCachedText == 0)
    {
        gSaveSelectCachedText = gameTextGet(0xec);
    }

    for (i = 0; i < 4; i++)
    {
        lbl_803A8680[i] = textureLoadAsset((&gSaveSelectTextureIds)[i]);
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
            ((void (**)(void))gTitleMenuLinkInterface->vtable)[2]();
        }

        gSaveSelectPanelIndex = 1;
        panel = &gSaveSelectPanels[1];
        panel->entries[0].flags = (u16)(panel->entries[0].flags & ~TITLE_MENU_TEXT_ENTRY_HIDDEN);
        panel->entries[1].pad18[2] = 0;
        panel->entries[1].textId = 0x3d6;
        gSaveSelectMenuItemActive = 0;
        ((void (**)(TitleMenuTextEntry*, u8, int, int, int, int, int, int, int, int, int, int))
                gTitleMenuLinkInterface->vtable)[1]
            (panel->entries, panel->count, 0, 0, 5, 4, 0x14, 0xc8, 0xff, 0xff, 0xff, 0xff);
        ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](0);
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

void SaveSelectScreen_frameEnd_nop(void)
{
}

extern TitleMenuTextEntry lbl_8031A4B0[];
extern TitleMenuTextEntry lbl_8031A564[];
extern TitleMenuTextEntry lbl_8031A618[];
extern TitleMenuTextEntry lbl_8031A5DC[];
extern TitleMenuTextEntry lbl_8031A654[];

SaveSelectPanel gSaveSelectPanels[] = {
    { lbl_8031A4B0, 3, 0, 0x0379, 0x0367, { 2, 0 } },
    { lbl_8031A564, 2, 0, 0x0379, 0x0367, { 2, 0 } },
    { lbl_8031A618, 1, 0, 0x037A, 0xFFFF, { 2, 0 } },
    { lbl_8031A5DC, 1, 0, 0x0379, 0x0367, { 2, 0 } },
    { lbl_8031A654, 6, 0, 0x0450, 0x0367, { 2, 0 } },
};
