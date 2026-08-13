#include "types.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/audio/sfx.h"
#include "main/gametext_api.h"
#include "main/gametext_color_api.h"
#include "main/gameloop_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_shared_internal.h"
#include "main/gx_scissor_api.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSFont.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/savedata_struct.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/dll_0015_save_settings.h"
#include "track/intersect_api.h"
#include "main/lightmap.h"
#include "main/audio/sfx_stop_object_api.h"

TextFont* gameTextFonts;
int gameTextCharset;
int curLanguage;
int gGameTextLastLanguage;
int curGameTextDir;
int gGameTextLastDir;
int lbl_803DC9D4;
int lbl_803DC9D0;
void* gCurTextBox;
int lbl_803DC9C8;
char* gGameTextCommandStringCursor;
int gGameTextRenderingById;
int gGameTextMeasureOnly;
int gGameTextBoundsMinY;
int gGameTextBoundsMaxY;
int gGameTextBoundsMinX;
int gGameTextBoundsMaxX;
u16 gGameTextCursorX;
u16 gGameTextCursorY;
u8 gGameTextColorR;
u8 gGameTextColorG;
u8 gGameTextColorB;
u8 gGameTextColorA;
f32 gGameTextScale;
int gGameTextRevealActive;
int gGameTextDrawnCharIndex;
f32 gGameTextRevealProgress;
u8 gGameTextShadowColorR;
u8 gGameTextShadowColorG;
u8 gGameTextShadowColorB;
int gGameTextShadowOffsetX;
int gGameTextShadowOffsetY;
int gGameTextShadowEnabled;
u8 lbl_803DC980;
int gGameTextBufferIndex;
char* gCurTextBuffer;
u8* gGameTextLastEntry;
int gGameTextFallbackBuf;
GameTextDrawFunc gameTextDrawFunc;
u8 gGameTextFontIsSjis;

void gameTextFinalizeLoad(GameTextLoadSlot* loadSlot);

SubtitleCmd* subtitleParseControlCmds(char* str, int* count);

typedef struct GameTextTableHeader
{
    u32 unk0;
    u16 entryCount;
    u16 textureOffset;
} GameTextTableHeader;
STATIC_ASSERT(sizeof(GameTextTableHeader) == 8);

typedef struct GameTextStringTable
{
    int count;
    int offsets[];
} GameTextStringTable;

static void gameTextLoadCancelCallback(s32 result, DVDCommandBlock* block);
static void gameTextLoadCompleteCallback(s32 status, DVDFileInfo* fileInfo);

void gameTextLoadDir(int dirId)
{
    GameTextSlot* cmd;
    GXColor color;
    int slotIndex;

    gGameTextColorR = 0xff;
    gGameTextColorG = 0xff;
    gGameTextColorB = 0xff;
    gGameTextColorA = 0xff;

    if (dirId == 3)
    {
        gameTextFonts = &gGameTextCharsets[GAMETEXT_SLOT_ERROR];
        gameTextCharset = GAMETEXT_SLOT_ERROR;
        color = gGameTextClearColor;
        hudDrawRect(0, 0, 0xa00, 0x780, color);
        gGameTextRevealActive = 0;
        if (gameTextDrawFunc == NULL)
        {
            slotIndex = gGameTextCommandCount;
            gGameTextCommandCount = slotIndex + 1;
            cmd = &gGameTextCommandSlots[slotIndex];
            cmd->opcode = GAMETEXT_COMMAND_SET_CHARSET;
            cmd->arg0 = GAMETEXT_SLOT_ERROR;
        }
    }
    else if (dirId == 0x1c)
    {
        curGameTextDir = dirId;
        gameTextFonts = &gGameTextCharsets[GAMETEXT_SLOT_HUD];
        gameTextCharset = GAMETEXT_SLOT_HUD;
        if (gameTextDrawFunc == NULL)
        {
            slotIndex = gGameTextCommandCount;
            gGameTextCommandCount = slotIndex + 1;
            cmd = &gGameTextCommandSlots[slotIndex];
            cmd->opcode = GAMETEXT_COMMAND_SET_CHARSET;
            cmd->arg0 = GAMETEXT_SLOT_HUD;
        }
        gameTextLoadForCurMap(GAMETEXT_SLOT_HUD);
    }
    else
    {
        gameTextFonts = &gGameTextCharsets[GAMETEXT_SLOT_DIALOGUE];
        gameTextCharset = GAMETEXT_SLOT_DIALOGUE;
        if (gameTextDrawFunc == NULL)
        {
            slotIndex = gGameTextCommandCount;
            gGameTextCommandCount = slotIndex + 1;
            cmd = &gGameTextCommandSlots[slotIndex];
            cmd->opcode = GAMETEXT_COMMAND_SET_CHARSET;
            cmd->arg0 = GAMETEXT_SLOT_DIALOGUE;
        }
        curGameTextDir = dirId;
        if ((subtitleIsActive() == 0 || gameTextSaveDir(dirId) == 0) && curGameTextDir != gGameTextLastDir)
        {
            gameTextLoadForCurMap(GAMETEXT_SLOT_DIALOGUE);
        }
    }
}

int gameTextGetCharset(void)
{
    return gameTextCharset;
}

void gameTextSetCharset(int charset, int flags)
{
    if (gameTextDrawFunc != NULL || (flags & 1))
    {
        gameTextFonts = &gGameTextCharsets[charset];
        gameTextCharset = charset;
        if (charset == 2)
        {
            GXColor color = gGameTextClearColor;
            hudDrawRect(0, 0, 0xa00, 0x780, color);
            gGameTextRevealActive = 0;
        }
    }
    if (gameTextDrawFunc == NULL || (flags & 2))
    {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = GAMETEXT_COMMAND_SET_CHARSET;
        cmd->arg0 = charset;
    }
}

int gameTextGetState(int i);

int getCurGameText(void)
{
    return curGameTextDir;
}

int getCurLanguage(void)
{
    return curLanguage;
}

f32 gameTextGetTimer(void)
{
    return gameTextFonts->timer;
}

int gameTextGetState(int i)
{
    return gGameTextCharsets[i].status;
}

char sGameTextMapPathFormat[] = "gametext/%s/%s.bin";

void gameTextRun(void)
{
    GameTextRuntime* runtime;
    GameTextLoadSlot* loadSlot;
    TextFont* pending;
    int sourceId;
    GameTextSlot* cmd;
    int i;
    GameTextLoadSlot* freeSlot;
    int dirId;
    int languageId;
    GameTextBox* textBox;
    GXColor color;
    double fadeLimit;
    double zero;

    runtime = (GameTextRuntime*)gGameTextBase;
    cmd = runtime->commands;

    loadSlot = runtime->loadSlots;
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if (loadSlot->state == 2)
        {
            gameTextFinalizeLoad(loadSlot);
        }
        loadSlot++;
    } while (i-- != 0);

    sourceId = 0;
    pending = runtime->fonts;
    do
    {
        if (pending->dirId != GAMETEXT_INVALID_DIR)
        {
            loadSlot = runtime->loadSlots;
            dirId = pending->dirId;
            do
            {
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                ++loadSlot;
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                ++loadSlot;
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                ++loadSlot;
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                ++loadSlot;
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                ++loadSlot;
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                ++loadSlot;
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                ++loadSlot;
                if (loadSlot->active == 0)
                {
                    dirId = pending->dirId;
                    break;
                }
                loadSlot = NULL;
            } while (0);
            freeSlot = loadSlot;

            if (freeSlot != NULL)
            {
                languageId = pending->languageId;
                freeSlot->state = 1;
                freeSlot->dirId = (u8)dirId;
                freeSlot->languageId = languageId;
                freeSlot->active = 1;
                freeSlot->sourceId = sourceId;
                sprintf(runtime->path, sGameTextMapPathFormat,
                         sMapDirectoryNameTable[dirId], sLanguageNameTable[languageId].name);
                setFileInfo(&freeSlot->fileInfo);
                freeSlot->loadHandle = loadFileByPathAsync(runtime->path,
                                                           &freeSlot->loadedSize, 1, gameTextLoadCompleteCallback);
                setFileInfo(NULL);
                pending->dirId = GAMETEXT_INVALID_DIR;
                pending->languageId = GAMETEXT_INVALID_LANGUAGE;
            }
        }
        pending++;
        sourceId++;
    } while (sourceId < GAMETEXT_PENDING_SOURCE_COUNT);

    loadSlot = runtime->loadSlots;
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if ((loadSlot->state == 5 || loadSlot->state == 6) && loadSlot->loadHandle != NULL)
        {
            mm_free(loadSlot->loadHandle);
            loadSlot->loadHandle = NULL;
            loadSlot->loadedSize = 0;
            loadSlot->active = 0;
        }
        loadSlot++;
    } while (i-- != 0);

    i = GAMETEXT_LOAD_SLOT_COUNT;
    {
        f32* alpha;
        GameTextDef* entry;
        f32* timer;
        timer = runtime->fadeTimers + 8;
        alpha = runtime->fadeElapsed + 8;
        entry = runtime->fallbackDefs + 8;
        zero = lbl_803DE704;
        fadeLimit = gGameTextFadeLimit;
        while (timer--, alpha--, entry--, i-- != 0)
        {
            if ((double)*timer > zero)
            {
                *alpha += timeDelta;
                if ((double)*alpha > fadeLimit)
                {
                    *timer = zero;
                    *alpha = zero;
                    sprintf(*entry->strings, sGameTextBlankFormat);
                }
            }
        }
    }

    if (gameTextFonts->status == 1)
    {
        gameTextFonts->timer += timeDelta;
    }
    else
    {
        gameTextFonts->timer = lbl_803DE704;
    }

    textBox = gTextBoxes;
    for (i = GAMETEXT_BOX_COUNT; i != 0; i--)
    {
        textBox->flags &= ~1;
        textBox++;
    }

    gGameTextRevealActive = 0;
    gGameTextCursorX = 0;
    gGameTextCursorY = 0;

    i = gGameTextCommandCount;
    while (i-- != 0)
    {
        switch (cmd->opcode)
        {
        case GAMETEXT_COMMAND_SET_COLOR:
        {
            u8 c1, c2, c3;
            c3 = cmd->arg3;
            c2 = cmd->arg2;
            c1 = cmd->arg1;
            gGameTextColorR = cmd->arg0;
            gGameTextColorG = c1;
            gGameTextColorB = c2;
            gGameTextColorA = c3;
            break;
        }
        case GAMETEXT_COMMAND_SET_WINDOW_POSITION:
        {
            int t1 = cmd->arg2;
            gTextBoxes[cmd->arg0].cursorX = (s16)cmd->arg1;
            gTextBoxes[cmd->arg0].cursorY = t1;
            break;
        }
        case GAMETEXT_COMMAND_TICK_REVEAL:
            gameTextTickReveal(cmd->arg0, (struct TextDisplayState*)cmd->arg1);
            break;
        case GAMETEXT_COMMAND_RENDER_BY_ID:
            gameTextRenderById(cmd->arg0, cmd->arg1, cmd->arg2);
            break;
        case GAMETEXT_COMMAND_SHOW_TIME_STRING:
        {
            int strId = cmd->arg0;
            if (gCurTextBox != NULL)
            {
                gameTextRenderStrs((char*)strId, ((u8*)gCurTextBox - (u8*)gTextBoxes) / 0x20);
            }
            break;
        }
        case GAMETEXT_COMMAND_APPEND_STRING:
            gameTextRenderStrs((char*)cmd->arg0, cmd->arg1);
            break;
        case GAMETEXT_COMMAND_SHOW_STRING_AT:
        {
            int t3 = cmd->arg3;
            int t2 = cmd->arg1;
            int t1 = cmd->arg0;
            textBox = &gTextBoxes[t2];
            textBox->cursorX = cmd->arg2;
            textBox->cursorY = t3;
            gameTextRenderStrs((char*)t1, t2);
            break;
        }
        case GAMETEXT_COMMAND_SET_WINDOW:
            if (cmd->arg0 == 0xff)
            {
                gCurTextBox = NULL;
            }
            else
            {
                gCurTextBox = &gTextBoxes[cmd->arg0];
            }
            break;
        case GAMETEXT_COMMAND_CALL_DRAW_FUNC:
            ((void (*)(void))cmd->arg0)();
            break;
        case GAMETEXT_COMMAND_SET_CURSOR:
        {
            u16 b1 = cmd->arg1;
            gGameTextCursorX = (u16)cmd->arg0;
            gGameTextCursorY = b1;
            break;
        }
        case GAMETEXT_COMMAND_RESET_CURSOR:
            gGameTextCursorX = 0;
            gGameTextCursorY = 0;
            break;
        case GAMETEXT_COMMAND_SET_SHADOW_ENABLED:
            gGameTextShadowEnabled = cmd->arg0;
            break;
        case GAMETEXT_COMMAND_SET_SHADOW_COLOR:
        {
            u8 e1, e2;
            e2 = cmd->arg2;
            e1 = cmd->arg1;
            gGameTextShadowColorR = cmd->arg0;
            gGameTextShadowColorG = e1;
            gGameTextShadowColorB = e2;
            break;
        }
        case GAMETEXT_COMMAND_SET_SHADOW_OFFSET:
        {
            int sy = cmd->arg1;
            gGameTextShadowOffsetX = cmd->arg0;
            gGameTextShadowOffsetY = sy;
            break;
        }
        case GAMETEXT_COMMAND_SET_CHARSET:
            gameTextFonts = (TextFont*)((cmd->arg0 * sizeof(TextFont) + offsetof(GameTextRuntime, fonts)) +
                                         (int)runtime);
            gameTextCharset = cmd->arg0;
            if (cmd->arg0 == 2)
            {
                color = gGameTextClearColor;
                hudDrawRect(0, 0, 0xa00, 0x780, color);
                gGameTextRevealActive = 0;
            }
            break;
        }
        cmd++;
    }

    if (gGameTextRevealActive == 0)
    {
        Sfx_StopFromObject(0, SFXTRIG_clock_loop);
    }
    gGameTextCommandCount = 0;
    gGameTextCommandStringCursor = runtime->commandStringBuffer;

    i = GAMETEXT_BOX_COUNT;
    textBox = &gTextBoxes[GAMETEXT_BOX_COUNT];
    while (textBox--, i-- != 0)
    {
        textBox->cursorX = 0;
        textBox->cursorY = 0;
    }
    gCurTextBox = NULL;
}

char sGameTextSequencePathFormat[] = "gametext/Sequences/%d_%s.bin";

static inline u32 lookupSjisGlyph(int c)
{
    int i = 0xfe;
    u16* p = gGameTextSjisGlyphTable;
    while (i--)
    {
        if (p[0] == c)
        {
            return p[1];
        }
        p++;
    }
    return 0;
}

void gameTextInit(void)
{
    gameTextInitBoxTextures();
    lbl_803DC980 = 1;
    gameTextLoadDir(0x1c);
}

void gameTextInitRendererState(void)
{
    u8* clearPtr;
    u8* glyphPage;
    u8** glyphPagePtr;
    GameTextDef* fallbackDef;
    u8* textWindow;
    u8* gameTextBase;
    int glyphPageCount;
    TextFont* font;
    GameTextBox* p;
    f32 zero;
    int i;
    int j;

    gameTextBase = gGameTextBase;

    i = GAMETEXT_BOX_COUNT;
    p = (GameTextBox*)(textWindow = (u8*)&gTextBoxes[GAMETEXT_BOX_COUNT]);
    while (p--, i-- != 0)
    {
        p->width = p->maxWidth;
        p->height = p->maxHeight;
    }

    glyphPageCount = GAMETEXT_LOAD_SLOT_COUNT;
    glyphPage = gameTextBase + 0x2c0;
    glyphPagePtr = (u8**)(gameTextBase + 0xc0);
    fallbackDef = (GameTextDef*)(gameTextBase + 0xa0);
    while (glyphPage -= 0x40, glyphPagePtr--, fallbackDef--, glyphPageCount-- != 0)
    {
        *glyphPagePtr = glyphPage;
        fallbackDef->identifier = 0xffff;
        fallbackDef->count = 1;
        fallbackDef->boxId = 0xff;
        fallbackDef->alignH = 0;
        fallbackDef->alignV = 0;
        fallbackDef->language = 0;
        fallbackDef->strings = (char**)glyphPagePtr;
    }

    i = GAMETEXT_BOX_COUNT;
    while (textWindow -= 0x20, i-- != 0)
    {
        ((GameTextBox*)textWindow)->alpha = 0xff;
    }

    j = 4;
    font = (TextFont*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    zero = lbl_803DE704;
    while (font--, j-- != 0)
    {
        font->glyphCount = 0;
        font->entryCount = 0;
        font->glyphs = NULL;
        font->entries = NULL;
        font->status = 0;
        font->timer = zero;
        font->dirId = GAMETEXT_INVALID_DIR;
        font->languageId = GAMETEXT_INVALID_LANGUAGE;

        i = 3;
        clearPtr = (u8*)font + 0xc;
        while (clearPtr -= 4, i-- != 0)
        {
            *(int*)(clearPtr + 0x10) = 0;
        }
    }

    gameTextFonts = (TextFont*)(gameTextBase + GAMETEXT_FONT_SLOT_OFFSET);
    gameTextCharset = 2;
    curLanguage = -1;
    curGameTextDir = -1;
    gCurTextBox = NULL;
    gGameTextLastLanguage = -1;
    gGameTextLastDir = -1;
    gGameTextMeasureOnly = 0;
    gGameTextColorR = 0xff;
    gGameTextColorG = 0xff;
    gGameTextColorB = 0xff;
    gGameTextColorA = 0xff;
    gGameTextCommandCount = 0;
    gGameTextCommandStringCursor = (char*)(gameTextBase + GAMETEXT_COMMAND_STRING_BUFFER_OFFSET);
    gGameTextBufferIndex = 0;
    fallbackDef = (GameTextDef*)(gameTextBase + 0x40);
    gGameTextLastEntry = (u8*)fallbackDef;
    gCurTextBuffer = (char*)*(int*)fallbackDef->strings;
    gGameTextShadowColorR = 0;
    gGameTextShadowColorG = 0;
    gGameTextShadowColorB = 0;
    gGameTextShadowOffsetX = 5;
    gGameTextShadowOffsetY = 5;
    gGameTextShadowEnabled = 1;
    lbl_803DC980 = 0;
    gameTextBuildSystemFontAtlas();
    curGameTextDir = 3;
    gGameTextStringStore = (void*)mmCreateMemoryStore(0x800);
}

void loadGameTextSequence(int sequenceSlotDir, int sequenceId)
{
    GameTextLoadSlot* slot;
    int oldHeap;
    GameTextRuntime* gameTextBase;
    int languageTableOffset;
    u8* languageTable;
    int i;

    gameTextBase = (GameTextRuntime*)gGameTextBase;
    languageTableOffset = curLanguage << 3;
    languageTable = (u8*)sLanguageNameTable;
    oldHeap = mmSetDelay(0);
    if (getGameState() != 0 && getGameState() != 1)
    {
        mmSetDelay(oldHeap);
        return;
    }

    lbl_803DC9D0 = lbl_803DC9D4;
    if (curLanguage < 0 || curLanguage >= 6)
    {
        mmSetDelay(oldHeap);
        return;
    }

    slot = gameTextBase->loadSlots;
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if (slot->sourceId == GAMETEXT_SEQUENCE_SOURCE_ID)
        {
            if (slot->state == 1)
            {
                slot->state = 4;
                DVDCancelAsync(&slot->fileInfo.cb, gameTextLoadCancelCallback);
            }
            if (slot->state == 3 && slot->active != 0)
            {
                mmSetFreeDelay(0);
                mm_free(slot->loadHandle);
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->loadedSize = 0;
                slot->active = 0;
            }
        }
        slot++;
    } while (i-- != 0);

    gameTextBase->fonts[GAMETEXT_SLOT_CUTSCENE].status = 1;
    slot = gameTextBase->loadSlots;
    slot = (slot->active == 0)       ? slot
           : ((++slot)->active == 0) ? slot
           : ((++slot)->active == 0) ? slot
           : ((++slot)->active == 0) ? slot
           : ((++slot)->active == 0) ? slot
           : ((++slot)->active == 0) ? slot
           : ((++slot)->active == 0) ? slot
           : ((++slot)->active == 0) ? slot
                                     : NULL;

    slot->state = 1;
    slot->dirId = sequenceSlotDir;
    slot->languageId = curLanguage;
    slot->active = 1;
    slot->sourceId = GAMETEXT_SEQUENCE_SOURCE_ID;
    sprintf(gameTextBase->path, sGameTextSequencePathFormat, sequenceId,
            ((LanguageName*)(languageTable + languageTableOffset))->name);
    setFileInfo(&slot->fileInfo);
    slot->loadHandle = loadFileByPathAsync(gameTextBase->path,
                                           &slot->loadedSize, 1, gameTextLoadCompleteCallback);
    setFileInfo(NULL);
    mmSetDelay(oldHeap);
}

void gameTextLoadForCurMap(int sourceId)
{
    u8* dirPtr;
    u8* langPtr;
    int oldHeap;
    int dirId;
    int languageId;
    GameTextLoadSlot* slot;
    GameTextLoadSlot* freeSlot;
    u8* gameTextBase;
    GameTextRuntime* runtime;
    int i;

    gameTextBase = gGameTextBase;
    runtime = (GameTextRuntime*)gameTextBase;
    oldHeap = mmSetDelay(0);
    if (getGameState() != 0 && getGameState() != 1)
    {
        mmSetDelay(oldHeap);
        return;
    }

    gGameTextLastDir = dirId = curGameTextDir;
    gGameTextLastLanguage = languageId = curLanguage;
    if (dirId < 0 || dirId >= GAMETEXT_MAP_DIR_COUNT || languageId < 0 || languageId >= GAMETEXT_LANGUAGE_COUNT)
    {
        mmSetDelay(oldHeap);
        return;
    }

    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if (slot->sourceId == sourceId)
        {
            if (slot->state == 1)
            {
                slot->state = 4;
                DVDCancelAsync(&slot->fileInfo.cb, gameTextLoadCancelCallback);
            }
            if (slot->state == 3 && slot->active != 0)
            {
                mmSetFreeDelay(0);
                if (slot->loadHandle != NULL)
                {
                    mm_free(slot->loadHandle);
                }
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->loadedSize = 0;
                slot->active = 0;
            }
        }
        slot++;
    } while (i-- != 0);

    runtime->fonts[sourceId].status = 1;
    *(dirPtr = &runtime->fonts[sourceId].dirId) = (u8)curGameTextDir;
    *(langPtr = &runtime->fonts[sourceId].languageId) = curLanguage;

    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    freeSlot = (slot->active == 0)       ? slot
               : ((++slot)->active == 0) ? slot
               : ((++slot)->active == 0) ? slot
               : ((++slot)->active == 0) ? slot
               : ((++slot)->active == 0) ? slot
               : ((++slot)->active == 0) ? slot
               : ((++slot)->active == 0) ? slot
               : ((++slot)->active == 0) ? slot
                                         : NULL;

    if (freeSlot != NULL)
    {
        int slotDir = *dirPtr;
        int slotLang = *langPtr;
        freeSlot->state = 1;
        freeSlot->dirId = slotDir;
        freeSlot->languageId = slotLang;
        freeSlot->active = 1;
        freeSlot->sourceId = sourceId;
        sprintf((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET), sGameTextMapPathFormat,
                sMapDirectoryNameTable[slotDir], sLanguageNameTable[slotLang].name);
        setFileInfo(&freeSlot->fileInfo);
        freeSlot->loadHandle = loadFileByPathAsync((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET),
                                                   &freeSlot->loadedSize, 1, gameTextLoadCompleteCallback);
        setFileInfo(NULL);
        *dirPtr = GAMETEXT_INVALID_DIR;
        *langPtr = GAMETEXT_INVALID_LANGUAGE;
    }

    mmSetDelay(oldHeap);
}

void gameTextBuildSystemFontAtlas(void)
{
    int wbytes;
    FontMetrics* base30;
    TextFont* charset;
    u8* buf;
    int sizeA;
    int y;
    int sizeB;
    int x;
    u8* bufA;
    OSFontHeader* bufB;
    int savedHeap;
    int count;
    TextGlyph* glyph;
    u8* fontData;
    u8 s[3];
    s32 width;

    fontData = (u8*)gGameTextFontData;
    base30 = gGameTextFontMetrics;
    charset = &gGameTextCharsets[GAMETEXT_SLOT_ERROR];
    savedHeap = mmSetDelay(0);
    buf = mmAlloc(0x120, 0x1a, 0);
    switch (OSGetFontEncode())
    {
    case 0:
        sizeA = 0x3000;
        sizeB = 0x10120;
        curLanguage = 0;
        gGameTextFontIsSjis = 0;
        break;
    case 1:
        sizeA = 0x4d000;
        sizeB = 0x90ee4;
        curLanguage = 4;
        gGameTextFontIsSjis = 1;
        break;
    }
    bufA = mmAlloc(sizeA, 0x1a, 0);
    bufB = mmAlloc(sizeB, 0x1a, 0);
    OSLoadFont(bufB, bufA);
    if (charset->glyphCount == 0)
    {
        if (gGameTextFontIsSjis)
        {
            charset->glyphs = (TextGlyph*)fontData;
            charset->glyphCount = 0x55;
            charset->entries = (GameTextDef*)(fontData + 0x8ec);
            charset->entryCount = 7;
        }
        else
        {
            charset->glyphs = (TextGlyph*)(fontData + 0x940);
            charset->glyphCount = 0x2b;
            charset->entries = (GameTextDef*)(fontData + 0xe24);
            charset->entryCount = 7;
        }
    }
    charset->textures[0] = (Texture*)textureAlloc(0x200, 0x60, 0, 0, 0, 0, 0, 1, 1);
    base30[6].glyphCount = charset->glyphCount;
    base30[6].unk04 = 0x30;
    base30[6].unk05 = 0x20;
    base30[6].maxWidth = 0;
    base30[6].lineHeight = 0x18;
    count = charset->glyphCount;
    glyph = charset->glyphs;
    x = 0;
    y = 0;
    while (count--)
    {
        if (gGameTextFontIsSjis)
        {
            int c;
            u32 val;
            int hi;
            u8 lo;
            c = glyph->key;
            val = lookupSjisGlyph(c);
            hi = (val >> 8) & 0xff;
            lo = val;
            if (hi == 0)
            {
                s[0] = lo;
                s[1] = 0;
            }
            else
            {
                s[0] = hi;
                s[1] = lo;
                s[2] = 0;
            }
        }
        else
        {
            s[0] = glyph->key;
            s[1] = 0;
        }
        OSGetFontWidth((const char*)s, &width);
        if (width > base30[6].maxWidth)
        {
            base30[6].maxWidth = width;
        }
        wbytes = width >> 3;
        if ((width & 7) != 0)
        {
            wbytes++;
        }
        {
            int j;
            u32* q = (u32*)buf;
            j = 0x48;
            while (j--)
            {
                *q++ = 0;
            }
        }
        OSGetFontTexel((const char*)s, buf, 0, 6, &width);
        if (x + 0x18 > 0x200)
        {
            x = 0;
            y += 0x18;
        }
        glyph->u = x;
        glyph->v = y;
        glyph->offsetX = 0;
        glyph->advanceX = 0;
        glyph->offsetY = 0;
        glyph->advanceY = 0;
        glyph->width = width;
        glyph->height = 0x18;
        glyph->font = 6;
        glyph->page = 0;
        {
            int ty;
            int tyEnd;
            int tx;
            int txEnd;
            int row;
            u8* dst;
            u32* src;
            int j2;

            src = (u32*)buf;
            ty = glyph->v >> 3;
            tx = glyph->u >> 3;
            row = ty;
            txEnd = tx + 3;
            tyEnd = ty + 3;
            for (; row < tyEnd; row++)
            {
                for (j2 = tx; j2 < txEnd; j2++)
                {
                    int k;
                    dst = (u8*)charset->textures[0] + (j2 << 5);
                    dst += gGameTextFontTexRowPitch * row;
                    for (k = 0; k < 8; k++)
                    {
                        *(u32*)(dst + 0x60 + k * 4) = *src++;
                    }
                }
            }
        }
        x += wbytes << 3;
        glyph++;
    }
    DCFlushRange((u8*)charset->textures[0] + 0x60, 0x20000);
    mm_free(bufA);
    mm_free(bufB);
    mm_free(buf);
    mmSetDelay(savedHeap);
    charset->status = 2;
}

/* Install a completed language/charset load, upload its textures, and compact
   the relocatable text tables. */
void gameTextFinalizeLoad(GameTextLoadSlot* loadSlot)
{
    int** textureSlot;
    u16* p;
    u32 bpp;
    int ofs;
    GameTextStringTable* stringTable;
    u32 w;
    u32 h;
    int i;
    u8* txt;
    int* texHdr;
    GameTextTableHeader* hdr;
    u16* texStart;
    int* data;
    u16 kind;
    u8* entries;
    int numStrings;
    int* strs;
    int n;
    u32 size;
    u16* newBuf;
    u16* old;
    int delta;
    int* strs2;
    TextFont* cs;

    DCStoreRange(loadSlot->loadHandle, loadSlot->loadedSize);
    if (loadSlot->sourceId == 1)
    {
        cs = &gGameTextCharsets[1];
    }
    else if (loadSlot->sourceId == 3)
    {
        cs = &gGameTextCharsets[3];
    }
    else
    {
        cs = &gGameTextCharsets[0];
        curGameTextDir = loadSlot->dirId;
        curLanguage = loadSlot->languageId;
    }
    data = loadSlot->loadHandle;
    cs->glyphCount = data[0];
    if (cs->glyphCount == 0)
    {
        cs->status = 3;
        loadSlot->state = 6;
        return;
    }
    cs->glyphs = (TextGlyph*)(data + 1);
    hdr = (GameTextTableHeader*)((u8*)data + cs->glyphCount * 16);
    cs->entryCount = hdr->entryCount;
    ofs = hdr->textureOffset;
    entries = (u8*)(hdr + 1);
    cs->entries = (GameTextDef*)entries;
    stringTable = (GameTextStringTable*)(entries + cs->entryCount * 12);
    numStrings = stringTable->count;
    strs = stringTable->offsets;
    for (i = 0; i < cs->entryCount; i++)
    {
        cs->entries[i].strings = (char**)(strs + (int)cs->entries[i].strings);
    }
    txt = (u8*)(numStrings * 4 + (u32)stringTable->offsets);
    {
        int j;
        for (j = 0; j < numStrings; j++)
        {
            strs[j] = strs[j] + (int)txt;
        }
    }
    texHdr = (int*)(txt + ofs);
    p = (u16*)((u8*)texHdr + texHdr[0]);
    p += 2;
    texStart = p;
    textureSlot = (int**)cs;
    while (1)
    {
        kind = p[0];
        bpp = p[1];
        w = p[2];
        h = p[3];
        p += 4;
        if (w == 0 && h == 0)
        {
            break;
        }
        switch (kind)
        {
        case 1:
            kind = 5;
            break;
        case 2:
            kind = 0;
            break;
        }
        if (textureSlot[4] != NULL)
        {
            mmSetFreeDelay(0);
            mm_free(textureSlot[4]);
            mmSetFreeDelay(2);
        }
        textureSlot[4] = (int*)textureAlloc(w, h, kind, 0, 0, 0, 0, 1, 1);
        if (textureSlot[4] != NULL)
        {
            if (bpp == 4)
            {
                u8* src8 = (u8*)p;
                u8* dst8 = (u8*)textureSlot[4] + 0x60;
                n = (int)(w * h) >> 1;
                while (n--)
                {
                    *dst8++ = *src8++;
                }
                DCFlushRange((u8*)textureSlot[4] + 0x60, ((Texture*)textureSlot[4])->dataSize);
            }
            else
            {
                u16* src16 = p;
                u16* dst16 = (u16*)((u8*)textureSlot[4] + 0x60);
                n = w * h;
                while (n--)
                {
                    *dst16++ = *src16++;
                }
                DCFlushRange((u8*)textureSlot[4] + 0x60, ((Texture*)textureSlot[4])->dataSize);
            }
        }
        {
            u32 area = w * h;
            p += (int)(area * bpp) >> 4;
        }
        textureSlot = textureSlot + 1;
    }
    size = (u32)((u8*)texStart - (u8*)loadSlot->loadHandle);
    newBuf = mmAlloc(size, 0x1a, 0);
    n = size >> 1;
    {
        u16* d = newBuf;
        u16* s;
        old = loadSlot->loadHandle;
        s = old;
        delta = (int)newBuf - (int)old;
        while (n--)
        {
            *d++ = *s++;
        }
    }
    cs->glyphs = (TextGlyph*)((u8*)cs->glyphs + delta);
    cs->entries = (GameTextDef*)((u8*)cs->entries + delta);
    for (i = 0; i < cs->entryCount; i++)
    {
        int ev = (int)cs->entries[i].strings;
        cs->entries[i].strings = (char**)(ev + delta);
    }
    strs2 = (int*)((u8*)strs + delta);
    for (i = 0; i < numStrings; i++)
    {
        strs2[i] += delta;
    }
    mmSetFreeDelay(0);
    mm_free(loadSlot->loadHandle);
    loadSlot->loadHandle = NULL;
    mmSetFreeDelay(2);
    loadSlot->loadHandle = newBuf;
    cs->status = 2;
    loadSlot->state = 3;
}

static void gameTextLoadCancelCallback(s32 result, DVDCommandBlock* block) {
    int i;
    GameTextLoadSlot* slot = curGameTexts;
    (void)result;
    for (i = 8; i != 0; i--) {
        if (block == &slot->fileInfo.cb) {
            slot->state = 5;
            return;
        }
        slot++;
    }
}

static void gameTextLoadCompleteCallback(s32 status, DVDFileInfo* fileInfo) {
    int i;
    GameTextLoadSlot* slot = curGameTexts;
    if (status != -1 && status != -3) {
        for (i = 8; i != 0; i--) {
            if (fileInfo == &slot->fileInfo) {
                slot->state = 2;
                return;
            }
            slot++;
        }
    } else {
        slot = curGameTexts;
        for (i = 8; i != 0; i--) {
            if (fileInfo == &slot->fileInfo) {
                slot->state = 5;
                return;
            }
            slot++;
        }
    }
}

void gameTextSetDrawFunc(void* fn)
{
    gameTextDrawFunc = fn;
}

int gameTextSaveDir(int x)
{
    if (gGameTextSequenceMode == 0)
    {
        gGameTextSavedDir = x;
        return 1;
    }
    return 0;
}
