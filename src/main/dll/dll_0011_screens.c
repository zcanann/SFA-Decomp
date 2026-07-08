/*
 * dll_0011 (screens) - task-hint text bookkeeping and the loading/help
 * "screens" overlay buffer.
 *
 * Hint tracking: the saved-game block (getLastSavedGameTexts) keeps a
 * small history of completed task ids at [0..4], a count at [6] and the
 * "current" task at [5]. New task completions are recorded as game bits
 * in banks based at 0x12F (one bit per task id), and the per-task text
 * directories named "TaskTextsNNN" are indexed through the directory-index
 * table and the hint-slot map.
 *
 * Screens overlay: screens_show streams a help/loading screen entry from
 * tab file 0x18 (entry table asset 0x19) into a heap buffer, caching the
 * current id and size and a "dirty" flag (heap buffer / size / dirty /
 * cached-id overlay globals).
 */
#include "main/asset_load.h"
#include "main/pi_dolphin.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/gamebits.h"
#include "main/dll/dll_0015_curves.h"

extern u32 lbl_803DD4A0;
extern u32 lbl_803DD4A4;
extern u32 lbl_803DD4A8;
extern u32 lbl_803DD4AC;
extern char* sMapDirectoryNameTable[];
extern u8 lbl_803A4218[];
extern s16 lbl_803119E0[];
extern void mm_free(u32);
extern void* gameTextGet(int textId);
extern void* mmAlloc(int size, int type, int flag);
extern int getCurGameText(void);
extern void gameTextLoadDir(int dirId);
extern void loadAssetFileById(void** out, int id);

void hintTextFn_800ea174(u8* out)
{
    u8* texts = getLastSavedGameTexts();
    s16 i;
    for (i = 0; i < 0xd; i++)
    {
        out[i] = mainGetBit(i + 0xf10);
    }
    out[lbl_803119E0[texts[5]]] = 1;
}

u8 getCurTaskHintTextMap(void)
{
    u8* texts = getLastSavedGameTexts();
    return (u8)(s32)lbl_803119E0[texts[5]];
}

void* saveGameGetCurHint(void)
{
    u8* texts = getLastSavedGameTexts();
    return gameTextGet((s32)texts[5] + 0xf4);
}

int hintTextMapFn_800ea264(void)
{
    int ret = getCurGameText();
    u8* texts = getLastSavedGameTexts();
    gameTextLoadDir(lbl_803A4218[lbl_803119E0[texts[5]]]);
    return ret;
}

u8 getNextTaskHintText(void)
{
    u8* p = getLastSavedGameTexts();
    return p[5];
}

static inline void markTaskBit(u8 id)
{
    int bank;
    u32 mask;
    u32 bits;

    mask = 1 << (id % 32);
    bank = (s16)(((u32)id >> 5) + 0x12f);
    bits = mainGetBit(bank);
    if ((bits & mask) == 0)
    {
        bits |= mask;
        mainSetBits(bank, bits);
    }
}

static inline int setTaskBit(u8 id)
{
    u32 mask;
    int bank;
    u32 bits;

    mask = 1 << (id % 32);
    bank = (s16)(((u32)id >> 5) + 0x12f);
    bits = mainGetBit(bank);
    if ((bits & mask) != 0)
    {
        return 0;
    }
    bits |= mask;
    mainSetBits(bank, bits);
    return 1;
}

void gameBitFn_800ea2e0(u8 id)
{
    u8* texts;
    u8 wasNew;
    u32 i;
    s16 cachedBank;
    u32 cachedBits;
    int dwBank;
    u32 dwMask;
    s16 historyIdx;

    texts = getLastSavedGameTexts();
    cachedBank = -1;

    if (texts[6] == 0)
    {
        for (i = 1; (s16)i < 0xce; i++)
        {
            if ((lbl_803119E0[i] == 0xffff) || (lbl_803119E0[i] == -1))
            {
                markTaskBit((u8)i);
            }
        }
    }

    wasNew = setTaskBit(id);

    if (wasNew)
    {
        if (texts[6] != 5)
        {
            texts[6]++;
        }

        for (historyIdx = 4; historyIdx != 0; historyIdx--)
        {
            texts[historyIdx] = texts[historyIdx - 1];
        }
        texts[0] = id;

        if (texts[5] == id)
        {
            do
            {
                texts[5]++;
                dwBank = (s16)(((u32)texts[5] >> 5) + 0x12f);
                if (dwBank != cachedBank)
                {
                    cachedBank = dwBank;
                    cachedBits = mainGetBit(dwBank);
                }
                dwMask = 1 << (texts[5] % 32);
            } while ((cachedBits & dwMask) != 0);
        }
    }
}

void loadTaskTexts(void)
{
    char** pp;
    int i;
    u8* name;
    int idx;
    u8* dst;
    int n = 0xd;
    dst = &lbl_803A4218[0xd];
    while (dst--, n-- != 0)
    {
        *dst = 0xff;
    }
    i = 0x49;
    pp = &sMapDirectoryNameTable[0x49];
    while (pp--, i-- != 0)
    {
        name = (u8*)*pp;
        if (name[0] == 'T' && name[1] == 'a' && name[2] == 's' && name[3] == 'k' && name[4] == 'T' && name[5] == 'e' &&
            name[6] == 'x' && name[7] == 't' && name[8] == 's')
        {
            idx = (name[9] - '0') * 100 + (name[10] - '0') * 10 + (name[11] - '0');
            if (idx < 0xd)
            {
                lbl_803A4218[idx] = i;
            }
        }
    }
}

void screens_run(void)
{
    if (lbl_803DD4A0 != 0)
    {
        mm_free(lbl_803DD4A0);
        lbl_803DD4A0 = 0;
        lbl_803DD4A4 = 0;
        lbl_803DD4AC = (u32)-1;
    }
}

void screens_remove(void)
{
    if (lbl_803DD4A0 != 0)
    {
        mm_free(lbl_803DD4A0);
        lbl_803DD4A0 = 0;
        lbl_803DD4AC = (u32)-1;
        lbl_803DD4A4 = 0;
        lbl_803DD4A8 = 0;
    }
}

void screens_show(int id)
{
    int* asset = NULL;
    int* p;
    int count;
    int offset, size;
    if ((int)lbl_803DD4AC != id)
    {
        loadAssetFileById((void**)&asset, MLDF_FILEID_SCREENS_TAB);
        count = 0;
        while (asset[count] != -1)
        {
            count++;
        }
        if (id < 0 || id >= count - 1)
            id = 0;
        offset = asset[id];
        size = asset[id + 1] - offset;
        if (size != (int)lbl_803DD4A4)
        {
            if (lbl_803DD4A0 != 0)
                mm_free(lbl_803DD4A0);
            lbl_803DD4A0 = (u32)mmAlloc(size, 2, 0);
        }
        lbl_803DD4A4 = size;
        getTabEntry((void*)lbl_803DD4A0, MLDF_FILEID_SCREENS_BIN, offset, size);
        mm_free((u32)asset);
        lbl_803DD4AC = id;
    }
    lbl_803DD4A8 = 1;
}

void screens_release(void)
{
}

void screens_initialise(void)
{
    lbl_803DD4AC = (u32)-1;
    lbl_803DD4A0 = 0;
    lbl_803DD4A4 = 0;
    lbl_803DD4A8 = 0;
}
