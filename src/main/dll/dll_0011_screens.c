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

extern void GameBit_Set(int eventId, int value);
extern u32 GameBit_Get(int eventId);
extern void mm_free(void* ptr);
extern void* getLastSavedGameTexts(void);
extern void* gameTextGet(int idx);
extern void* mmAlloc(u32 size, u32 tag, void* name);
extern void* getCurGameText(void);
extern void gameTextLoadDir(int dirId);
extern void loadAssetFileById(void** out, int id);

extern char* sMapDirectoryNameTable[];
extern u8 lbl_803A4218[];   /* taskId -> "TaskTextsNNN" directory index */
extern s16 lbl_803119E0[];  /* taskId -> hint text slot */

extern u32 lbl_803DD4A0;    /* heap buffer */
extern u32 lbl_803DD4A4;    /* buffer size */
extern u32 lbl_803DD4A8;    /* dirty flag */
extern u32 lbl_803DD4AC;    /* cached screen id */

enum
{
    SCREENS_TASK_COUNT = 0xd,            /* number of task-hint slots */
    SCREENS_GAMEBIT_TASK_BASE = 0xf10,   /* base game bit for task-completed flags */
    SCREENS_GAMETEXT_HINT_BASE = 0xf4,   /* base game-text id for hint strings */
    SCREENS_BANK_BASE = 0x12f,           /* base game-bit bank for task ids */
};

void screens_release(void)
{
}

u8 getNextTaskHintText(void)
{
    u8* p = (u8*)getLastSavedGameTexts();
    return p[5];
}

void screens_initialise(void)
{
    lbl_803DD4AC = (u32) - 1;
    lbl_803DD4A0 = 0;
    lbl_803DD4A4 = 0;
    lbl_803DD4A8 = 0;
}

void* saveGameGetCurHint(void)
{
    return gameTextGet((s32) * (u8*)((char*)getLastSavedGameTexts() + 0x5) + SCREENS_GAMETEXT_HINT_BASE);
}

void loadTaskTexts(void)
{
    char** pp;
    int i;
    u8* s;
    int idx;
    u8* p;
    int n = SCREENS_TASK_COUNT;
    p = &lbl_803A4218[SCREENS_TASK_COUNT];
    while (p--, n-- != 0)
    {
        *p = 0xff;
    }
    i = 0x49; /* 73: directory name table size */
    pp = &sMapDirectoryNameTable[0x49];
    while (pp--, i-- != 0)
    {
        s = (u8*)*pp;
        if (s[0] == 'T' && s[1] == 'a' && s[2] == 's' && s[3] == 'k' &&
            s[4] == 'T' && s[5] == 'e' && s[6] == 'x' && s[7] == 't' && s[8] == 's')
        {
            idx = (s[9] - '0') * 100 + (s[10] - '0') * 10 + (s[11] - '0');
            if (idx < SCREENS_TASK_COUNT)
            {
                lbl_803A4218[idx] = (u8)i;
            }
        }
    }
}

u8 getCurTaskHintTextMap(void)
{
    return (u8)lbl_803119E0[*(u8*)((char*)getLastSavedGameTexts() + 0x5)];
}

void hintTextFn_800ea174(u8* out)
{
    u8* texts = (u8*)getLastSavedGameTexts();
    s16 i;
    for (i = 0; i < SCREENS_TASK_COUNT; i++)
    {
        out[i] = (u8)GameBit_Get(i + SCREENS_GAMEBIT_TASK_BASE);
    }
    out[lbl_803119E0[texts[5]]] = 1;
}

int hintTextMapFn_800ea264(void)
{
    void* r = getCurGameText();
    u8* t = (u8*)getLastSavedGameTexts();
    gameTextLoadDir(lbl_803A4218[lbl_803119E0[t[5]]]);
    return (int)r;
}

#pragma opt_common_subs off
void gameBitFn_800ea2e0(u8 id)
{
    u8* texts;
    u8 wasNew;
    s16* taskMap;
    u32 i;
    s16 cachedBank;
    u32 cachedBits;
    u32 mask;
    u32 bits;
    s16 bank;
    s16 historyIdx;

    texts = (u8*)getLastSavedGameTexts();
    cachedBank = -1;

    if (texts[6] == 0)
    {
        for (i = 1, taskMap = &lbl_803119E0[1]; (s16)i < 0xce; i++) /* 206: hint-slot map entries scanned */
        {
            if ((*taskMap == 0xffff) || (*taskMap == -1))
            {
                mask = 1 << ((u8)i % 32);
                bank = (s16)(((u32)(u8)i >> 5) + SCREENS_BANK_BASE);
                bits = GameBit_Get(bank);
                if ((bits & mask) == 0)
                {
                    bits |= mask;
                    GameBit_Set(bank, bits);
                }
            }
            taskMap++;
        }
    }

    mask = 1 << (id % 32);
    bank = (s16)(((u32)id >> 5) + SCREENS_BANK_BASE);
    bits = GameBit_Get(bank);
    if ((bits & mask) != 0)
    {
        wasNew = 0;
    }
    else
    {
        bits |= mask;
        GameBit_Set(bank, bits);
        wasNew = 1;
    }

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
                bank = (s16)(((u32)texts[5] >> 5) + SCREENS_BANK_BASE);
                if (bank != cachedBank)
                {
                    cachedBank = bank;
                    cachedBits = GameBit_Get(bank);
                }
                mask = 1 << (texts[5] % 32);
            }
            while ((cachedBits & mask) != 0);
        }
    }
}
#pragma opt_common_subs reset

void screens_remove(void)
{
    if (lbl_803DD4A0 != 0)
    {
        mm_free((void*)lbl_803DD4A0);
        lbl_803DD4A0 = 0;
        lbl_803DD4AC = (u32) - 1;
        lbl_803DD4A4 = 0;
        lbl_803DD4A8 = 0;
    }
}

/* like screens_remove but only frees buffer, size and cached-id (leaves the
 * dirty flag), and clears them in a different order */
void screens_remove2(void)
{
    if (lbl_803DD4A0 != 0)
    {
        mm_free((void*)lbl_803DD4A0);
        lbl_803DD4A0 = 0;
        lbl_803DD4A4 = 0;
        lbl_803DD4AC = (u32) - 1;
    }
}

void screens_show(int id)
{
    int* asset = NULL;
    int count;
    int offset, size;
    if ((int)lbl_803DD4AC != id)
    {
        loadAssetFileById((void**)&asset, 0x19);
        count = 0;
        while (asset[count] != -1)
        {
            count++;
        }
        if (id < 0 || id >= count - 1) id = 0;
        offset = asset[id];
        size = asset[id + 1] - offset;
        if (size != (int)lbl_803DD4A4)
        {
            if (lbl_803DD4A0 != 0) mm_free((void*)lbl_803DD4A0);
            lbl_803DD4A0 = (u32)mmAlloc(size, 2, NULL);
        }
        lbl_803DD4A4 = size;
        getTabEntry((void*)lbl_803DD4A0, 0x18, offset, size);
        mm_free(asset);
        lbl_803DD4AC = id;
    }
    lbl_803DD4A8 = 1;
}
