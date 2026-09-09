#include "dlls/object_descriptor.h"
#include "main/pi_dolphin.h"
#include "main/mapEventTypes.h"
#include "main/dll/dll_0015_curves.h"
#include "main/textrender_api.h"
#include "main/gametext_api.h"
#include "main/asset_load.h"
#include "main/gamebits_api.h"
#include "main/mm.h"
#include "main/dll/dll_0011_screens.h"
#include "main/dll/hint_text_api.h"
#include "main/dll/dll_0011_screens_api.h"

u32 gScreenDataId;
u32 lbl_803DD4A8;
u32 gScreenDataSize;
void* gScreenDataBuffer;

u8 gTaskTextDirIds[0x10];
extern s16 gTaskHintMapData[];

void hintTextGetAvailableMaps(u8* out)
{
    u8* texts = getLastSavedGameTexts();
    s16 i;
    for (i = 0; i < 0xd; i++)
    {
        out[i] = mainGetBit(i + 0xf10);
    }
    out[gTaskHintMapData[texts[5]]] = 1;
}

u8 getCurTaskHintTextMap(void)
{
    u8* texts = getLastSavedGameTexts();
    return (u8)(s32)gTaskHintMapData[texts[5]];
}

GameTextDef* saveGameGetCurHint(void)
{
    u8* texts = getLastSavedGameTexts();
    return gameTextGet((s32)texts[5] + 0xf4);
}

int hintTextLoadTaskMapTexts(void)
{
    int ret = getCurGameText();
    u8* texts = getLastSavedGameTexts();
    gameTextLoadDir(gTaskTextDirIds[gTaskHintMapData[texts[5]]]);
    return ret;
}

u16 getNextTaskHintText(void)
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

void taskHintRecordCompletedTask(u8 id)
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
            if ((gTaskHintMapData[i] == 0xffff) || (gTaskHintMapData[i] == -1))
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
    dst = &gTaskTextDirIds[0xd];
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
                gTaskTextDirIds[idx] = i;
            }
        }
    }
}

void screens_run(int unused)
{
    if (gScreenDataBuffer != 0)
    {
        mm_free((void*)gScreenDataBuffer);
        gScreenDataBuffer = 0;
        gScreenDataSize = 0;
        gScreenDataId = (u32)-1;
    }
}

void screens_remove(void)
{
    if (gScreenDataBuffer != 0)
    {
        mm_free((void*)gScreenDataBuffer);
        gScreenDataBuffer = 0;
        gScreenDataId = (u32)-1;
        gScreenDataSize = 0;
        lbl_803DD4A8 = 0;
    }
}

void screens_show(int id)
{
    int* asset = NULL;
    int count;
    int offset, size;
    if ((int)gScreenDataId != id)
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
        if (size != (int)gScreenDataSize)
        {
            if (gScreenDataBuffer != 0)
                mm_free((void*)gScreenDataBuffer);
            gScreenDataBuffer = mmAlloc(size, 2, 0);
        }
        gScreenDataSize = size;
        getTabEntry((void*)gScreenDataBuffer, MLDF_FILEID_SCREENS_BIN, offset, size);
        mm_free(asset);
        gScreenDataId = id;
    }
    lbl_803DD4A8 = 1;
}

void screens_release(void)
{
}

void screens_initialise(void)
{
    gScreenDataId = (u32)-1;
    gScreenDataBuffer = 0;
    gScreenDataSize = 0;
    lbl_803DD4A8 = 0;
}

s16 gTaskHintMapData[256] = {
    -1, 0, 0, 0, 0, -1, -1, 0, 0, 6, 6, 6, 6, 6, 6, -1,
    -1, 2, 2, 5, 5, 5, 5, 6, -1, -1, 6, 6, 6, 6, 6, 6,
    -1, 5, -1, 5, 6, 7, -1, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, -1, -1, -1, -1, 7, 6, 9, 9, 10, 10, 10, 10, 10, -1, 9,
    9, 9, 9, 9, 9, 6, -1, 0, 0, 12, -1, 12, -1, -1, 12, 6,
    11, -1, 11, 11, 11, 11, 11, 11, -1, -1, -1, -1, 11, -1, 12, 8,
    8, 8, 8, -1, -1, -1, 6, 4, 4, 4, -1, 4, -1, -1, -1, 4,
    -1, 0, 6, 6, 3, -1, 3, 3, 3, 3, -1, -1, -1, 3, 10, 10,
    10, 10, -1, 6, -1, 6, 5, 5, 5, -1, 0, -1, 6, 1, -1, -1,
    1, 1, 1, 1, -1, 1, 1, -1, -1, -1, -1, -1, -1, 1, 12, 8,
    -1, 8, -1, -1, 6, 6, 3, 3, -1, 3, -1, -1, -1, 3, 3, 0,
    0, 0, 0, 0, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,
};
typedef struct ScreensDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback show;
    ObjectDescriptorCallback remove;
    ObjectDescriptorCallback run;
} ScreensDllInterface;

ScreensDllInterface screens_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)screens_initialise,
    (ObjectDescriptorCallback)screens_release,
    0,
    (ObjectDescriptorCallback)screens_show,
    (ObjectDescriptorCallback)screens_remove,
    (ObjectDescriptorCallback)screens_run,
};
