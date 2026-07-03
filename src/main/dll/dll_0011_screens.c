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
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/gamebits.h"
#include "main/dll/dll_0015_curves.h"
extern u64 FUN_80003494();
extern u32 FUN_80006768();
extern u32 FUN_8000676c();
extern u32 FUN_80006770();
extern int FUN_80006b7c();
extern u32 FUN_80006b84();
extern u32 FUN_80006b8c();
extern u32 FUN_80006c20();
extern u32 FUN_80017488();
extern u32 FUN_80017498();
extern u32 FUN_80017500();
extern u32 FUN_80017690();
extern u64 FUN_80017698();
extern u32 FUN_800176cc();
extern u32 FUN_800176dc();
extern u32 FUN_80042b9c();
extern u32 FUN_8005d018();
extern u32 FUN_80072564();
extern u32 FUN_800d783c();
extern u32 FUN_8011e80c();
extern s64 FUN_80286830();
extern u32 FUN_80286834();
extern u32 FUN_8028687c();
extern u32 FUN_80286880();
extern u32 DAT_802c28f0;
extern u32 DAT_802c28f4;
extern u32 DAT_802c28f8;
extern short DAT_80312370;
extern short DAT_80312460;
extern u32 DAT_80312630;
extern short DAT_80312632;
extern char DAT_803a3be0;
extern u32 DAT_803a3be1;
extern u32 DAT_803a3be2;
extern u32 DAT_803a3c1c;
extern u32 DAT_803a3dac;
extern u8 gGameplayPreviewSettings;
extern u32 DAT_803a3e26;
extern u32 DAT_803a3e27;
extern u32 DAT_803a3e28;
extern u32 DAT_803a3e2a;
extern u32 DAT_803a3e2c;
extern u32 DAT_803a3e2d;
extern u32 gGameplayPreviewColorRed;
extern u32 gGameplayPreviewColorGreen;
extern u32 gGameplayPreviewColorBlue;
extern u32 gGameplayRegisteredDebugOptions;
extern u8 DAT_803a3f08;
extern u32 DAT_803a3f09;
extern u32 DAT_803a3f0c;
extern u32 DAT_803a3f0e;
extern u32 DAT_803a3f12;
extern u32 DAT_803a3f14;
extern u32 DAT_803a3f15;
extern u32 DAT_803a3f18;
extern u32 DAT_803a3f1a;
extern u32 DAT_803a3f1e;
extern u32 DAT_803a3f21;
extern char DAT_803a3f24;
extern u32 DAT_803a3f25;
extern u32 DAT_803a3f26;
extern u32 DAT_803a3f27;
extern u32 DAT_803a3f28;
extern u32 DAT_803a3f29;
extern u32 DAT_803a3f2b;
extern u32 DAT_803a4070;
extern u32 DAT_803a4074;
extern u32 DAT_803a4078;
extern u32 DAT_803a407c;
extern u32 DAT_803a4460;
extern u32 DAT_803a4465;
extern u32 DAT_803a458c;
extern u32 DAT_803a4590;
extern u32 DAT_803a4594;
extern u32 DAT_803a4599;
extern u32 DAT_803a459a;
extern u32 DAT_803a45aa;
extern u32 DAT_803a45ac;
extern u32 DAT_803a45b0;
extern u32 DAT_803a45b4;
extern u32 DAT_803a45b6;
extern u32 DAT_803a45ba;
extern u32 DAT_803a45bc;
extern u32 DAT_803a45be;
extern u32 DAT_803a45c0;
extern u32 DAT_803a45c2;
extern u32 DAT_803a45f0;
extern u32 DAT_803a45f1;
extern u32 DAT_803a45f2;
extern u32 DAT_803a45f3;
extern u32 DAT_803a4e78;
extern u32 DAT_803dc4f0;
extern u32* DAT_803dd6d0;
extern u32* gEnterSaveNameTotalWidth;
extern u32 DAT_803de100;
extern u32 DAT_803de104;
extern u32 DAT_803de10c;
extern u32* DAT_803de110;
extern f32 lbl_803E1348;
extern u32 uRam803de108;
extern void mm_free(u32);

extern u32 lbl_803DD4A0;
extern u32 lbl_803DD4A4;
extern u32 lbl_803DD4A8;
extern u32 lbl_803DD4AC;
extern void* gameTextGet(int textId);
extern void* mmAlloc(int size, int type, int flag);
extern char* sMapDirectoryNameTable[];
extern u8 lbl_803A4218[];
extern s16 lbl_803119E0[];
extern int getCurGameText(void);
extern void gameTextLoadDir(int dirId);
extern void loadAssetFileById(void** out, int id);

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void saveFileStruct_unlockCheat(u32 cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
    return;
}

u32 isCheatUnlocked(u32 cheatId)
{
    return gGameplayRegisteredDebugOptions & 1 << (cheatId & 0xff);
}

void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
    return;
}

u8* getSaveFileStruct(void)
{
    return &gGameplayPreviewSettings;
}

void loadSaveSettings(u64 arg1, u64 arg2, u64 arg3, u64 arg4,
                      u64 arg5, u64 arg6, u64 arg7,
                      u64 arg8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, DAT_803a3e26);
    FUN_80006c20(DAT_803a3e2c);
    FUN_80006768(DAT_803a3e2d, '\0');
    (**(VtableFn**)(*gEnterSaveNameTotalWidth + 0x50))(DAT_803a3e27);
    (**(VtableFn**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((u32)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((u32)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((u32)gGameplayPreviewColorBlue, 10, 0, 0, 1);
    return;
}

/* Returns the saved-game task-hint state block (history[0..4]/current[5]/count[6]). */
u8* FUN_800e82d8(void)
{
    return (u8*)&DAT_803a4460;
}

/*
 * Set or clear a map-act (event) flag. unused1/unused2 identify the act; the
 * (map,bit) pair is resolved through FUN_80286830 and the &DAT_80312460 event
 * table. setMode: 1 set, 0 clear, -1 force-set, -2 clear-without-history.
 * Setting propagates the bit into the six parallel group-status words
 * (&DAT_803a3c1c); clearing also records the (map,bit) into the recently-
 * cleared history ring at &DAT_803a3be0 unless keepTransient was requested.
 */
void FUN_800e95e8(u32 unused1, u32 unused2, int setMode)
{
    bool keepTransient;
    char foundIndex;
    u32 flags;
    char scanIndex;
    short* eventIds;
    char* entry;
    u32* groupStatuses;
    u32 shift;
    u32 newFlags;
    u32 mapId;
    char* history;
    int i;
    int j;
    s64 packed;

    packed = FUN_80286830();
    mapId = (u32)((u64)packed >> 0x20);
    shift = packed;
    history = &DAT_803a3be0;
    if (0x4fffffffff < packed)
    {
        mapId = (u32)(u8)(&DAT_803a3dac)[mapId];
    }
    if ((int)mapId < 0x78)
    {
        if ((u16)(&DAT_80312460)[mapId] != 0)
        {
            if (setMode == -1)
            {
                setMode = 1;
            }
            keepTransient = setMode == -2;
            if (keepTransient)
            {
                setMode = 0;
            }
            flags = FUN_80017690((u32)(u16)(&DAT_80312460)[mapId]);
            if (setMode == 0)
            {
                newFlags = flags & ~(1 << shift);
            }
            else
            {
                newFlags = flags | 1 << shift;
            }
            FUN_80017698((u32)(u16)(&DAT_80312460)[mapId], newFlags);
            DAT_803de104 = mapId;
            uRam803de108 = newFlags;
            if (setMode == 0)
            {
                eventIds = &DAT_80312460;
                groupStatuses = &DAT_803a3c1c;
                flags = ~(1 << shift);
                i = 0x14;
                do
                {
                    if (*eventIds == (&DAT_80312460)[mapId])
                    {
                        *groupStatuses = *groupStatuses & flags;
                    }
                    if (eventIds[1] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[1] = groupStatuses[1] & flags;
                    }
                    if (eventIds[2] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[2] = groupStatuses[2] & flags;
                    }
                    if (eventIds[3] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[3] = groupStatuses[3] & flags;
                    }
                    if (eventIds[4] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[4] = groupStatuses[4] & flags;
                    }
                    if (eventIds[5] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[5] = groupStatuses[5] & flags;
                    }
                    eventIds = eventIds + 6;
                    groupStatuses = groupStatuses + 6;
                    i = i + -1;
                }
                while (i != 0);
                if (!keepTransient)
                {
                    scanIndex = '\0';
                    i = 4;
                    entry = history;
                    do
                    {
                        if ((((((mapId == (int)*entry) && (foundIndex = scanIndex, shift == entry[1])) ||
                                    ((foundIndex = scanIndex + '\x01', mapId == entry[3] && (shift == entry[4])))
                                ) || ((foundIndex = scanIndex + '\x02', mapId == entry[6] &&
                                    (shift == entry[7])))) ||
                                ((foundIndex = scanIndex + '\x03', mapId == entry[9] && (shift == entry[10]))))
                            || ((mapId == entry[0xc] &&
                                (foundIndex = scanIndex + '\x04', shift == entry[0xd]))))
                            goto LAB_800e9628;
                        entry = entry + 0xf;
                        scanIndex = scanIndex + '\x05';
                        i = i + -1;
                    }
                    while (i != 0);
                    foundIndex = -1;
                LAB_800e9628:
                    if (foundIndex == -1)
                    {
                        i = 0;
                        j = 0x14;
                        do
                        {
                            if (*history == -1)
                            {
                                i = i * 3;
                                (&DAT_803a3be0)[i] = mapId;
                                (&DAT_803a3be1)[i] = packed;
                                (&DAT_803a3be2)[i] = 3;
                                break;
                            }
                            history = history + 3;
                            i = i + 1;
                            j = j + -1;
                        }
                        while (j != 0);
                    }
                }
            }
            else
            {
                shift = 1 << shift;
                if ((flags & shift) == 0)
                {
                    eventIds = &DAT_80312460;
                    groupStatuses = &DAT_803a3c1c;
                    i = 0x14;
                    do
                    {
                        if (*eventIds == (&DAT_80312460)[mapId])
                        {
                            *groupStatuses = *groupStatuses | shift;
                        }
                        if (eventIds[1] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[1] = groupStatuses[1] | shift;
                        }
                        if (eventIds[2] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[2] = groupStatuses[2] | shift;
                        }
                        if (eventIds[3] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[3] = groupStatuses[3] | shift;
                        }
                        if (eventIds[4] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[4] = groupStatuses[4] | shift;
                        }
                        if (eventIds[5] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[5] = groupStatuses[5] | shift;
                        }
                        eventIds = eventIds + 6;
                        groupStatuses = groupStatuses + 6;
                        i = i + -1;
                    }
                    while (i != 0);
                }
            }
        }
    }
    FUN_8028687c();
    return;
}

void SaveGame_func08_nop(void);

void screens_release(void)
{
}

void Carryable_release(void);

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

u8 getNextTaskHintText(void)
{
    u8* p = getLastSavedGameTexts();
    return p[5];
}

void SaveGame_gplayClearRestartPoint(void);

void screens_initialise(void)
{
    lbl_803DD4AC = (u32) - 1;
    lbl_803DD4A0 = 0;
    lbl_803DD4A4 = 0;
    lbl_803DD4A8 = 0;
}

void updateSavedHealth(void);

void* saveGameGetCurHint(void)
{
    return gameTextGet((s32) * (u8*)((char*)getLastSavedGameTexts() + 0x5) + 0xf4);
}

u32 SaveGame_mapGetObjGroups(int idx);

void loadTaskTexts(void)
{
    char** pp;
    int i;
    u8* s;
    int idx;
    u8* p;
    int n = 0xd;
    p = &lbl_803A4218[0xd];
    while (p--, n-- != 0)
    {
        *p = 0xff;
    }
    i = 0x49;
    pp = &sMapDirectoryNameTable[0x49];
    while (pp--, i-- != 0)
    {
        s = (u8*)*pp;
        if (s[0] == 'T' && s[1] == 'a' && s[2] == 's' && s[3] == 'k' &&
            s[4] == 'T' && s[5] == 'e' && s[6] == 'x' && s[7] == 't' && s[8] == 's')
        {
            idx = (s[9] - '0') * 100 + (s[10] - '0') * 10 + (s[11] - '0');
            if (idx < 0xd)
            {
                lbl_803A4218[idx] = i;
            }
        }
    }
}

u8 getCurTaskHintTextMap(void)
{
    return (u8)(s32)
    lbl_803119E0[*(u8*)((char*)getLastSavedGameTexts() + 0x5)];
}

void hintTextFn_800ea174(u8* out)
{
    u8* texts = getLastSavedGameTexts();
    s16 i;
    for (i = 0; i < 0xd; i++)
    {
        out[i] = GameBit_Get(i + 0xf10);
    }
    out[lbl_803119E0[texts[5]]] = 1;
}

int hintTextMapFn_800ea264(void)
{
    int r = getCurGameText();
    u8* t = getLastSavedGameTexts();
    gameTextLoadDir(lbl_803A4218[lbl_803119E0[t[5]]]);
    return r;
}

static inline void markTaskBit(u8 id)
{
    int bank;
    u32 mask;
    u32 bits;

    mask = 1 << (id % 32);
    bank = (s16)(((u32)id >> 5) + 0x12f);
    bits = GameBit_Get(bank);
    if ((bits & mask) == 0)
    {
        bits |= mask;
        GameBit_Set(bank, bits);
    }
}

static inline int setTaskBit(u8 id)
{
    u32 mask;
    int bank;
    u32 bits;

    mask = 1 << (id % 32);
    bank = (s16)(((u32)id >> 5) + 0x12f);
    bits = GameBit_Get(bank);
    if ((bits & mask) != 0)
    {
        return 0;
    }
    bits |= mask;
    GameBit_Set(bank, bits);
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
                    cachedBits = GameBit_Get(dwBank);
                }
                dwMask = 1 << (texts[5] % 32);
            }
            while ((cachedBits & dwMask) != 0);
        }
    }
}

void* fn_800E888C(u8 a, u8 b);

void screens_remove(void)
{
    if (lbl_803DD4A0 != 0)
    {
        mm_free(lbl_803DD4A0);
        lbl_803DD4A0 = 0;
        lbl_803DD4AC = (u32) - 1;
        lbl_803DD4A4 = 0;
        lbl_803DD4A8 = 0;
    }
}

void screens_remove2(void)
{
    if (lbl_803DD4A0 != 0)
    {
        mm_free(lbl_803DD4A0);
        lbl_803DD4A0 = 0;
        lbl_803DD4A4 = 0;
        lbl_803DD4AC = (u32) - 1;
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
            if (lbl_803DD4A0 != 0) mm_free(lbl_803DD4A0);
            lbl_803DD4A0 = (u32)mmAlloc(size, 2, 0);
        }
        lbl_803DD4A4 = size;
        getTabEntry((void*)lbl_803DD4A0, 0x18, offset, size);
        mm_free((u32)asset);
        lbl_803DD4AC = id;
    }
    lbl_803DD4A8 = 1;
}

void dll_60_func03(u8* sourceObj, int variant, u8* posSource, u32 flags);
