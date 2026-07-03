/*
 * dll5efunc0 (DLL 0x5E) - save-file / gameplay-state services.
 *
 * Home TU for a block of save and map-event helpers that live in the
 * 0x800e8xxx-0x800eaxxx text range and are called from many object DLLs
 * (the FUN_800exxxx symbols are mirrored as drift duplicates in sibling
 * dll_00xx files; this file holds the canonical bodies the linker resolves).
 *
 * Named entry points cover the gameplay preview/cheat settings struct
 * (cheat-unlock bitset in gGameplayRegisteredDebugOptions, preview RGB
 * volumes, getSaveFileStruct), save load/commit, the map-act flag history
 * tables, and a modgfx particle-sequence spawn (dll_5E_func03). Several
 * tiny dll_5E/5F entry stubs are no-ops.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
extern ModgfxInterface** gModgfxInterface;
extern void* memset(void* dst, int val, u32 n);
extern void* memcpy(void* dst, const void* src, u32 n);
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
extern u32* DAT_803dd6e8;
extern u32 DAT_803de100;
extern u32 DAT_803de104;
extern u32 DAT_803de10c;
extern u32* DAT_803de110;
extern f32 lbl_803E1348;
extern u32 uRam803de108;
extern u8 gDll5EFunc03SequenceData[];
extern f32 lbl_803E07C0, lbl_803E07C4, lbl_803E07C8, lbl_803E07CC, lbl_803E07D0, lbl_803E07D4;
extern f32 lbl_803E07D8, lbl_803E07DC, lbl_803E07E0, lbl_803E07E4, lbl_803E07E8, lbl_803E07EC;
extern f32 lbl_803E07F0, lbl_803E07F4, lbl_803E07F8;

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
    (**(VtableFn**)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
    (**(VtableFn**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((u32)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((u32)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((u32)gGameplayPreviewColorBlue, 10, 0, 0, 1);
    return;
}

u8* FUN_800e82d8(void)
{
    return (u8*)&DAT_803a4460;
}

void FUN_800e8630(int obj)
{
    int objId;
    u8* entry;
    int slotBase;
    int slotIdx;
    int groupsLeft;

    if ((*(u16*)&((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    slotBase = 0;
    entry = &DAT_803a3f08;
    groupsLeft = 9;
    while ((slotIdx = slotBase, *(int*)(entry + 0x168) != 0 &&
        (objId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14), objId != *(int*)(entry + 0x168))))
    {
        slotIdx = slotBase + 1;
        if ((*(int*)(entry + 0x178) == 0) || (objId == *(int*)(entry + 0x178))) break;
        slotIdx = slotBase + 2;
        if ((*(int*)(entry + 0x188) == 0) || (objId == *(int*)(entry + 0x188))) break;
        slotIdx = slotBase + 3;
        if ((*(int*)(entry + 0x198) == 0) || (objId == *(int*)(entry + 0x198))) break;
        slotIdx = slotBase + 4;
        if ((*(int*)(entry + 0x1a8) == 0) || (objId == *(int*)(entry + 0x1a8))) break;
        slotIdx = slotBase + 5;
        if ((*(int*)(entry + 0x1b8) == 0) || (objId == *(int*)(entry + 0x1b8))) break;
        slotIdx = slotBase + 6;
        if ((*(int*)(entry + 0x1c8) == 0) || (objId == *(int*)(entry + 0x1c8))) break;
        entry = entry + 0x70;
        slotBase += 7;
        groupsLeft--;
        slotIdx = slotBase;
        if (groupsLeft == 0) break;
    }
    if (slotIdx == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[slotIdx * 4] = *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    (&DAT_803a4074)[slotIdx * 4] = *(u32*)&((GameObject*)obj)->anim.localPosX;
    (&DAT_803a4078)[slotIdx * 4] = *(u32*)&((GameObject*)obj)->anim.localPosY;
    (&DAT_803a407c)[slotIdx * 4] = *(u32*)&((GameObject*)obj)->anim.localPosZ;
    *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 8) = *(u32*)&((GameObject*)obj)->anim
        .localPosX;
    *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc) = *(u32*)&((GameObject*)obj)->
        anim.localPosY;
    *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10) = *(u32*)&((GameObject*)obj)->
        anim.localPosZ;
    return;
}

u32* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}

u8 FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(u64 unused1, double arg2, u64 arg3, u64 arg4,
                  u64 arg5, u64 arg6, u64 arg7, u64 arg8)
{
    u32 savedX;
    u32 savedY;
    u32 savedZ;
    char* dst;
    int act;
    short* actFlags;
    char* src;
    char c;
    u64 saveHandle;
    u64 result;

    result = FUN_80286840();
    savedZ = DAT_802c28f8;
    savedY = DAT_802c28f4;
    savedX = DAT_802c28f0;
    src = (char*)((u64)result >> 0x20);
    memset((void*)-0x7fc5c0f8, 0, 0xf70);
    if ((*(u8*)(DAT_803de110 + 0x21) & 0x80) == 0)
    {
        memset((void*)DAT_803de110, 0, 0x6ec);
    }
    DAT_803a3f28 = 0;
    DAT_803a3f08 = 0xc;
    DAT_803a3f09 = 0xc;
    DAT_803a3f0e = 0x19;
    DAT_803a3f0c = 0;
    DAT_803a3f12 = 1;
    DAT_803a459a = 0xff;
    DAT_803a3f14 = 0xc;
    DAT_803a3f15 = 0xc;
    DAT_803a3f1a = 0x19;
    DAT_803a3f18 = 0;
    DAT_803a3f1e = 1;
    DAT_803a45aa = 0xff;
    DAT_803a3f21 = 0x14;
    DAT_803a45ac = 0xffff;
    DAT_803a45b0 = lbl_803E1348;
    DAT_803a45b4 = 0xffff;
    DAT_803a45b6 = 0xffff;
    DAT_803a45ba = 0xffff;
    DAT_803a45bc = 0xffff;
    DAT_803a45be = 0xffff;
    DAT_803a45c0 = 0xffff;
    DAT_803a45c2 = 0xffff;
    DAT_803a45f1 = 0xff;
    DAT_803a45f2 = 0xff;
    DAT_803a45f3 = 0xff;
    DAT_803a45f0 = 9;
    DAT_803a3f2b = 0;
    DAT_803a3f29 = 1;
    act = 0;
    actFlags = &DAT_80312370;
    do
    {
        if (*actFlags != 0)
        {
            (*gMapEventInterface)->setMapAct(act, 1);
        }
        actFlags = actFlags + 1;
        act++;
    }
    while (act < 0x78);
    FUN_800e95e8(7, 0, 1);
    FUN_800e95e8(7, 2, 1);
    FUN_800e95e8(7, 3, 1);
    FUN_800e95e8(7, 5, 1);
    FUN_800e95e8(7, 10, 1);
    FUN_800e95e8(0x1d, 0, 1);
    FUN_800e95e8(0x1d, 0x1f, 1);
    FUN_800e95e8(0x13, 0, 1);
    FUN_800e95e8(0x13, 0x16, 1);
    FUN_80017698(0x967, 1);
    (&DAT_803a458c)[DAT_803a3f28 * 4] = savedX;
    (&DAT_803a4590)[DAT_803a3f28 * 4] = savedY;
    (&DAT_803a4594)[DAT_803a3f28 * 4] = savedZ;
    DAT_803a4465 = 1;
    if (src == NULL)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        src = NULL;
    }
    else
    {
        dst = &DAT_803a3f24;
        do
        {
            c = *src;
            src++;
            *dst = c;
            dst++;
        }
        while (c != '\0');
    }
    saveHandle = (u64)memcpy(DAT_803de110, (void*)0x803a3f08, 0x6ec);
    c = result;
    if ((c != -1) && (DAT_803dc4f0 = c, src != NULL))
    {
        FUN_80072564(saveHandle, arg2, arg3, arg4, arg5, arg6, arg7, arg8, result & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(u32 unused1, u32 unused2, int setMode)
{
    bool isClearMode;
    char slotIdx;
    u32 flagWord;
    char slotBase;
    short* actPtr;
    char* histScan;
    u32* wordPtr;
    u32 bitIndex;
    u32 newWord;
    u32 flagId;
    char* histPtr;
    int i;
    int j;
    s64 rawId;

    rawId = FUN_80286830();
    flagId = (u32)((u64)rawId >> 0x20);
    bitIndex = rawId;
    histPtr = &DAT_803a3be0;
    if (0x4fffffffff < rawId)
    {
        flagId = (u32)(u8)(&DAT_803a3dac)[flagId];
    }
    if ((int)flagId < 0x78)
    {
        if ((u16)(&DAT_80312460)[flagId] != 0)
        {
            if (setMode == -1)
            {
                setMode = 1;
            }
            isClearMode = setMode == -2;
            if (isClearMode)
            {
                setMode = 0;
            }
            flagWord = FUN_80017690((u32)(u16)(&DAT_80312460)[flagId]);
            if (setMode == 0)
            {
                newWord = flagWord & ~(1 << bitIndex);
            }
            else
            {
                newWord = flagWord | 1 << bitIndex;
            }
            FUN_80017698((u32)(u16)(&DAT_80312460)[flagId], newWord);
            DAT_803de104 = flagId;
            uRam803de108 = newWord;
            if (setMode == 0)
            {
                actPtr = &DAT_80312460;
                wordPtr = &DAT_803a3c1c;
                flagWord = ~(1 << bitIndex);
                i = 0x14;
                do
                {
                    if (*actPtr == (&DAT_80312460)[flagId])
                    {
                        *wordPtr = *wordPtr & flagWord;
                    }
                    if (actPtr[1] == (&DAT_80312460)[flagId])
                    {
                        wordPtr[1] = wordPtr[1] & flagWord;
                    }
                    if (actPtr[2] == (&DAT_80312460)[flagId])
                    {
                        wordPtr[2] = wordPtr[2] & flagWord;
                    }
                    if (actPtr[3] == (&DAT_80312460)[flagId])
                    {
                        wordPtr[3] = wordPtr[3] & flagWord;
                    }
                    if (actPtr[4] == (&DAT_80312460)[flagId])
                    {
                        wordPtr[4] = wordPtr[4] & flagWord;
                    }
                    if (actPtr[5] == (&DAT_80312460)[flagId])
                    {
                        wordPtr[5] = wordPtr[5] & flagWord;
                    }
                    actPtr = actPtr + 6;
                    wordPtr = wordPtr + 6;
                    i--;
                }
                while (i != 0);
                if (!isClearMode)
                {
                    slotBase = '\0';
                    i = 4;
                    histScan = histPtr;
                    do
                    {
                        if ((((((flagId == (int)*histScan) && (slotIdx = slotBase, bitIndex == histScan[1])) ||
                                    ((slotIdx = slotBase + '\x01', flagId == histScan[3] && (bitIndex == histScan[4])))
                                ) || ((slotIdx = slotBase + '\x02', flagId == histScan[6] &&
                                    (bitIndex == histScan[7])))) ||
                                ((slotIdx = slotBase + '\x03', flagId == histScan[9] && (bitIndex == histScan[10]))))
                            || ((flagId == histScan[0xc] &&
                                (slotIdx = slotBase + '\x04', bitIndex == histScan[0xd]))))
                            goto LAB_800e9628;
                        histScan = histScan + 0xf;
                        slotBase = slotBase + '\x05';
                        i--;
                    }
                    while (i != 0);
                    slotIdx = -1;
                LAB_800e9628:
                    if (slotIdx == -1)
                    {
                        i = 0;
                        j = 0x14;
                        do
                        {
                            if (*histPtr == -1)
                            {
                                i = i * 3;
                                (&DAT_803a3be0)[i] = flagId;
                                (&DAT_803a3be1)[i] = rawId;
                                (&DAT_803a3be2)[i] = 3;
                                break;
                            }
                            histPtr = histPtr + 3;
                            i++;
                            j--;
                        }
                        while (j != 0);
                    }
                }
            }
            else
            {
                bitIndex = 1 << bitIndex;
                if ((flagWord & bitIndex) == 0)
                {
                    actPtr = &DAT_80312460;
                    wordPtr = &DAT_803a3c1c;
                    i = 0x14;
                    do
                    {
                        if (*actPtr == (&DAT_80312460)[flagId])
                        {
                            *wordPtr = *wordPtr | bitIndex;
                        }
                        if (actPtr[1] == (&DAT_80312460)[flagId])
                        {
                            wordPtr[1] = wordPtr[1] | bitIndex;
                        }
                        if (actPtr[2] == (&DAT_80312460)[flagId])
                        {
                            wordPtr[2] = wordPtr[2] | bitIndex;
                        }
                        if (actPtr[3] == (&DAT_80312460)[flagId])
                        {
                            wordPtr[3] = wordPtr[3] | bitIndex;
                        }
                        if (actPtr[4] == (&DAT_80312460)[flagId])
                        {
                            wordPtr[4] = wordPtr[4] | bitIndex;
                        }
                        if (actPtr[5] == (&DAT_80312460)[flagId])
                        {
                            wordPtr[5] = wordPtr[5] | bitIndex;
                        }
                        actPtr = actPtr + 6;
                        wordPtr = wordPtr + 6;
                        i--;
                    }
                    while (i != 0);
                }
            }
        }
    }
    FUN_8028687c();
    return;
}

void FUN_800e9e9c(void)
{
    u32 slotIdx;
    int saveResult;
    u32 sizeArg;

    DAT_803de10c = 0xff;
    DAT_803de104 = 0xffffffff;
    FUN_80042b9c(0, 0, 1);
    sizeArg = 0x884;
    memset((void*)-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    slotIdx = DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[slotIdx * 4], (double)(float)(&DAT_803a4590)[slotIdx * 4],
                 (double)(float)(&DAT_803a4594)[slotIdx * 4],
                 (int)(char)(&DAT_803a4599)[slotIdx * 0x10], sizeArg);
    saveResult = FUN_80006b7c();
    if (saveResult != 4)
    {
        FUN_80006b84(1);
    }
    FUN_800d783c(0x1e, 1);
    DAT_803de100 = 2;
    return;
}

u32
FUN_800ea8c8(u64 arg1, u64 arg2, u64 arg3, u64 arg4,
             u64 arg5, u64 arg6, u64 arg7, u64 arg8)
{
    u32 result;
    u8* history;

    result = FUN_80017498();
    history = FUN_800e82d8();
    FUN_80017488(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                 (u32)(u8)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (u32)(u8)history[5] * 2)
    ]
    )
    ;
    return result;
}

u8 FUN_800ea9ac(void)
{
    u8* history;

    history = FUN_800e82d8();
    return history[5];
}

void FUN_800ea9b8(void)
{
    u32 mapId;
    u8* history;
    short i;
    u32 flagWord;
    u32 bit;
    u32 flagId;
    u32 flagWordCache;
    u32 cachedFlagId;
    u32 scanId;
    short* mapFlags;

    mapId = FUN_80286834();
    history = FUN_800e82d8();
    cachedFlagId = 0xffffffff;
    if (history[6] == '\0')
    {
        mapFlags = &DAT_80312632;
        for (scanId = 1; scanId < 0xce; scanId++)
        {
            if ((*mapFlags == 0xffff) || (*mapFlags == -1))
            {
                bit = 1 << (scanId & 0x1f);
                flagId = (u32)(short)((short)((scanId & 0xff) >> 5) + 0x12f);
                flagWord = FUN_80017690(flagId);
                if ((flagWord & bit) == 0)
                {
                    FUN_80017698(flagId, flagWord | bit);
                }
            }
            mapFlags = mapFlags + 1;
        }
    }
    flagId = 1 << (mapId & 0x1f);
    flagWord = (u32)(short)((short)((mapId & 0xff) >> 5) + 0x12f);
    scanId = FUN_80017690(flagWord);
    if ((scanId & flagId) == 0)
    {
        FUN_80017698(flagWord, scanId | flagId);
        if (history[6] != '\x05')
        {
            history[6] = history[6] + '\x01';
        }
        for (i = 4; i != 0; i = i + -1)
        {
            history[i] = history[i + -1];
        }
        *history = mapId;
        if ((u32)(u8)history[5] == (mapId & 0xff)
        )
        {
            do
            {
                history[5] = history[5] + '\x01';
                mapId = (u32)(short)(((u8)history[5] >> 5) + 0x12f);
                if (mapId != (int)(short)cachedFlagId)
                {
                    flagWordCache = FUN_80017690(mapId);
                    cachedFlagId = mapId;
                }
            }
            while ((flagWordCache & 1 << ((u8)history[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void dll_5E_func01_nop(void)
{
}

void dll_5E_func00_nop(void)
{
}

void dll_5E_func03(int sourceObj, int variant, u8* posSource, u32 flags)
{
    u8* base = (u8*)(int)gDll5EFunc03SequenceData;
    (*gModgfxInterface)->beginSequence((void*)sourceObj, (u8)variant, 0x12, 3, 9);
    (*gModgfxInterface)->setSequenceParams(&base[0x2cc]);
    (*gModgfxInterface)->addSequenceFlags(flags | 0x4004484);
    (*gModgfxInterface)->resetSequenceSpawns();
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C0, lbl_803E07C4, *(f32*)&lbl_803E07C0, 9, &base[0x1c8]);
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C8, lbl_803E07C4, lbl_803E07CC, 9, &base[0x1dc]);
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C8, lbl_803E07C4, *(f32*)&lbl_803E07C8, 9, &base[0x1f0]);
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C8, lbl_803E07C4, *(f32*)&lbl_803E07C8, 9, &base[0x204]);
    (*gModgfxInterface)->addSequenceSpawn(4, 0.0f, 0.0f, 0.0f, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(8, lbl_803E07D4, lbl_803E07D8, lbl_803E07DC, 0x24, &base[0x260]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07E0, lbl_803E07E4, *(f32*)&lbl_803E07E0, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, lbl_803E07EC, *(f32*)&lbl_803E07EC, lbl_803E07F0, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(4, lbl_803E07F4, lbl_803E07D0, *(f32*)&lbl_803E07D0, 0x12, &base[0x2a8]);
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, lbl_803E07D0, *(f32*)&lbl_803E07D0, lbl_803E07F8, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, lbl_803E07EC, *(f32*)&lbl_803E07EC, lbl_803E07F0, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, lbl_803E07D0, *(f32*)&lbl_803E07D0, lbl_803E07F8, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, lbl_803E07EC, *(f32*)&lbl_803E07EC, lbl_803E07F0, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, lbl_803E07D0, *(f32*)&lbl_803E07D0, lbl_803E07F8, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(4, 0.0f, 0.0f, 0.0f, 0x24, &base[0x260]);
    (*gModgfxInterface)->spawnSequence(posSource, (u8*)(int)gDll5EFunc03SequenceData, 0x24, &base[0x168], 0x10, 0x120, 0);
    (*gModgfxInterface)->getLastSpawnHandle();
}

u8 gDll5EFunc03SequenceData[748] = {
    4, 76, 0, 0, 0, 0, 0, 0, 0, 0, 3, 39, 0, 0, 253, 61,
    0, 15, 0, 0, 0, 0, 0, 0, 252, 24, 0, 31, 0, 0, 253, 161,
    0, 0, 253, 61, 0, 47, 0, 0, 252, 124, 0, 0, 0, 0, 0, 63,
    0, 0, 253, 161, 0, 0, 2, 195, 0, 79, 0, 0, 0, 0, 0, 0,
    3, 232, 0, 95, 0, 0, 3, 39, 0, 0, 2, 195, 0, 111, 0, 0,
    4, 76, 0, 0, 0, 0, 0, 127, 0, 0, 4, 176, 7, 208, 0, 100,
    0, 0, 0, 31, 3, 39, 7, 208, 253, 161, 0, 15, 0, 31, 0, 100,
    7, 208, 252, 124, 0, 31, 0, 31, 253, 161, 7, 208, 253, 161, 0, 47,
    0, 31, 252, 124, 7, 208, 0, 100, 0, 63, 0, 31, 253, 161, 7, 208,
    3, 39, 0, 79, 0, 31, 0, 0, 7, 208, 4, 76, 0, 95, 0, 31,
    3, 39, 7, 208, 3, 39, 0, 111, 0, 31, 4, 176, 7, 208, 0, 100,
    0, 127, 0, 31, 3, 132, 15, 160, 0, 100, 0, 0, 0, 63, 2, 95,
    15, 160, 253, 161, 0, 15, 0, 63, 255, 156, 15, 160, 252, 124, 0, 31,
    0, 63, 252, 217, 15, 160, 253, 161, 0, 47, 0, 63, 251, 180, 15, 160,
    0, 100, 0, 63, 0, 63, 252, 217, 15, 160, 3, 39, 0, 79, 0, 63,
    0, 100, 15, 160, 4, 76, 0, 95, 0, 63, 2, 95, 15, 160, 3, 39,
    0, 111, 0, 63, 3, 132, 15, 160, 0, 100, 0, 127, 0, 63, 3, 232,
    23, 112, 255, 156, 0, 0, 0, 94, 2, 195, 23, 112, 252, 217, 0, 15,
    0, 94, 0, 0, 23, 112, 251, 180, 0, 31, 0, 94, 253, 61, 23, 112,
    252, 217, 0, 47, 0, 94, 252, 24, 23, 112, 255, 156, 0, 63, 0, 94,
    253, 61, 23, 112, 2, 95, 0, 79, 0, 94, 0, 0, 23, 112, 3, 132,
    0, 95, 0, 94, 2, 195, 23, 112, 2, 95, 0, 111, 0, 94, 3, 232,
    23, 112, 255, 156, 0, 127, 0, 94, 0, 0, 0, 1, 0, 10, 0, 0,
    0, 10, 0, 9, 0, 1, 0, 2, 0, 11, 0, 1, 0, 11, 0, 10,
    0, 2, 0, 3, 0, 12, 0, 2, 0, 12, 0, 11, 0, 3, 0, 4,
    0, 13, 0, 3, 0, 13, 0, 12, 0, 4, 0, 5, 0, 14, 0, 4,
    0, 14, 0, 13, 0, 5, 0, 6, 0, 15, 0, 5, 0, 15, 0, 14,
    0, 6, 0, 7, 0, 16, 0, 6, 0, 16, 0, 15, 0, 7, 0, 8,
    0, 17, 0, 7, 0, 17, 0, 16, 0, 0, 0, 1, 0, 2, 0, 3,
    0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 0, 0, 9, 0, 10,
    0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 0,
    0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0, 23, 0, 24, 0, 25,
    0, 26, 0, 0, 0, 27, 0, 28, 0, 29, 0, 30, 0, 31, 0, 32,
    0, 33, 0, 34, 0, 35, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3,
    0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11,
    0, 12, 0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19,
    0, 20, 0, 21, 0, 22, 0, 23, 0, 24, 0, 25, 0, 26, 0, 27,
    0, 28, 0, 29, 0, 30, 0, 31, 0, 32, 0, 33, 0, 34, 0, 35,
    0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7,
    0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15,
    0, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0, 23,
    0, 24, 0, 25, 0, 26, 0, 27, 0, 28, 0, 29, 0, 30, 0, 31,
    0, 32, 0, 33, 0, 34, 0, 35, 0, 9, 0, 10, 0, 11, 0, 12,
    0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19, 0, 20,
    0, 21, 0, 22, 0, 23, 0, 24, 0, 25, 0, 26, 0, 0, 0, 10,
    0, 120, 0, 80, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 217,
    0, 0, 1, 253, 0, 0, 2, 1, 0, 0, 2, 3,
};
