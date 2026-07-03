/*
 * DLL 0x62 (dll62func0) - a thin gameplay-effect DLL exporting three
 * object hooks. func01/func00 are empty no-op slots; func03 builds a
 * fourteen-command modgfx effect list on the stack (texture/blend modes
 * from the lbl_803E089x float constants and the lbl_803129C8 resource
 * blob) and submits it through gModgfxInterface->spawnEffect. The list
 * shape varies by `variant` (1 zeroes a halfword + swaps the base scale
 * float; 2 forces six layers). When the effect's flag bit 0 is set the
 * spawn position is offset either by the source object's local position
 * (object 0x18/0x1c/0x20) or, if absent, by the PartFxSpawnParams packet
 * at posSource.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

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
extern u8 lbl_803129C8[];
extern f32 lbl_803E0898;
extern f32 lbl_803E089C;
extern f32 lbl_803E08A0;
extern f32 lbl_803E08B8;
extern f32 lbl_803E08A4;
extern f32 lbl_803E08A8;
extern f32 lbl_803E08AC;
extern f32 lbl_803E08B0;
extern f32 lbl_803E08B4;

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

void loadSaveSettings(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                      u64 param_5, u64 param_6, u64 param_7,
                      u64 param_8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, DAT_803a3e26);
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
    int placementId;
    u8* slot;
    int baseIndex;
    int foundIndex;
    int remaining;

    if ((*(u16*)&((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    baseIndex = 0;
    slot = &DAT_803a3f08;
    remaining = 9;
    while ((foundIndex = baseIndex, *(int*)(slot + 0x168) != 0 &&
        (placementId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14), placementId != *(int*)(slot + 0x168))))
    {
        foundIndex = baseIndex + 1;
        if ((*(int*)(slot + 0x178) == 0) || (placementId == *(int*)(slot + 0x178))) break;
        foundIndex = baseIndex + 2;
        if ((*(int*)(slot + 0x188) == 0) || (placementId == *(int*)(slot + 0x188))) break;
        foundIndex = baseIndex + 3;
        if ((*(int*)(slot + 0x198) == 0) || (placementId == *(int*)(slot + 0x198))) break;
        foundIndex = baseIndex + 4;
        if ((*(int*)(slot + 0x1a8) == 0) || (placementId == *(int*)(slot + 0x1a8))) break;
        foundIndex = baseIndex + 5;
        if ((*(int*)(slot + 0x1b8) == 0) || (placementId == *(int*)(slot + 0x1b8))) break;
        foundIndex = baseIndex + 6;
        if ((*(int*)(slot + 0x1c8) == 0) || (placementId == *(int*)(slot + 0x1c8))) break;
        slot = slot + 0x70;
        baseIndex = baseIndex + 7;
        remaining = remaining + -1;
        foundIndex = baseIndex;
        if (remaining == 0) break;
    }
    if (foundIndex == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[foundIndex * 4] = *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    (&DAT_803a4074)[foundIndex * 4] = *(u32*)&((GameObject*)obj)->anim.localPosX;
    (&DAT_803a4078)[foundIndex * 4] = *(u32*)&((GameObject*)obj)->anim.localPosY;
    (&DAT_803a407c)[foundIndex * 4] = *(u32*)&((GameObject*)obj)->anim.localPosZ;
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

void FUN_800e8f58(u64 param_1, double param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
    u32 savedX;
    u32 savedY;
    u32 savedZ;
    char* dst;
    int actIndex;
    short* actEntry;
    char* tagSrc;
    char tagChar;
    u64 handle;
    u64 ret;

    ret = FUN_80286840();
    savedZ = DAT_802c28f8;
    savedY = DAT_802c28f4;
    savedX = DAT_802c28f0;
    tagSrc = (char*)((u64)ret >> 0x20);
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
    actIndex = 0;
    actEntry = &DAT_80312370;
    do
    {
        if (*actEntry != 0)
        {
            (*gMapEventInterface)->setMapAct(actIndex, 1);
        }
        actEntry = actEntry + 1;
        actIndex = actIndex + 1;
    }
    while (actIndex < 0x78);
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
    if (tagSrc == 0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        tagSrc = 0x0;
    }
    else
    {
        dst = &DAT_803a3f24;
        do
        {
            tagChar = *tagSrc;
            tagSrc = tagSrc + 1;
            *dst = tagChar;
            dst = dst + 1;
        }
        while (tagChar != '\0');
    }
    handle = (u64)memcpy(DAT_803de110, (void*)0x803a3f08, 0x6ec);
    tagChar = ret;
    if ((tagChar != -1) && (DAT_803dc4f0 = tagChar, tagSrc != 0x0))
    {
        FUN_80072564(handle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, ret & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(u32 groupId, u32 flagArg, int mode)
{
    bool wasMinusTwo;
    char matchIdx;
    u32 word;
    char idxBase;
    short* mapEntry;
    char* hist;
    u32* bitWord;
    u32 bit;
    u32 newWord;
    u32 act;
    char* histBase;
    int count;
    int slotCount;
    s64 gamebit;

    gamebit = FUN_80286830();
    act = (u32)((u64)gamebit >> 0x20);
    bit = gamebit;
    histBase = &DAT_803a3be0;
    if (0x4fffffffff < gamebit)
    {
        act = (u32)(u8)(&DAT_803a3dac)[act];
    }
    if ((int)act < 0x78)
    {
        if ((u16)(&DAT_80312460)[act] != 0)
        {
            if (mode == -1)
            {
                mode = 1;
            }
            wasMinusTwo = mode == -2;
            if (wasMinusTwo)
            {
                mode = 0;
            }
            word = FUN_80017690((u32)(u16)(&DAT_80312460)[act]);
            if (mode == 0)
            {
                newWord = word & ~(1 << bit);
            }
            else
            {
                newWord = word | 1 << bit;
            }
            FUN_80017698((u32)(u16)(&DAT_80312460)[act], newWord);
            DAT_803de104 = act;
            uRam803de108 = newWord;
            if (mode == 0)
            {
                mapEntry = &DAT_80312460;
                bitWord = &DAT_803a3c1c;
                word = ~(1 << bit);
                count = 0x14;
                do
                {
                    if (*mapEntry == (&DAT_80312460)[act])
                    {
                        *bitWord = *bitWord & word;
                    }
                    if (mapEntry[1] == (&DAT_80312460)[act])
                    {
                        bitWord[1] = bitWord[1] & word;
                    }
                    if (mapEntry[2] == (&DAT_80312460)[act])
                    {
                        bitWord[2] = bitWord[2] & word;
                    }
                    if (mapEntry[3] == (&DAT_80312460)[act])
                    {
                        bitWord[3] = bitWord[3] & word;
                    }
                    if (mapEntry[4] == (&DAT_80312460)[act])
                    {
                        bitWord[4] = bitWord[4] & word;
                    }
                    if (mapEntry[5] == (&DAT_80312460)[act])
                    {
                        bitWord[5] = bitWord[5] & word;
                    }
                    mapEntry = mapEntry + 6;
                    bitWord = bitWord + 6;
                    count = count + -1;
                }
                while (count != 0);
                if (!wasMinusTwo)
                {
                    idxBase = '\0';
                    count = 4;
                    hist = histBase;
                    do
                    {
                        if ((((((act == (int)*hist) && (matchIdx = idxBase, bit == hist[1])) ||
                                    ((matchIdx = idxBase + '\x01', act == hist[3] && (bit == hist[4])))
                                ) || ((matchIdx = idxBase + '\x02', act == hist[6] &&
                                    (bit == hist[7])))) ||
                                ((matchIdx = idxBase + '\x03', act == hist[9] && (bit == hist[10]))))
                            || ((act == hist[0xc] &&
                                (matchIdx = idxBase + '\x04', bit == hist[0xd]))))
                            goto LAB_800e9628;
                        hist = hist + 0xf;
                        idxBase = idxBase + '\x05';
                        count = count + -1;
                    }
                    while (count != 0);
                    matchIdx = -1;
                LAB_800e9628:
                    if (matchIdx == -1)
                    {
                        count = 0;
                        slotCount = 0x14;
                        do
                        {
                            if (*histBase == -1)
                            {
                                count = count * 3;
                                (&DAT_803a3be0)[count] = act;
                                (&DAT_803a3be1)[count] = gamebit;
                                (&DAT_803a3be2)[count] = 3;
                                break;
                            }
                            histBase = histBase + 3;
                            count = count + 1;
                            slotCount = slotCount + -1;
                        }
                        while (slotCount != 0);
                    }
                }
            }
            else
            {
                bit = 1 << bit;
                if ((word & bit) == 0)
                {
                    mapEntry = &DAT_80312460;
                    bitWord = &DAT_803a3c1c;
                    count = 0x14;
                    do
                    {
                        if (*mapEntry == (&DAT_80312460)[act])
                        {
                            *bitWord = *bitWord | bit;
                        }
                        if (mapEntry[1] == (&DAT_80312460)[act])
                        {
                            bitWord[1] = bitWord[1] | bit;
                        }
                        if (mapEntry[2] == (&DAT_80312460)[act])
                        {
                            bitWord[2] = bitWord[2] | bit;
                        }
                        if (mapEntry[3] == (&DAT_80312460)[act])
                        {
                            bitWord[3] = bitWord[3] | bit;
                        }
                        if (mapEntry[4] == (&DAT_80312460)[act])
                        {
                            bitWord[4] = bitWord[4] | bit;
                        }
                        if (mapEntry[5] == (&DAT_80312460)[act])
                        {
                            bitWord[5] = bitWord[5] | bit;
                        }
                        mapEntry = mapEntry + 6;
                        bitWord = bitWord + 6;
                        count = count + -1;
                    }
                    while (count != 0);
                }
            }
        }
    }
    FUN_8028687c();
    return;
}

void FUN_800e9e9c(void)
{
    u32 saveIndex;
    int status;
    u32 extraout_r4;
    u32 size;
    u32 in_r6;
    u32 in_r7;
    u32 in_r8;
    u32 in_r9;
    u32 in_r10;
    u64 in_f4;
    u64 in_f5;
    u64 in_f6;
    u64 in_f7;
    u64 in_f8;

    DAT_803de10c = 0xff;
    DAT_803de104 = 0xffffffff;
    FUN_80042b9c(0, 0, 1);
    size = 0x884;
    memset((void*)-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    saveIndex = DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[saveIndex * 4], (double)(float)(&DAT_803a4590)[saveIndex * 4],
                 (double)(float)(&DAT_803a4594)[saveIndex * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[saveIndex * 0x10], extraout_r4, size, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    status = FUN_80006b7c();
    if (status != 4)
    {
        FUN_80006b84(1);
    }
    FUN_800d783c(0x1e, 1);
    DAT_803de100 = 2;
    return;
}

u32
FUN_800ea8c8(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
    u32 result;
    u8* save;

    result = FUN_80017498();
    save = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (u32)(u8)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (u32)(u8)save[5] * 2)
    ]
    )
    ;
    return result;
}

u8 FUN_800ea9ac(void)
{
    u8* save;

    save = FUN_800e82d8();
    return save[5];
}

void FUN_800ea9b8(void)
{
    u32 mapId;
    u8* save;
    short i;
    u32 word;
    u32 bit;
    u32 wordIndex;
    u32 unaff_r27;
    u32 lastWordIndex;
    u32 entry;
    short* mapEntry;

    mapId = FUN_80286834();
    save = FUN_800e82d8();
    lastWordIndex = 0xffffffff;
    if (save[6] == '\0')
    {
        mapEntry = &DAT_80312632;
        for (entry = 1; entry < 0xce; entry = entry + 1)
        {
            if ((*mapEntry == 0xffff) || (*mapEntry == -1))
            {
                bit = 1 << (entry & 0x1f);
                wordIndex = (u32)(short)((short)((entry & 0xff) >> 5) + 0x12f);
                word = FUN_80017690(wordIndex);
                if ((word & bit) == 0)
                {
                    FUN_80017698(wordIndex, word | bit);
                }
            }
            mapEntry = mapEntry + 1;
        }
    }
    wordIndex = 1 << (mapId & 0x1f);
    word = (u32)(short)((short)((mapId & 0xff) >> 5) + 0x12f);
    entry = FUN_80017690(word);
    if ((entry & wordIndex) == 0)
    {
        FUN_80017698(word, entry | wordIndex);
        if (save[6] != '\x05')
        {
            save[6] = save[6] + '\x01';
        }
        for (i = 4; i != 0; i = i + -1)
        {
            save[i] = save[i + -1];
        }
        *save = mapId;
        if ((u32)(u8)save[5] == (mapId & 0xff)
        )
        {
            do
            {
                save[5] = save[5] + '\x01';
                mapId = (u32)(short)(((u8)save[5] >> 5) + 0x12f);
                if (mapId != (int)(short)lastWordIndex)
                {
                    unaff_r27 = FUN_80017690(mapId);
                    lastWordIndex = mapId;
                }
            }
            while ((unaff_r27 & 1 << ((u8)save[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void SaveGame_func08_nop(void);

void dll_62_func01_nop(void)
{
}

void dll_62_func00_nop(void)
{
}

void dll_63_func01_nop(void);

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* lbl = N (byte) */

/* 12b 3-insn patterns. */

/* misc 8b leaves */

/* if (lbl) fn(lbl); */

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

void dll_62_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    GfxCmd* e = buf.entries;
    u8* base = (u8*)(int)lbl_803129C8;
    u8 cnt;
    f32 v;
    v = lbl_803E0898;
    cnt = *(u8*)(*(int*)(sourceObj + 76) + 26);
    if (variant == 1)
    {
        *(s16*)&base[478] = 0;
        v = lbl_803E089C;
    }
    else if (variant == 2)
    {
        v = lbl_803E08A0;
        cnt = 6;
    }
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = lbl_803E08A0;
    e[0].y = lbl_803E08A0;
    e[0].z = lbl_803E08A0;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = &base[404];
    e[1].mode = 2;
    e[1].x = lbl_803E08A4;
    e[1].y = lbl_803E08A8;
    e[1].z = lbl_803E08A4;
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &base[372];
    e[2].mode = 2;
    e[2].x = lbl_803E08A4;
    e[2].y = lbl_803E08A8;
    e[2].z = lbl_803E08A4;
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = &base[372];
    e[3].mode = 4;
    e[3].x = lbl_803E08AC;
    e[3].y = lbl_803E08A0;
    e[3].z = lbl_803E08A0;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = &base[388];
    e[4].mode = 4;
    e[4].x = lbl_803E08AC;
    e[4].y = lbl_803E08A0;
    e[4].z = lbl_803E08A0;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[432];
    e[5].mode = 0x100;
    e[5].x = lbl_803E08A0;
    e[5].y = lbl_803E08A0;
    e[5].z = lbl_803E08B0;
    e[6].layer = 2;
    e[6].flags = 0x3a;
    e[6].tex = 0;
    e[6].mode = 0x1800000;
    e[6].x = v;
    e[6].y = lbl_803E08A0;
    e[6].z = lbl_803E08B4;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &base[432];
    e[7].mode = 0x100;
    e[7].x = lbl_803E08A0;
    e[7].y = lbl_803E08A0;
    e[7].z = lbl_803E08B0;
    e[8].layer = 3;
    e[8].flags = 0x3a;
    e[8].tex = 0;
    e[8].mode = 0x1800000;
    e[8].x = v;
    e[8].y = lbl_803E08A0;
    e[8].z = lbl_803E08B4;
    e[9].layer = 3;
    e[9].flags = 0x15;
    e[9].tex = &base[432];
    e[9].mode = 0x100;
    e[9].x = lbl_803E08A0;
    e[9].y = lbl_803E08A0;
    e[9].z = lbl_803E08B0;
    e[10].layer = 4;
    e[10].flags = 2;
    e[10].tex = 0;
    e[10].mode = 0x2000;
    e[10].x = lbl_803E08A0;
    e[10].y = lbl_803E08A0;
    e[10].z = lbl_803E08A0;
    e[11].layer = 5;
    e[11].flags = 7;
    e[11].tex = &base[372];
    e[11].mode = 4;
    e[11].x = lbl_803E08A0;
    e[11].y = lbl_803E08A0;
    e[11].z = lbl_803E08A0;
    e[12].layer = 5;
    e[12].flags = 7;
    e[12].tex = &base[388];
    e[12].mode = 4;
    e[12].x = lbl_803E08A0;
    e[12].y = lbl_803E08A0;
    e[12].z = lbl_803E08A0;
    e[13].layer = 5;
    e[13].flags = 0x15;
    e[13].tex = &base[432];
    e[13].mode = 0x100;
    e[13].x = lbl_803E08A0;
    e[13].y = lbl_803E08A0;
    e[13].z = lbl_803E08B0;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E08A0;
    buf.pos[1] = lbl_803E08A0;
    buf.pos[2] = lbl_803E08A0;
    buf.col[0] = lbl_803E08A0;
    buf.col[1] = lbl_803E08A0;
    buf.col[2] = lbl_803E08A0;
    if (cnt != 0)
    {
        buf.scale = lbl_803E08B8 * (f32)(u32)cnt;
    }
    else
    {
        buf.scale = lbl_803E0898;
    }
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 14;
    buf.hw[0] = *(s16*)&base[476];
    buf.hw[1] = *(s16*)&base[478];
    buf.hw[2] = *(s16*)&base[480];
    buf.hw[3] = *(s16*)&base[482];
    buf.hw[4] = *(s16*)&base[484];
    buf.hw[5] = *(s16*)&base[486];
    buf.hw[6] = *(s16*)&base[488];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0400c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)buf.ctx != NULL)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803129C8, 0x18, &base[212], 0x5e0, 0);
}

void dll_64_func03(u8* sourceObj, int variant, u8* posSource, u32 flags);
