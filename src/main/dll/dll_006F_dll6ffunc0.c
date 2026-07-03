/*
 * dll6ffunc0 (DLL 0x6F) - shared save-game / world-progress core lib.
 *
 * Owns the gameplay save-state helpers exported through gameplay.h:
 *   - debug-cheat unlock bits (saveFileStruct_unlockCheat / isCheatUnlocked)
 *     packed into gGameplayRegisteredDebugOptions.
 *   - preview color/volume defaults (saveFileStruct_resetVolumes, 0x7f each).
 *   - the save-settings apply path (loadSaveSettings) and the per-map act /
 *     object-position fix-up (FUN_800e8630).
 *   - FUN_800e95e8: the map-act flag setter that mirrors a flag bit across the
 *     map-act table and maintains the recently-changed history ring.
 *   - FUN_800e8f58 / FUN_800e9e9c: new-game / save-slot setup, seeding the
 *     map-act table and the save block.
 *   - FUN_800ea9b8: the visited-map history ring (most-recent-first, depth 5).
 *   - dll_6F_func03: builds a 32-entry modgfx command list (the spirit/aura
 *     particle effect) and submits it via gModgfxInterface->spawnEffect.
 *
 * The map-act / flag tables live at 0x803a3f08.. and 0x80312460..; the visited
 * history ring at 0x803a3be0. Bit indices are split into (word,bit) by the
 * 0x12f flag-word base. These globals are cross-TU; only this DLL writes the
 * debug-option and preview-color globals.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"

/* one modgfx draw command in the dll_6F_func03 effect list */
typedef struct GfxCmd
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

/* Cross-TU main-lib functions and globals this DLL references (home TUs
   un-recovered; left as Ghidra FUN_/DAT_ names). */

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
extern u32* DAT_803dd6e8;
extern u32 DAT_803de100;
extern u32 DAT_803de104;
extern u32 DAT_803de10c;
extern u32* DAT_803de110;
extern f32 lbl_803E1348;
extern u32 uRam803de108;
extern u8 gDll6FGfxCmdResourceTable[];
extern u8 gDll6FGfxCmdTexture;
extern f32 lbl_803E0AB8;
extern f32 lbl_803E0ABC;
extern f32 lbl_803E0AC0;
extern f32 lbl_803E0AC4;
extern f32 lbl_803E0AC8;
extern f32 lbl_803E0ACC;
extern f32 lbl_803E0AD0;
extern f32 lbl_803E0AD4;
extern f32 lbl_803E0AD8;
extern f32 lbl_803E0ADC;
extern f32 lbl_803E0AE0;
extern f32 lbl_803E0AE4;
extern f32 lbl_803E0AE8;
extern f32 lbl_803E0AEC;
extern f32 lbl_803E0AF0;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void saveFileStruct_unlockCheat(u32 cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
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
        slotBase = slotBase + 7;
        groupsLeft = groupsLeft + -1;
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
    FUN_800033a8(-0x7fc5c0f8, 0, 0xf70);
    if ((*(u8*)(DAT_803de110 + 0x21) & 0x80) == 0)
    {
        FUN_800033a8(DAT_803de110, 0, 0x6ec);
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
        act = act + 1;
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
            src = src + 1;
            *dst = c;
            dst = dst + 1;
        }
        while (c != '\0');
    }
    saveHandle = FUN_80003494(DAT_803de110, 0x803a3f08, 0x6ec);
    c = result;
    if ((c != -1) && (DAT_803dc4f0 = c, src != NULL))
    {
        FUN_80072564(saveHandle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, result & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
}

void FUN_800e95e8(u32 param_1, u32 param_2, int setMode)
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
                    i = i + -1;
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
                        i = i + -1;
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
                            i = i + 1;
                            j = j + -1;
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
                        i = i + -1;
                    }
                    while (i != 0);
                }
            }
        }
    }
    FUN_8028687c();
}

void FUN_800e9e9c(void)
{
    u32 slotIdx;
    int saveResult;
    u32 extraout_r4;
    u32 sizeArg;
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
    sizeArg = 0x884;
    FUN_800033a8(-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    slotIdx = DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[slotIdx * 4], (double)(float)(&DAT_803a4590)[slotIdx * 4],
                 (double)(float)(&DAT_803a4594)[slotIdx * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[slotIdx * 0x10], extraout_r4, sizeArg, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    saveResult = FUN_80006b7c();
    if (saveResult != 4)
    {
        FUN_80006b84(1);
    }
    FUN_800d783c(0x1e, 1);
    DAT_803de100 = 2;
}

u32
FUN_800ea8c8(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
    u32 result;
    u8* history;

    result = FUN_80017498();
    history = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
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
    u32 cachedWord;
    u32 cachedFlagId;
    u32 scanId;
    short* mapFlags;

    mapId = FUN_80286834();
    history = FUN_800e82d8();
    cachedFlagId = 0xffffffff;
    if (history[6] == '\0')
    {
        mapFlags = &DAT_80312632;
        for (scanId = 1; scanId < 0xce; scanId = scanId + 1)
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
                    cachedWord = FUN_80017690(mapId);
                    cachedFlagId = mapId;
                }
            }
            while ((cachedWord & 1 << ((u8)history[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
}

void dll_6F_func01_nop(void)
{
}

void dll_6F_func00_nop(void)
{
}

void dll_6F_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    u8* base = (u8*)(int)gDll6FGfxCmdResourceTable;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x18;
    buf.entries[0].tex = &base[336];
    buf.entries[0].mode = 2;
    buf.entries[0].x = lbl_803E0AB8;
    buf.entries[0].y = lbl_803E0ABC;
    buf.entries[0].z = lbl_803E0AB8;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x18;
    buf.entries[1].tex = &base[336];
    buf.entries[1].mode = 4;
    buf.entries[1].x = lbl_803E0AC0;
    buf.entries[1].y = lbl_803E0AC0;
    buf.entries[1].z = lbl_803E0AC0;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 0x18;
    buf.entries[2].tex = &base[336];
    buf.entries[2].mode = 8;
    buf.entries[2].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[2].y = (*(f32*)&lbl_803E0AC4);
    buf.entries[2].z = lbl_803E0AC0;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x18;
    buf.entries[3].tex = &base[336];
    buf.entries[3].mode = 8;
    buf.entries[3].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[3].y = (*(f32*)&lbl_803E0AC4);
    buf.entries[3].z = lbl_803E0AC0;
    buf.entries[4].layer = 0;
    buf.entries[4].flags = 8;
    buf.entries[4].tex = &base[384];
    buf.entries[4].mode = 8;
    buf.entries[4].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[4].y = (*(f32*)&lbl_803E0AC8);
    buf.entries[4].z = lbl_803E0AC0;
    buf.entries[5].layer = 0;
    buf.entries[5].flags = 0xc;
    buf.entries[5].tex = &base[400];
    buf.entries[5].mode = 8;
    buf.entries[5].x = lbl_803E0ACC;
    buf.entries[5].y = lbl_803E0AC0;
    buf.entries[5].z = lbl_803E0AC0;
    buf.entries[6].layer = 0;
    buf.entries[6].flags = 0x7a;
    buf.entries[6].tex = 0;
    buf.entries[6].mode = 0x10000;
    buf.entries[6].x = lbl_803E0AC0;
    buf.entries[6].y = lbl_803E0AC0;
    buf.entries[6].z = lbl_803E0AC0;
    buf.entries[7].layer = 0;
    buf.entries[7].flags = 0x14;
    buf.entries[7].tex = 0;
    buf.entries[7].mode = 0x800000;
    buf.entries[7].x = (*(f32*)&lbl_803E0AD0);
    buf.entries[7].y = lbl_803E0AC0;
    buf.entries[7].z = lbl_803E0AC0;
    buf.entries[8].layer = 0;
    buf.entries[8].flags = 0x11;
    buf.entries[8].tex = 0;
    buf.entries[8].mode = 0x800000;
    buf.entries[8].x = lbl_803E0AD4;
    buf.entries[8].y = lbl_803E0AC0;
    buf.entries[8].z = lbl_803E0AC0;
    buf.entries[9].layer = 0;
    buf.entries[9].flags = 1;
    buf.entries[9].tex = 0;
    buf.entries[9].mode = 0x2008000;
    buf.entries[9].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[9].y = (*(f32*)&lbl_803E0AC8);
    buf.entries[9].z = lbl_803E0AC0;
    buf.entries[10].layer = 0;
    buf.entries[10].flags = 0;
    buf.entries[10].tex = 0;
    buf.entries[10].mode = 0x80000;
    buf.entries[10].x = lbl_803E0AC0;
    buf.entries[10].y = lbl_803E0AD8;
    buf.entries[10].z = lbl_803E0AC0;
    buf.entries[11].layer = 0;
    buf.entries[11].flags = 0;
    buf.entries[11].tex = 0;
    buf.entries[11].mode = 0x100;
    buf.entries[11].x = lbl_803E0AC0;
    buf.entries[11].y = lbl_803E0AC0;
    buf.entries[11].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[12].layer = 1;
    buf.entries[12].flags = 4;
    buf.entries[12].tex = &gDll6FGfxCmdTexture;
    buf.entries[12].mode = 4;
    buf.entries[12].x = lbl_803E0AE0;
    buf.entries[12].y = lbl_803E0AC0;
    buf.entries[12].z = lbl_803E0AC0;
    buf.entries[13].layer = 1;
    buf.entries[13].flags = 8;
    buf.entries[13].tex = &base[384];
    buf.entries[13].mode = 4;
    buf.entries[13].x = lbl_803E0AE4;
    buf.entries[13].y = lbl_803E0AC0;
    buf.entries[13].z = lbl_803E0AC0;
    buf.entries[14].layer = 1;
    buf.entries[14].flags = 0x18;
    buf.entries[14].tex = &base[336];
    buf.entries[14].mode = 0x4000;
    buf.entries[14].x = lbl_803E0AC0;
    buf.entries[14].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[14].z = lbl_803E0AC0;
    buf.entries[15].layer = 1;
    buf.entries[15].flags = 0x7a;
    buf.entries[15].tex = 0;
    buf.entries[15].mode = 0x10000;
    buf.entries[15].x = (*(f32*)&lbl_803E0AD0);
    buf.entries[15].y = lbl_803E0AC0;
    buf.entries[15].z = lbl_803E0AC0;
    buf.entries[16].layer = 1;
    buf.entries[16].flags = 0;
    buf.entries[16].tex = 0;
    buf.entries[16].mode = 0x100;
    buf.entries[16].x = lbl_803E0AC0;
    buf.entries[16].y = lbl_803E0AC0;
    buf.entries[16].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[17].layer = 2;
    buf.entries[17].flags = 4;
    buf.entries[17].tex = &gDll6FGfxCmdTexture;
    buf.entries[17].mode = 4;
    buf.entries[17].x = lbl_803E0AC0;
    buf.entries[17].y = lbl_803E0AC0;
    buf.entries[17].z = lbl_803E0AC0;
    buf.entries[18].layer = 2;
    buf.entries[18].flags = 8;
    buf.entries[18].tex = &base[384];
    buf.entries[18].mode = 4;
    buf.entries[18].x = (*(f32*)&lbl_803E0AC8);
    buf.entries[18].y = lbl_803E0AC0;
    buf.entries[18].z = lbl_803E0AC0;
    buf.entries[19].layer = 2;
    buf.entries[19].flags = 0x18;
    buf.entries[19].tex = &base[336];
    buf.entries[19].mode = 0x4000;
    buf.entries[19].x = lbl_803E0AC0;
    buf.entries[19].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[19].z = lbl_803E0AC0;
    buf.entries[20].layer = 2;
    buf.entries[20].flags = 0;
    buf.entries[20].tex = 0;
    buf.entries[20].mode = 0x80000;
    buf.entries[20].x = lbl_803E0AC0;
    buf.entries[20].y = lbl_803E0AEC;
    buf.entries[20].z = lbl_803E0AC0;
    buf.entries[21].layer = 2;
    buf.entries[21].flags = 0;
    buf.entries[21].tex = 0;
    buf.entries[21].mode = 0x100;
    buf.entries[21].x = lbl_803E0AC0;
    buf.entries[21].y = lbl_803E0AC0;
    buf.entries[21].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[22].layer = 3;
    buf.entries[22].flags = 8;
    buf.entries[22].tex = &base[384];
    buf.entries[22].mode = 4;
    buf.entries[22].x = lbl_803E0AC0;
    buf.entries[22].y = lbl_803E0AC0;
    buf.entries[22].z = lbl_803E0AC0;
    buf.entries[23].layer = 3;
    buf.entries[23].flags = 0xc;
    buf.entries[23].tex = &base[400];
    buf.entries[23].mode = 4;
    buf.entries[23].x = lbl_803E0AF0;
    buf.entries[23].y = lbl_803E0AC0;
    buf.entries[23].z = lbl_803E0AC0;
    buf.entries[24].layer = 3;
    buf.entries[24].flags = 0x18;
    buf.entries[24].tex = &base[336];
    buf.entries[24].mode = 0x4000;
    buf.entries[24].x = lbl_803E0AC0;
    buf.entries[24].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[24].z = lbl_803E0AC0;
    buf.entries[25].layer = 3;
    buf.entries[25].flags = 0;
    buf.entries[25].tex = 0;
    buf.entries[25].mode = 0x100;
    buf.entries[25].x = lbl_803E0AC0;
    buf.entries[25].y = lbl_803E0AC0;
    buf.entries[25].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[26].layer = 4;
    buf.entries[26].flags = 0xc;
    buf.entries[26].tex = &base[400];
    buf.entries[26].mode = 4;
    buf.entries[26].x = lbl_803E0AC0;
    buf.entries[26].y = lbl_803E0AC0;
    buf.entries[26].z = lbl_803E0AC0;
    buf.entries[27].layer = 4;
    buf.entries[27].flags = 0x18;
    buf.entries[27].tex = &base[336];
    buf.entries[27].mode = 0x4000;
    buf.entries[27].x = lbl_803E0AC0;
    buf.entries[27].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[27].z = lbl_803E0AC0;
    buf.entries[28].layer = 4;
    buf.entries[28].flags = 0;
    buf.entries[28].tex = 0;
    buf.entries[28].mode = 0x2008000;
    buf.entries[28].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[28].y = (*(f32*)&lbl_803E0AC8);
    buf.entries[28].z = lbl_803E0AC0;
    buf.entries[29].layer = 4;
    buf.entries[29].flags = 0;
    buf.entries[29].tex = 0;
    buf.entries[29].mode = 0x100;
    buf.entries[29].x = lbl_803E0AC0;
    buf.entries[29].y = lbl_803E0AC0;
    buf.entries[29].z = (*(f32*)&lbl_803E0ADC);
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0AC0;
    buf.pos[1] = lbl_803E0AC0;
    buf.pos[2] = lbl_803E0AC0;
    buf.col[0] = lbl_803E0AC0;
    buf.col[1] = lbl_803E0AC0;
    buf.col[2] = lbl_803E0AC0;
    buf.scale = (*(f32*)&lbl_803E0AD0);
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x18;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.flags = 0x4000084;
    buf.count = 0x14;
    buf.hw[0] = *(s16*)&base[424];
    buf.hw[1] = *(s16*)&base[426];
    buf.hw[2] = *(s16*)&base[428];
    buf.hw[3] = *(s16*)&base[430];
    buf.hw[4] = *(s16*)&base[432];
    buf.hw[5] = *(s16*)&base[434];
    buf.hw[6] = *(s16*)&base[436];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0AC0 + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0AC0 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0AC0 + *(f32*)(ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0AC0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0AC0 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0AC0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x18, (u8*)(int)gDll6FGfxCmdResourceTable, 0x10, &base[240], 0x48, 0);
}
