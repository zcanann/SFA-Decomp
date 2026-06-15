#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern undefined4 FUN_80006768();
extern undefined4 FUN_8000676c();
extern undefined4 FUN_80006770();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80006b8c();
extern undefined4 FUN_80006c20();
extern undefined4 FUN_80017488();
extern undefined4 FUN_80017498();
extern undefined4 FUN_80017500();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_800176cc();
extern undefined4 FUN_800176dc();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_8005d018();
extern undefined4 FUN_80072564();
extern undefined4 FUN_800d783c();
extern undefined4 FUN_8011e80c();
extern longlong FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern undefined4 DAT_802c28f0;
extern undefined4 DAT_802c28f4;
extern undefined4 DAT_802c28f8;
extern short DAT_80312370;
extern short DAT_80312460;
extern undefined4 DAT_80312630;
extern short DAT_80312632;
extern char DAT_803a3be0;
extern undefined4 DAT_803a3be1;
extern undefined4 DAT_803a3be2;
extern uint DAT_803a3c1c;
extern undefined4 DAT_803a3dac;
extern undefined1 gGameplayPreviewSettings;
extern undefined4 DAT_803a3e26;
extern undefined4 DAT_803a3e27;
extern undefined4 DAT_803a3e28;
extern undefined4 DAT_803a3e2a;
extern undefined4 DAT_803a3e2c;
extern undefined4 DAT_803a3e2d;
extern undefined4 gGameplayPreviewColorRed;
extern undefined4 gGameplayPreviewColorGreen;
extern undefined4 gGameplayPreviewColorBlue;
extern undefined4 gGameplayRegisteredDebugOptions;
extern undefined1 DAT_803a3f08;
extern undefined4 DAT_803a3f09;
extern undefined4 DAT_803a3f0c;
extern undefined4 DAT_803a3f0e;
extern undefined4 DAT_803a3f12;
extern undefined4 DAT_803a3f14;
extern undefined4 DAT_803a3f15;
extern undefined4 DAT_803a3f18;
extern undefined4 DAT_803a3f1a;
extern undefined4 DAT_803a3f1e;
extern undefined4 DAT_803a3f21;
extern char DAT_803a3f24;
extern undefined4 DAT_803a3f25;
extern undefined4 DAT_803a3f26;
extern undefined4 DAT_803a3f27;
extern undefined4 DAT_803a3f28;
extern undefined4 DAT_803a3f29;
extern undefined4 DAT_803a3f2b;
extern undefined4 DAT_803a4070;
extern undefined4 DAT_803a4074;
extern undefined4 DAT_803a4078;
extern undefined4 DAT_803a407c;
extern undefined4 DAT_803a4460;
extern undefined4 DAT_803a4465;
extern undefined4 DAT_803a458c;
extern undefined4 DAT_803a4590;
extern undefined4 DAT_803a4594;
extern undefined4 DAT_803a4599;
extern undefined4 DAT_803a459a;
extern undefined4 DAT_803a45aa;
extern undefined4 DAT_803a45ac;
extern undefined4 DAT_803a45b0;
extern undefined4 DAT_803a45b4;
extern undefined4 DAT_803a45b6;
extern undefined4 DAT_803a45ba;
extern undefined4 DAT_803a45bc;
extern undefined4 DAT_803a45be;
extern undefined4 DAT_803a45c0;
extern undefined4 DAT_803a45c2;
extern undefined4 DAT_803a45f0;
extern undefined4 DAT_803a45f1;
extern undefined4 DAT_803a45f2;
extern undefined4 DAT_803a45f3;
extern undefined4 DAT_803a4e78;
extern undefined4 DAT_803dc4f0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6e8;
extern undefined4 DAT_803de100;
extern undefined4 DAT_803de104;
extern undefined4 DAT_803de10c;
extern undefined4* DAT_803de110;
extern f32 lbl_803E1348;
extern undefined4 uRam803de108;
extern u8 lbl_80313E98[];
extern f32 lbl_803E0AF8;
extern f32 lbl_803E0AFC;
extern f32 lbl_803E0B00;
extern f32 lbl_803E0B04;
extern f32 lbl_803E0B08;
extern f32 lbl_803E0B0C;
extern f32 lbl_803E0B10;
extern f32 lbl_803E0B14;
extern f32 lbl_803E0B18;
extern f32 lbl_803E0B1C;
extern f32 lbl_803E0B20;
extern f32 lbl_803E0B24;
extern f32 lbl_803E0B28;
extern f32 lbl_803E0B2C;
extern f32 lbl_803E0B30;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void saveFileStruct_unlockCheat(uint cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
    return;
}

uint isCheatUnlocked(uint cheatId)
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

void loadSaveSettings(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                      undefined8 param_5, undefined8 param_6, undefined8 param_7,
                      undefined8 param_8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)DAT_803a3e26);
    FUN_80006c20(DAT_803a3e2c);
    FUN_80006768(DAT_803a3e2d, '\0');
    (**(code**)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
    (**(code**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((uint)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((uint)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((uint)gGameplayPreviewColorBlue, 10, 0, 0, 1);
    return;
}

undefined* FUN_800e82d8(void)
{
    return (undefined*)&DAT_803a4460;
}

void FUN_800e8630(int obj)
{
    int objId;
    undefined1* entry;
    int slotBase;
    int slotIdx;
    int groupsLeft;

    if ((*(ushort*)&((GameObject*)obj)->anim.flags & 0x2000) != 0)
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
    (&DAT_803a4070)[slotIdx * 4] = *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    (&DAT_803a4074)[slotIdx * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosX;
    (&DAT_803a4078)[slotIdx * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosY;
    (&DAT_803a407c)[slotIdx * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosZ;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 8) = *(undefined4*)&((GameObject*)obj)->anim
        .localPosX;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc) = *(undefined4*)&((GameObject*)obj)->
        anim.localPosY;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10) = *(undefined4*)&((GameObject*)obj)->
        anim.localPosZ;
    return;
}

undefined4* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}


undefined FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 savedX;
    undefined4 savedY;
    undefined4 savedZ;
    char* dst;
    int act;
    short* actFlags;
    char* src;
    char c;
    undefined8 saveHandle;
    undefined8 result;

    result = FUN_80286840();
    savedZ = DAT_802c28f8;
    savedY = DAT_802c28f4;
    savedX = DAT_802c28f0;
    src = (char*)((ulonglong)result >> 0x20);
    FUN_800033a8(-0x7fc5c0f8, 0, 0xf70);
    if ((*(byte*)(DAT_803de110 + 0x21) & 0x80) == 0)
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
    (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = savedX;
    (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = savedY;
    (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = savedZ;
    DAT_803a4465 = 1;
    if (src == (char*)0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        src = (char*)0x0;
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
    c = (char)result;
    if ((c != -1) && (DAT_803dc4f0 = c, src != (char*)0x0))
    {
        FUN_80072564(saveHandle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)result & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int param_3)
{
    bool isClearMode;
    char slotIdx;
    uint flagWord;
    char slotBase;
    short* actPtr;
    char* histScan;
    uint* wordPtr;
    uint bitIndex;
    uint newWord;
    uint flagId;
    char* histPtr;
    int i;
    int j;
    longlong rawId;

    rawId = FUN_80286830();
    flagId = (uint)((ulonglong)rawId >> 0x20);
    bitIndex = (uint)rawId;
    histPtr = &DAT_803a3be0;
    if (0x4fffffffff < rawId)
    {
        flagId = (uint)(byte)(&DAT_803a3dac)[flagId];
    }
    if ((int)flagId < 0x78)
    {
        if ((ushort)(&DAT_80312460)[flagId] != 0)
        {
            if (param_3 == -1)
            {
                param_3 = 1;
            }
            isClearMode = param_3 == -2;
            if (isClearMode)
            {
                param_3 = 0;
            }
            flagWord = FUN_80017690((uint)(ushort)(&DAT_80312460)[flagId]);
            if (param_3 == 0)
            {
                newWord = flagWord & ~(1 << bitIndex);
            }
            else
            {
                newWord = flagWord | 1 << bitIndex;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[flagId], newWord);
            DAT_803de104 = flagId;
            uRam803de108 = newWord;
            if (param_3 == 0)
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
                        if ((((((flagId == (int)*histScan) && (slotIdx = slotBase, bitIndex == (byte)histScan[1])) ||
                                    ((slotIdx = slotBase + '\x01', flagId == (int)histScan[3] && (bitIndex == (byte)histScan[4])))
                                ) || ((slotIdx = slotBase + '\x02', flagId == (int)histScan[6] &&
                                    (bitIndex == (byte)histScan[7])))) ||
                                ((slotIdx = slotBase + '\x03', flagId == (int)histScan[9] && (bitIndex == (byte)histScan[10]))))
                            || ((flagId == (int)histScan[0xc] &&
                                (slotIdx = slotBase + '\x04', bitIndex == (byte)histScan[0xd]))))
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
                                (&DAT_803a3be0)[i] = (char)flagId;
                                (&DAT_803a3be1)[i] = (char)rawId;
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
    return;
}

void FUN_800e9e9c(void)
{
    uint slotIdx;
    int saveResult;
    undefined4 extraout_r4;
    undefined4 sizeArg;
    undefined4 in_r6;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 in_f4;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;

    DAT_803de10c = 0xff;
    DAT_803de104 = 0xffffffff;
    FUN_80042b9c(0, 0, 1);
    sizeArg = 0x884;
    FUN_800033a8(-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    slotIdx = (uint)DAT_803a3f28;
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
    return;
}

undefined4
FUN_800ea8c8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 uVar1;
    undefined* puVar2;

    uVar1 = FUN_80017498();
    puVar2 = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (uint)(byte)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (uint)(byte)puVar2[5] * 2)
    ]
    )
    ;
    return uVar1;
}

undefined FUN_800ea9ac(void)
{
    undefined* puVar1;

    puVar1 = FUN_800e82d8();
    return puVar1[5];
}

void FUN_800ea9b8(void)
{
    uint mapId;
    undefined* history;
    short i;
    uint flagWord;
    uint bit;
    uint flagId;
    uint unaff_r27;
    uint cachedFlagId;
    uint scanId;
    short* mapFlags;

    mapId = FUN_80286834();
    history = FUN_800e82d8();
    cachedFlagId = 0xffffffff;
    if (history[6] == '\0')
    {
        mapFlags = &DAT_80312632;
        for (scanId = 1; (short)scanId < 0xce; scanId = scanId + 1)
        {
            if ((*mapFlags == 0xffff) || (*mapFlags == -1))
            {
                bit = 1 << (scanId & 0x1f);
                flagId = (uint)(short)((short)((scanId & 0xff) >> 5) + 0x12f);
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
    flagWord = (uint)(short)((short)((mapId & 0xff) >> 5) + 0x12f);
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
        *history = (char)mapId;
        if ((uint)(byte)history[5] == (mapId & 0xff)
        )
        {
            do
            {
                history[5] = history[5] + '\x01';
                mapId = (uint)(short)(((byte)history[5] >> 5) + 0x12f);
                if (mapId != (int)(short)cachedFlagId)
                {
                    unaff_r27 = FUN_80017690(mapId);
                    cachedFlagId = mapId;
                }
            }
            while ((unaff_r27 & 1 << ((byte)history[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void SaveGame_func08_nop(void);

void dll_70_func01_nop(void)
{
}

void dll_70_func00_nop(void)
{
}

void dll_71_func01_nop(void);

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

void dll_70_func03(int sourceObj, int variant, int posSource, uint flags)
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
    u8* base = (u8*)(int)lbl_80313E98;
    int ctx;
    e[0].layer = 0;
    e[0].flags = 0x12;
    e[0].tex = &base[336];
    e[0].mode = 4;
    e[0].x = lbl_803E0AF8;
    e[0].y = lbl_803E0AF8;
    e[0].z = lbl_803E0AF8;
    e[1].layer = 0;
    e[1].flags = 9;
    e[1].tex = &base[276];
    e[1].mode = 8;
    e[1].x = lbl_803E0AFC;
    e[1].y = lbl_803E0AFC;
    e[1].z = lbl_803E0AF8;
    e[2].layer = 0;
    e[2].flags = 9;
    e[2].tex = &base[296];
    e[2].mode = 2;
    e[2].x = lbl_803E0B00;
    e[2].y = lbl_803E0B04;
    e[2].z = lbl_803E0B00;
    e[3].layer = 0;
    e[3].flags = 0x12;
    e[3].tex = &base[336];
    e[3].mode = 2;
    e[3].x = lbl_803E0B08;
    e[3].y = lbl_803E0B00;
    e[3].z = lbl_803E0B08;
    e[4].layer = 0;
    e[4].flags = 9;
    e[4].tex = &base[296];
    e[4].mode = 8;
    e[4].x = lbl_803E0B0C;
    e[4].y = lbl_803E0AF8;
    e[4].z = lbl_803E0AF8;
    e[5].layer = 0;
    e[5].flags = 1;
    e[5].tex = (void*)0;
    e[5].mode = 0x8000;
    e[5].x = lbl_803E0AFC;
    e[5].y = lbl_803E0B10;
    e[5].z = lbl_803E0AF8;
    e[6].layer = 0;
    e[6].flags = 0;
    e[6].tex = (void*)0;
    e[6].mode = 0x80000;
    e[6].x = lbl_803E0AF8;
    e[6].y = lbl_803E0B14;
    e[6].z = lbl_803E0AF8;
    e[7].layer = 1;
    e[7].flags = 0x12;
    e[7].tex = &base[336];
    e[7].mode = 4;
    e[7].x = lbl_803E0AFC;
    e[7].y = lbl_803E0AF8;
    e[7].z = lbl_803E0AF8;
    e[8].layer = 1;
    e[8].flags = 9;
    e[8].tex = &base[296];
    e[8].mode = 2;
    e[8].x = lbl_803E0B00;
    e[8].y = lbl_803E0B18;
    e[8].z = lbl_803E0B00;
    e[9].layer = 1;
    e[9].flags = 0x7a;
    e[9].tex = (void*)0;
    e[9].mode = 0x10000;
    e[9].x = lbl_803E0AF8;
    e[9].y = lbl_803E0AF8;
    e[9].z = lbl_803E0AF8;
    e[10].layer = 1;
    e[10].flags = 0;
    e[10].tex = (void*)0;
    e[10].mode = 0x80000;
    e[10].x = lbl_803E0AF8;
    e[10].y = lbl_803E0B14;
    e[10].z = lbl_803E0AF8;
    e[11].layer = 2;
    e[11].flags = 0x9d;
    e[11].tex = (void*)0;
    e[11].mode = 0x20000;
    e[11].x = lbl_803E0AF8;
    e[11].y = lbl_803E0AF8;
    e[11].z = lbl_803E0AF8;
    e[12].layer = 3;
    e[12].flags = 9;
    e[12].tex = &base[276];
    e[12].mode = 8;
    e[12].x = lbl_803E0AFC;
    e[12].y = lbl_803E0B1C;
    e[12].z = lbl_803E0AF8;
    e[13].layer = 3;
    e[13].flags = 0x12;
    e[13].tex = &base[336];
    e[13].mode = 0x100;
    e[13].x = lbl_803E0AF8;
    e[13].y = lbl_803E0AF8;
    e[13].z = lbl_803E0B20;
    e[14].layer = 3;
    e[14].flags = 5;
    e[14].tex = &base[392];
    e[14].mode = 2;
    e[14].x = lbl_803E0B24;
    e[14].y = lbl_803E0B00;
    e[14].z = lbl_803E0B24;
    e[15].layer = 3;
    e[15].flags = 4;
    e[15].tex = (void*)0;
    e[15].mode = 2;
    e[15].x = lbl_803E0B28;
    e[15].y = lbl_803E0B00;
    e[15].z = lbl_803E0B28;
    e[16].layer = 3;
    e[16].flags = 0;
    e[16].tex = (void*)0;
    e[16].mode = 0x80000;
    e[16].x = lbl_803E0AF8;
    e[16].y = lbl_803E0B2C;
    e[16].z = lbl_803E0AF8;
    e[17].layer = 4;
    e[17].flags = 9;
    e[17].tex = &base[276];
    e[17].mode = 8;
    e[17].x = lbl_803E0AFC;
    e[17].y = lbl_803E0AFC;
    e[17].z = lbl_803E0AF8;
    e[18].layer = 4;
    e[18].flags = 0x12;
    e[18].tex = &base[336];
    e[18].mode = 0x100;
    e[18].x = lbl_803E0AF8;
    e[18].y = lbl_803E0AF8;
    e[18].z = lbl_803E0B20;
    e[19].layer = 4;
    e[19].flags = 5;
    e[19].tex = &base[392];
    e[19].mode = 2;
    e[19].x = lbl_803E0B28;
    e[19].y = lbl_803E0B00;
    e[19].z = lbl_803E0B28;
    e[20].layer = 4;
    e[20].flags = 4;
    e[20].tex = (void*)0;
    e[20].mode = 2;
    e[20].x = lbl_803E0B24;
    e[20].y = lbl_803E0B00;
    e[20].z = lbl_803E0B24;
    e[21].layer = 5;
    e[21].flags = 2;
    e[21].tex = (void*)0;
    e[21].mode = 0x1000;
    e[21].x = lbl_803E0B00;
    e[21].y = lbl_803E0AF8;
    e[21].z = lbl_803E0AF8;
    e[22].layer = 6;
    e[22].flags = 0x9d;
    e[22].tex = (void*)0;
    e[22].mode = 0x20000;
    e[22].x = lbl_803E0AF8;
    e[22].y = lbl_803E0AF8;
    e[22].z = lbl_803E0AF8;
    e[23].layer = 6;
    e[23].flags = 0x9b;
    e[23].tex = (void*)0;
    e[23].mode = 0x10000;
    e[23].x = lbl_803E0AF8;
    e[23].y = lbl_803E0AF8;
    e[23].z = lbl_803E0AF8;
    e[24].layer = 6;
    e[24].flags = 0x12;
    e[24].tex = &base[336];
    e[24].mode = 4;
    e[24].x = lbl_803E0AF8;
    e[24].y = lbl_803E0AF8;
    e[24].z = lbl_803E0AF8;
    e[25].layer = 6;
    e[25].flags = 0x12;
    e[25].tex = &base[336];
    e[25].mode = 2;
    e[25].x = lbl_803E0B30;
    e[25].y = lbl_803E0B00;
    e[25].z = lbl_803E0B30;
    e[26].layer = 6;
    e[26].flags = 0;
    e[26].tex = (void*)0;
    e[26].mode = 0x80000;
    e[26].x = lbl_803E0AF8;
    e[26].y = lbl_803E0B2C;
    e[26].z = lbl_803E0AF8;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0B30;
    buf.pos[1] = lbl_803E0B30;
    buf.pos[2] = lbl_803E0B30;
    buf.col[0] = lbl_803E0AF8;
    buf.col[1] = lbl_803E0AF8;
    buf.col[2] = lbl_803E0AF8;
    buf.scale = lbl_803E0B00;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0xc;
    buf.count = 27;
    buf.hw[0] = *(s16*)&base[404];
    buf.hw[1] = *(s16*)&base[406];
    buf.hw[2] = *(s16*)&base[408];
    buf.hw[3] = *(s16*)&base[410];
    buf.hw[4] = *(s16*)&base[412];
    buf.hw[5] = *(s16*)&base[414];
    buf.hw[6] = *(s16*)&base[416];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x1000082;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx == NULL)
        {
            buf.pos[0] = lbl_803E0B30 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0B30 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0B30 + ((PartFxSpawnParams*)posSource)->posZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0B30 + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0B30 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0B30 + *(f32*)(ctx + 0x20);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x12, (u8*)(int)lbl_80313E98, 0x10, &base[180], 0x45, 0);
}

void dll_71_func03(int sourceObj, int variant, int posSource, uint flags);

