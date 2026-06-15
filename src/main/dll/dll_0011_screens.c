#include "main/asset_load.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"

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
extern void GameBit_Set(int eventId, int value);
extern u32 GameBit_Get(int eventId);
extern void mm_free(u32);
extern void* getLastSavedGameTexts(void);
extern u32 lbl_803DD4A0;
extern u32 lbl_803DD4A4;
extern u32 lbl_803DD4A8;
extern u32 lbl_803DD4AC;
extern void* gameTextGet(int idx);
extern void* mmAlloc(int size, int heap, int flags);
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

void FUN_800e8630(int param_1)
{
    int placementId;
    undefined1* slot;
    int baseIndex;
    int foundIndex;
    int remaining;

    if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) != 0)
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
        (placementId = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14), placementId != *(int*)(slot + 0x168))))
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
    (&DAT_803a4070)[foundIndex * 4] = *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    (&DAT_803a4074)[foundIndex * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosX;
    (&DAT_803a4078)[foundIndex * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosY;
    (&DAT_803a407c)[foundIndex * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosZ;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 8) = *(undefined4*)&((GameObject*)param_1)->anim
        .localPosX;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0xc) = *(undefined4*)&((GameObject*)param_1)->
        anim.localPosY;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x10) = *(undefined4*)&((GameObject*)param_1)->
        anim.localPosZ;
    return;
}

undefined4* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}

int saveFn_800e8508(void);

undefined FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 colorR;
    undefined4 colorG;
    undefined4 colorB;
    char* dst;
    int mapIdx;
    short* actPtr;
    char* nameSrc;
    char ch;
    undefined8 cfgHandle;
    undefined8 taskInfo;

    taskInfo = FUN_80286840();
    colorB = DAT_802c28f8;
    colorG = DAT_802c28f4;
    colorR = DAT_802c28f0;
    nameSrc = (char*)((ulonglong)taskInfo >> 0x20);
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
    mapIdx = 0;
    actPtr = &DAT_80312370;
    do
    {
        if (*actPtr != 0)
        {
            (*gMapEventInterface)->setMapAct(mapIdx, 1);
        }
        actPtr = actPtr + 1;
        mapIdx = mapIdx + 1;
    }
    while (mapIdx < 0x78);
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
    (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = colorR;
    (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = colorG;
    (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = colorB;
    DAT_803a4465 = 1;
    if (nameSrc == (char*)0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        nameSrc = (char*)0x0;
    }
    else
    {
        dst = &DAT_803a3f24;
        do
        {
            ch = *nameSrc;
            nameSrc = nameSrc + 1;
            *dst = ch;
            dst = dst + 1;
        }
        while (ch != '\0');
    }
    cfgHandle = FUN_80003494(DAT_803de110, 0x803a3f08, 0x6ec);
    ch = (char)taskInfo;
    if ((ch != -1) && (DAT_803dc4f0 = ch, nameSrc != (char*)0x0))
    {
        FUN_80072564(cfgHandle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)taskInfo & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int param_3)
{
    bool keepTransient;
    char foundIndex;
    uint flags;
    char scanIndex;
    short* eventIds;
    char* entry;
    uint* groupStatuses;
    uint shift;
    uint newFlags;
    uint mapId;
    char* history;
    int i;
    int j;
    longlong packed;

    packed = FUN_80286830();
    mapId = (uint)((ulonglong)packed >> 0x20);
    shift = (uint)packed;
    history = &DAT_803a3be0;
    if (0x4fffffffff < packed)
    {
        mapId = (uint)(byte)(&DAT_803a3dac)[mapId];
    }
    if ((int)mapId < 0x78)
    {
        if ((ushort)(&DAT_80312460)[mapId] != 0)
        {
            if (param_3 == -1)
            {
                param_3 = 1;
            }
            keepTransient = param_3 == -2;
            if (keepTransient)
            {
                param_3 = 0;
            }
            flags = FUN_80017690((uint)(ushort)(&DAT_80312460)[mapId]);
            if (param_3 == 0)
            {
                newFlags = flags & ~(1 << shift);
            }
            else
            {
                newFlags = flags | 1 << shift;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[mapId], newFlags);
            DAT_803de104 = mapId;
            uRam803de108 = newFlags;
            if (param_3 == 0)
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
                        if ((((((mapId == (int)*entry) && (foundIndex = scanIndex, shift == (byte)entry[1])) ||
                                    ((foundIndex = scanIndex + '\x01', mapId == (int)entry[3] && (shift == (byte)entry[4])))
                                ) || ((foundIndex = scanIndex + '\x02', mapId == (int)entry[6] &&
                                    (shift == (byte)entry[7])))) ||
                                ((foundIndex = scanIndex + '\x03', mapId == (int)entry[9] && (shift == (byte)entry[10]))))
                            || ((mapId == (int)entry[0xc] &&
                                (foundIndex = scanIndex + '\x04', shift == (byte)entry[0xd]))))
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
                                (&DAT_803a3be0)[i] = (char)mapId;
                                (&DAT_803a3be1)[i] = (char)packed;
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

void FUN_800e9e9c(void)
{
    uint colorIdx;
    int mode;
    undefined4 extraout_r4;
    undefined4 uVar3;
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
    uVar3 = 0x884;
    FUN_800033a8(-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    colorIdx = (uint)DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[colorIdx * 4], (double)(float)(&DAT_803a4590)[colorIdx * 4],
                 (double)(float)(&DAT_803a4594)[colorIdx * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[colorIdx * 0x10], extraout_r4, uVar3, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    mode = FUN_80006b7c();
    if (mode != 4)
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
    undefined4 result;
    undefined* state;

    result = FUN_80017498();
    state = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (uint)(byte)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (uint)(byte)state[5] * 2)
    ]
    )
    ;
    return result;
}

undefined FUN_800ea9ac(void)
{
    undefined* state;

    state = FUN_800e82d8();
    return state[5];
}

void FUN_800ea9b8(void)
{
    uint id;
    undefined* state;
    short i;
    uint flags;
    uint mask;
    uint bit;
    uint cachedFlags;
    uint lastBitWord;
    uint scanId;
    short* entry;

    id = FUN_80286834();
    state = FUN_800e82d8();
    lastBitWord = 0xffffffff;
    if (state[6] == '\0')
    {
        entry = &DAT_80312632;
        for (scanId = 1; (short)scanId < 0xce; scanId = scanId + 1)
        {
            if ((*entry == 0xffff) || (*entry == -1))
            {
                mask = 1 << (scanId & 0x1f);
                bit = (uint)(short)((short)((scanId & 0xff) >> 5) + 0x12f);
                flags = FUN_80017690(bit);
                if ((flags & mask) == 0)
                {
                    FUN_80017698(bit, flags | mask);
                }
            }
            entry = entry + 1;
        }
    }
    bit = 1 << (id & 0x1f);
    flags = (uint)(short)((short)((id & 0xff) >> 5) + 0x12f);
    scanId = FUN_80017690(flags);
    if ((scanId & bit) == 0)
    {
        FUN_80017698(flags, scanId | bit);
        if (state[6] != '\x05')
        {
            state[6] = state[6] + '\x01';
        }
        for (i = 4; i != 0; i = i + -1)
        {
            state[i] = state[i + -1];
        }
        *state = (char)id;
        if ((uint)(byte)state[5] == (id & 0xff)
        )
        {
            do
            {
                state[5] = state[5] + '\x01';
                id = (uint)(short)(((byte)state[5] >> 5) + 0x12f);
                if (id != (int)(short)lastBitWord)
                {
                    cachedFlags = FUN_80017690(id);
                    lastBitWord = id;
                }
            }
            while ((cachedFlags & 1 << ((byte)state[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
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
    u8* p = (u8*)getLastSavedGameTexts();
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
            idx = (s[9] - '0') * 100 + (s[10] - '0') * 10 + s[11] - '0';
            if (idx < 0xd)
            {
                lbl_803A4218[idx] = (u8)i;
            }
        }
    }
}

void SaveGame_updateTransientMapBits(void);

u8 getCurTaskHintTextMap(void)
{
    return (u8)(s32)
    lbl_803119E0[*(u8*)((char*)getLastSavedGameTexts() + 0x5)];
}

void hintTextFn_800ea174(u8* out)
{
    u8* texts = (u8*)getLastSavedGameTexts();
    s16 i;
    for (i = 0; i < 0xd; i++)
    {
        out[i] = (u8)GameBit_Get(i + 0xf10);
    }
    out[lbl_803119E0[texts[5]]] = 1;
}

int hintTextMapFn_800ea264(void)
{
    int r = getCurGameText();
    u8* t = (u8*)getLastSavedGameTexts();
    gameTextLoadDir(lbl_803A4218[lbl_803119E0[t[5]]]);
    return r;
}

void gameBitFn_800ea2e0(u8 id)
{
    u8* texts;
    u8 wasNew;
    s16 cachedBank;
    u32 cachedBits;
    u32 mask;
    u32 bits;
    s16 bank;
    s16 historyIdx;
    u32 i;
    s16* taskMap;

    texts = (u8*)getLastSavedGameTexts();
    cachedBank = -1;

    if (texts[6] == 0)
    {
        taskMap = &lbl_803119E0[1];
        for (i = 1; (s16)i < 0xce; i++)
        {
            if ((*taskMap == 0xffff) || (*taskMap == -1))
            {
                mask = 1 << ((u8)i % 32);
                bank = (s16)(((u32)(u8)i >> 5) + 0x12f
                )
                ;
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
    bank = (s16)(((u32)id >> 5) + 0x12f);
    bits = GameBit_Get(bank);
    if ((bits & mask) == 0)
    {
        bits |= mask;
        GameBit_Set(bank, bits);
        wasNew = 1;
    }
    else
    {
        wasNew = 0;
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
                bank = (s16)(((u32)texts[5] >> 5) + 0x12f);
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

void dll_60_func03(u8* sourceObj, int variant, u8* posSource, uint flags);
