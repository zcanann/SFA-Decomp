#include "main/asset_load.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"

typedef struct SaveGameData
{
    u8 pad0[0x20 - 0x0];
    u8 currentCharacter;
    u8 pad21[0x55E - 0x21];
    u8 unk55E;
    u8 pad55F[0x560 - 0x55F];
    f32 playTime;
    u8 pad564[0x6A4 - 0x564];
    s16 camActionNo;
    u8 pad6A6[0xF70 - 0x6A6];
} SaveGameData;


typedef struct CarryableUpdateHeldState
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    u8 pad4[0x5 - 0x4];
    s8 unk5;
    u8 unk6;
    u8 unk7;
    u8 unk8;
    u8 pad9[0x10 - 0x9];
} CarryableUpdateHeldState;


typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}


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
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_8005d018();
extern undefined4 FUN_80072564();
extern undefined4 FUN_800d783c();
extern undefined4 FUN_8011e80c();
extern void OSSetSaveRegion(void* start, void* end);
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
extern EffectInterface** gPartfxInterface;
extern undefined4 DAT_803de100;
extern undefined4 DAT_803de104;
extern undefined4 DAT_803de10c;
extern undefined4* DAT_803de110;
extern f32 lbl_803E1348;
extern undefined4 uRam803de108;
extern u8 gSaveGameData[];
extern u8 saveGameLoadStatus;
extern s8 lbl_803DB890;
extern u8* lbl_803DD498;
extern char sGameplayFoxName;
extern u8 saveData[228];
extern f32 lbl_803E06C8;
extern f32 lbl_803E06CC;
extern u16 lbl_80311720[];
extern u16 lbl_80311810[];
extern u32 gMapObjGroupStatuses[];
extern u8 gExtendedMapActLookup[];
extern int lbl_803DD48C;

#define SAVEGAME_OBJECT_POSITION_COUNT 0x3f
#define SAVEGAME_OBJECT_POSITION_OFFSET 0x168
#define SAVEGAME_OBJECT_POSITION_DIRTY_OFFSET 0x20158
#define SAVEGAME_LIVE_BUFFER_SIZE 0xf70
#define SAVEGAME_ACTIVE_SIZE 0x6ec
#define SAVEGAME_PLAYER_NAME_OFFSET 0x1c
#define SAVEGAME_CURRENT_CHARACTER_OFFSET 0x20
#define SAVEGAME_NEW_FILE_FLAG_OFFSET 0x21
#define SAVEGAME_CHARACTER_POSITION_OFFSET 0x684
#define SAVE_SCORE_FILE_STRIDE 0x28
#define SAVE_SCORE_TABLE_OFFSET 0x1c
#define SAVE_SCORE_ENTRY_COUNT 5
#define SAVEGAME_MAP_COUNT 0x78
#define SAVEGAME_EXTENDED_MAP_THRESHOLD 0x50
#define SAVEGAME_TRANSIENT_MAP_BIT_COUNT 20
#define SAVEGAME_TRANSIENT_MAP_BIT_TTL 3
#define SAVEGAME_CHARACTER_POSITION(save)                                                     \
    ((SaveGameCharacterPosition *)((save) +                                                     \
                                  (save)[SAVEGAME_CURRENT_CHARACTER_OFFSET] *                  \
                                      sizeof(SaveGameCharacterPosition) +                       \
                                  SAVEGAME_CHARACTER_POSITION_OFFSET))

typedef struct SaveGameObjectPosition
{
    u32 objectId;
    f32 x;
    f32 y;
    f32 z;
} SaveGameObjectPosition;

typedef struct SaveGameRomListPosition
{
    u8 pad0[0x8];
    f32 x;
    f32 y;
    f32 z;
    u32 objectId;
} SaveGameRomListPosition;

typedef struct SaveScoreEntry
{
    u32 score : 31;
    u32 flag : 1;
    u8 initials[4];
} SaveScoreEntry;

typedef struct SaveGameDefaultPosition
{
    f32 x;
    f32 y;
    f32 z;
} SaveGameDefaultPosition;

typedef struct SaveGameCharacterPosition
{
    f32 x;
    f32 y;
    f32 z;
    s8 angle;
    s8 map;
    u8 padE[2];
} SaveGameCharacterPosition;

typedef struct SaveSelectInfo
{
    u8 name[4];
    u8 percentComplete;
    u8 rankA;
    u8 rankB;
    u8 pad7;
    u32 playTime;
    void* taskTexts[5];
    u8 valid;
    u8 active;
    u8 pad22[2];
} SaveSelectInfo;

typedef struct MapBitTransient
{
    s8 mapId;
    u8 shift;
    s8 timer;
} MapBitTransient;

extern MapBitTransient gTransientMapBits[];

extern SaveGameDefaultPosition lbl_802C2170;

int saveGame_restoreObjectPosToRomList(SaveGameRomListPosition* object);

void saveGame_unsaveObjectPos(u8* obj);

extern void* memset(void* dst, int val, u32 n);
extern void* memcpy(void* dst, const void* src, u32 n);
extern int loadSaveGame(int slot, void* save);
extern int _saveGame(int slot, int save, int data);
extern void GameBit_Set(int eventId, int value);
extern u32 GameBit_Get(int eventId);
extern void* gameTextGetPhrase(int textId, int variant);

int trySaveGame(int slot);

int saveScoreFn_800e88b4(u8 slot, u8 flag, u32 score, u8* initials);

int gplayNewGame(char* name, int slot);

void SaveGame_gplaySetObjGroupStatus(int idx, int shift, int value);

int saveSelect_getInfo(void* outPtr);

/*
 * --INFO--
 *
 * Function: saveFileStruct_unlockCheat
 * EN v1.0 Address: 0x800E7ED8
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x800E815C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void saveFileStruct_unlockCheat(uint cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
    return;
}

/*
 * --INFO--
 *
 * Function: isCheatUnlocked
 * EN v1.0 Address: 0x800E7EFC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x800E8180
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint isCheatUnlocked(uint cheatId)
{
    return gGameplayRegisteredDebugOptions & 1 << (cheatId & 0xff);
}

/*
 * --INFO--
 *
 * Function: saveFileStruct_resetVolumes
 * EN v1.0 Address: 0x800E7F1C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x800E81A0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
    return;
}

/*
 * --INFO--
 *
 * Function: getSaveFileStruct
 * EN v1.0 Address: 0x800E7F38
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800E81BC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8* getSaveFileStruct(void)
{
    return &gGameplayPreviewSettings;
}

/*
 * --INFO--
 *
 * Function: loadSaveSettings
 * EN v1.0 Address: 0x800E7F44
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800E81C8
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800e82d8
 * EN v1.0 Address: 0x800E82D8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E82C8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined* FUN_800e82d8(void)
{
    return (undefined*)&DAT_803a4460;
}


/*
 * --INFO--
 *
 * Function: FUN_800e8630
 * EN v1.0 Address: 0x800E8630
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x800E85F4
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e8630(int param_1)
{
    int iVar1;
    undefined1* puVar2;
    int iVar3;
    int iVar4;
    int iVar5;

    if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    iVar3 = 0;
    puVar2 = &DAT_803a3f08;
    iVar5 = 9;
    while ((iVar4 = iVar3, *(int*)(puVar2 + 0x168) != 0 &&
        (iVar1 = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14), iVar1 != *(int*)(puVar2 + 0x168))))
    {
        iVar4 = iVar3 + 1;
        if ((*(int*)(puVar2 + 0x178) == 0) || (iVar1 == *(int*)(puVar2 + 0x178))) break;
        iVar4 = iVar3 + 2;
        if ((*(int*)(puVar2 + 0x188) == 0) || (iVar1 == *(int*)(puVar2 + 0x188))) break;
        iVar4 = iVar3 + 3;
        if ((*(int*)(puVar2 + 0x198) == 0) || (iVar1 == *(int*)(puVar2 + 0x198))) break;
        iVar4 = iVar3 + 4;
        if ((*(int*)(puVar2 + 0x1a8) == 0) || (iVar1 == *(int*)(puVar2 + 0x1a8))) break;
        iVar4 = iVar3 + 5;
        if ((*(int*)(puVar2 + 0x1b8) == 0) || (iVar1 == *(int*)(puVar2 + 0x1b8))) break;
        iVar4 = iVar3 + 6;
        if ((*(int*)(puVar2 + 0x1c8) == 0) || (iVar1 == *(int*)(puVar2 + 0x1c8))) break;
        puVar2 = puVar2 + 0x70;
        iVar3 = iVar3 + 7;
        iVar5 = iVar5 + -1;
        iVar4 = iVar3;
        if (iVar5 == 0) break;
    }
    if (iVar4 == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[iVar4 * 4] = *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    (&DAT_803a4074)[iVar4 * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosX;
    (&DAT_803a4078)[iVar4 * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosY;
    (&DAT_803a407c)[iVar4 * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosZ;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 8) = *(undefined4*)&((GameObject*)param_1)->anim
        .localPosX;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0xc) = *(undefined4*)&((GameObject*)param_1)->
        anim.localPosY;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x10) = *(undefined4*)&((GameObject*)param_1)->
        anim.localPosZ;
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_800e87a8
 * EN v1.0 Address: 0x800E87A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E877C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}

/*
 * --INFO--
 *
 * Function: saveFn_800e8508
 * EN v1.0 Address: 0x800E8508
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800E878C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int maybeTryLoadSave(int a);

int saveFn_800e8508(void);


/*
 * --INFO--
 *
 * Function: gplaySaveGame
 * EN v1.0 Address: 0x800E85A0
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x800E8824
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u32 pRestartPoint;

void gplaySaveGame(int param);

/*
 * --INFO--
 *
 * Function: titleDoLoadSave
 * EN v1.0 Address: 0x800E866C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800E88F0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void titleDoLoadSave(void);

/*
 * --INFO--
 *
 * Function: saveGame_save
 * EN v1.0 Address: 0x800E86D0
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x800E8954
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void saveGame_save(void);


/*
 * --INFO--
 *
 * Function: FUN_800e8b98
 * EN v1.0 Address: 0x800E8B98
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800E8A48
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_800e8b98(void)
{
    return DAT_803de100;
}


/*
 * --INFO--
 *
 * Function: FUN_800e8f58
 * EN v1.0 Address: 0x800E8F58
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x800E8D40
 * EN v1.1 Size: 736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e8f58(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 uVar1;
    undefined4 uVar2;
    undefined4 uVar3;
    char* pcVar4;
    int iVar5;
    short* psVar6;
    char* pcVar7;
    char cVar8;
    undefined8 uVar9;
    undefined8 uVar10;

    uVar10 = FUN_80286840();
    uVar3 = DAT_802c28f8;
    uVar2 = DAT_802c28f4;
    uVar1 = DAT_802c28f0;
    pcVar7 = (char*)((ulonglong)uVar10 >> 0x20);
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
    iVar5 = 0;
    psVar6 = &DAT_80312370;
    do
    {
        if (*psVar6 != 0)
        {
            (*gMapEventInterface)->setMode(iVar5, 1);
        }
        psVar6 = psVar6 + 1;
        iVar5 = iVar5 + 1;
    }
    while (iVar5 < 0x78);
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
    (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = uVar1;
    (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = uVar2;
    (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = uVar3;
    DAT_803a4465 = 1;
    if (pcVar7 == (char*)0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        pcVar7 = (char*)0x0;
    }
    else
    {
        pcVar4 = &DAT_803a3f24;
        do
        {
            cVar8 = *pcVar7;
            pcVar7 = pcVar7 + 1;
            *pcVar4 = cVar8;
            pcVar4 = pcVar4 + 1;
        }
        while (cVar8 != '\0');
    }
    uVar9 = FUN_80003494(DAT_803de110, 0x803a3f08, 0x6ec);
    cVar8 = (char)uVar10;
    if ((cVar8 != -1) && (DAT_803dc4f0 = cVar8, pcVar7 != (char*)0x0))
    {
        FUN_80072564(uVar9, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)uVar10 & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_800e95e8
 * EN v1.0 Address: 0x800E95E8
 * EN v1.0 Size: 1040b
 * EN v1.1 Address: 0x800E927C
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int param_3)
{
    bool bVar1;
    char cVar2;
    uint uVar3;
    char cVar4;
    short* psVar5;
    char* pcVar6;
    uint* puVar7;
    uint uVar8;
    uint uVar9;
    uint uVar10;
    char* pcVar11;
    int iVar12;
    int iVar13;
    longlong lVar14;

    lVar14 = FUN_80286830();
    uVar10 = (uint)((ulonglong)lVar14 >> 0x20);
    uVar8 = (uint)lVar14;
    pcVar11 = &DAT_803a3be0;
    if (0x4fffffffff < lVar14)
    {
        uVar10 = (uint)(byte)(&DAT_803a3dac)[uVar10];
    }
    if ((int)uVar10 < 0x78)
    {
        if ((ushort)(&DAT_80312460)[uVar10] != 0)
        {
            if (param_3 == -1)
            {
                param_3 = 1;
            }
            bVar1 = param_3 == -2;
            if (bVar1)
            {
                param_3 = 0;
            }
            uVar3 = FUN_80017690((uint)(ushort)(&DAT_80312460)[uVar10]);
            if (param_3 == 0)
            {
                uVar9 = uVar3 & ~(1 << uVar8);
            }
            else
            {
                uVar9 = uVar3 | 1 << uVar8;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[uVar10], uVar9);
            DAT_803de104 = uVar10;
            uRam803de108 = uVar9;
            if (param_3 == 0)
            {
                psVar5 = &DAT_80312460;
                puVar7 = &DAT_803a3c1c;
                uVar3 = ~(1 << uVar8);
                iVar12 = 0x14;
                do
                {
                    if (*psVar5 == (&DAT_80312460)[uVar10])
                    {
                        *puVar7 = *puVar7 & uVar3;
                    }
                    if (psVar5[1] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[1] = puVar7[1] & uVar3;
                    }
                    if (psVar5[2] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[2] = puVar7[2] & uVar3;
                    }
                    if (psVar5[3] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[3] = puVar7[3] & uVar3;
                    }
                    if (psVar5[4] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[4] = puVar7[4] & uVar3;
                    }
                    if (psVar5[5] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[5] = puVar7[5] & uVar3;
                    }
                    psVar5 = psVar5 + 6;
                    puVar7 = puVar7 + 6;
                    iVar12 = iVar12 + -1;
                }
                while (iVar12 != 0);
                if (!bVar1)
                {
                    cVar4 = '\0';
                    iVar12 = 4;
                    pcVar6 = pcVar11;
                    do
                    {
                        if ((((((uVar10 == (int)*pcVar6) && (cVar2 = cVar4, uVar8 == (byte)pcVar6[1])) ||
                                    ((cVar2 = cVar4 + '\x01', uVar10 == (int)pcVar6[3] && (uVar8 == (byte)pcVar6[4])))
                                ) || ((cVar2 = cVar4 + '\x02', uVar10 == (int)pcVar6[6] &&
                                    (uVar8 == (byte)pcVar6[7])))) ||
                                ((cVar2 = cVar4 + '\x03', uVar10 == (int)pcVar6[9] && (uVar8 == (byte)pcVar6[10]))))
                            || ((uVar10 == (int)pcVar6[0xc] &&
                                (cVar2 = cVar4 + '\x04', uVar8 == (byte)pcVar6[0xd]))))
                            goto LAB_800e9628;
                        pcVar6 = pcVar6 + 0xf;
                        cVar4 = cVar4 + '\x05';
                        iVar12 = iVar12 + -1;
                    }
                    while (iVar12 != 0);
                    cVar2 = -1;
                LAB_800e9628:
                    if (cVar2 == -1)
                    {
                        iVar12 = 0;
                        iVar13 = 0x14;
                        do
                        {
                            if (*pcVar11 == -1)
                            {
                                iVar12 = iVar12 * 3;
                                (&DAT_803a3be0)[iVar12] = (char)uVar10;
                                (&DAT_803a3be1)[iVar12] = (char)lVar14;
                                (&DAT_803a3be2)[iVar12] = 3;
                                break;
                            }
                            pcVar11 = pcVar11 + 3;
                            iVar12 = iVar12 + 1;
                            iVar13 = iVar13 + -1;
                        }
                        while (iVar13 != 0);
                    }
                }
            }
            else
            {
                uVar8 = 1 << uVar8;
                if ((uVar3 & uVar8) == 0)
                {
                    psVar5 = &DAT_80312460;
                    puVar7 = &DAT_803a3c1c;
                    iVar12 = 0x14;
                    do
                    {
                        if (*psVar5 == (&DAT_80312460)[uVar10])
                        {
                            *puVar7 = *puVar7 | uVar8;
                        }
                        if (psVar5[1] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[1] = puVar7[1] | uVar8;
                        }
                        if (psVar5[2] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[2] = puVar7[2] | uVar8;
                        }
                        if (psVar5[3] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[3] = puVar7[3] | uVar8;
                        }
                        if (psVar5[4] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[4] = puVar7[4] | uVar8;
                        }
                        if (psVar5[5] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[5] = puVar7[5] | uVar8;
                        }
                        psVar5 = psVar5 + 6;
                        puVar7 = puVar7 + 6;
                        iVar12 = iVar12 + -1;
                    }
                    while (iVar12 != 0);
                }
            }
        }
    }
    FUN_8028687c();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_800e9e9c
 * EN v1.0 Address: 0x800E9E9C
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x800E9E64
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e9e9c(void)
{
    uint uVar1;
    int iVar2;
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
    uVar1 = (uint)DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[uVar1 * 4], (double)(float)(&DAT_803a4590)[uVar1 * 4],
                 (double)(float)(&DAT_803a4594)[uVar1 * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[uVar1 * 0x10], extraout_r4, uVar3, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    iVar2 = FUN_80006b7c();
    if (iVar2 != 4)
    {
        FUN_80006b84(1);
    }
    FUN_800d783c(0x1e, 1);
    DAT_803de100 = 2;
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_800ea8c8
 * EN v1.0 Address: 0x800EA8C8
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x800EA4E8
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800ea9ac
 * EN v1.0 Address: 0x800EA9AC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800EA540
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_800ea9ac(void)
{
    undefined* puVar1;

    puVar1 = FUN_800e82d8();
    return puVar1[5];
}

/*
 * --INFO--
 *
 * Function: FUN_800ea9b8
 * EN v1.0 Address: 0x800EA9B8
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x800EA564
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea9b8(void)
{
    uint uVar1;
    undefined* puVar2;
    short sVar3;
    uint uVar4;
    uint uVar5;
    uint uVar6;
    uint unaff_r27;
    uint uVar7;
    uint uVar8;
    short* psVar9;

    uVar1 = FUN_80286834();
    puVar2 = FUN_800e82d8();
    uVar7 = 0xffffffff;
    if (puVar2[6] == '\0')
    {
        psVar9 = &DAT_80312632;
        for (uVar8 = 1; (short)uVar8 < 0xce; uVar8 = uVar8 + 1)
        {
            if ((*psVar9 == 0xffff) || (*psVar9 == -1))
            {
                uVar5 = 1 << (uVar8 & 0x1f);
                uVar6 = (uint)(short)((short)((uVar8 & 0xff) >> 5) + 0x12f);
                uVar4 = FUN_80017690(uVar6);
                if ((uVar4 & uVar5) == 0)
                {
                    FUN_80017698(uVar6, uVar4 | uVar5);
                }
            }
            psVar9 = psVar9 + 1;
        }
    }
    uVar6 = 1 << (uVar1 & 0x1f);
    uVar4 = (uint)(short)((short)((uVar1 & 0xff) >> 5) + 0x12f);
    uVar8 = FUN_80017690(uVar4);
    if ((uVar8 & uVar6) == 0)
    {
        FUN_80017698(uVar4, uVar8 | uVar6);
        if (puVar2[6] != '\x05')
        {
            puVar2[6] = puVar2[6] + '\x01';
        }
        for (sVar3 = 4; sVar3 != 0; sVar3 = sVar3 + -1)
        {
            puVar2[sVar3] = puVar2[sVar3 + -1];
        }
        *puVar2 = (char)uVar1;
        if ((uint)(byte)puVar2[5] == (uVar1 & 0xff)
        )
        {
            do
            {
                puVar2[5] = puVar2[5] + '\x01';
                uVar1 = (uint)(short)(((byte)puVar2[5] >> 5) + 0x12f);
                if (uVar1 != (int)(short)uVar7)
                {
                    unaff_r27 = FUN_80017690(uVar1);
                    uVar7 = uVar1;
                }
            }
            while ((unaff_r27 & 1 << ((byte)puVar2[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}


/*
 * --INFO--
 *
 * Function: dll_60_func03
 * EN v1.0 Address: 0x800ED5E4
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x800F24A8
 * EN v1.1 Size: 1160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
void SaveGame_func08_nop(void);

void screens_release(void);

void Carryable_release(void);

void Carryable_initialise(void);

void dll_59_func01_nop(void);

void dll_59_func00_nop(void);

void dll_5C_func01_nop(void);

void dll_5C_func00_nop(void);

void dll_5D_func01_nop(void);

void dll_5D_func00_nop(void);

void dll_5E_func01_nop(void);

void dll_5E_func00_nop(void);

void dll_5F_func01_nop(void);

void dll_5F_func00_nop(void);

void dll_60_func01_nop(void);

void dll_60_func00_nop(void);

void dll_61_func01_nop(void);

void dll_61_func00_nop(void);

void dll_62_func01_nop(void);

void dll_62_func00_nop(void);

void dll_63_func01_nop(void);

void dll_63_func00_nop(void);

void dll_64_func01_nop(void);

void dll_64_func00_nop(void);

void dll_65_func01_nop(void);

void dll_65_func00_nop(void);

void dll_A3_func01_nop(void);

void dll_A3_func00_nop(void);

void dll_66_func01_nop(void);

void dll_66_func00_nop(void);

void dll_67_func01_nop(void);

void dll_67_func00_nop(void);

void dll_68_func01_nop(void);

void dll_68_func00_nop(void);

void Dummy58_release(void);

void Dummy58_initialise(void);

void dll_69_func01_nop(void);

void dll_69_func00_nop(void);

void dll_6A_func01_nop(void);

void dll_6A_func00_nop(void);

void dll_6B_func01_nop(void);

void dll_6B_func00_nop(void);

void Dummy6C_release(void);

void Dummy6C_initialise(void);

void dll_6D_func01_nop(void);

void dll_6D_func00_nop(void);

void dll_6E_func01_nop(void);

void dll_6E_func00_nop(void);

void dll_6F_func01_nop(void);

void dll_6F_func00_nop(void);

void dll_70_func01_nop(void);

void dll_70_func00_nop(void);

void dll_71_func01_nop(void);

void dll_71_func00_nop(void);

void dll_72_func01_nop(void);

void dll_72_func00_nop(void);

void dll_73_func01_nop(void);

void dll_73_func00_nop(void);

void dll_74_func01_nop(void);

void dll_74_func00_nop(void);

void dll_75_func01_nop(void)
{
}

void dll_75_func00_nop(void)
{
}

void dll_76_func01_nop(void);

void dll_76_func00_nop(void);

void dll_77_func01_nop(void);

void dll_77_func00_nop(void);

void dll_78_func01_nop(void);

void dll_78_func00_nop(void);

void dll_79_func01_nop(void);

void dll_79_func00_nop(void);

void dll_7A_func01_nop(void);

void dll_7A_func00_nop(void);

void dll_7B_func01_nop(void);

void dll_7B_func00_nop(void);

/* 8b "li r3, N; blr" returners. */
int Dummy58_func03_ret_0(void);
int Dummy6C_func03_ret_0(void);

/* sda21 accessors. */
u8 getSaveGameLoadStatus(void);

void setSaveGameLoadingFlag(void);
s32 isSaveGameLoading(void);

void Carryable_init(int obj, int state);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void Carryable_free(int x);

/* lbl = N (byte) */
void clearSaveGameLoadingFlag(void);

/* 12b 3-insn patterns. */
s32 Carryable_isHeld(u8* obj);
s32 Carryable_getFlag01(u8* state);

void Carryable_setFlag08(u8* state, u8 enable);

s32 Carryable_getFlag04(u8* state);

void Carryable_setFlag04(u8* state, u8 enable);

void Carryable_setFlag02Inverted(u8* state, u8 clear);

/* misc 8b leaves */
u8 Carryable_getSurfaceType(u8* state);

/* if (lbl) fn(lbl); */
extern void mm_free(u32);
void SaveGame_release(void);

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

extern s8 lbl_803DD494;

void SaveGame_initialise(void);

extern void* getLastSavedGameTexts(void);

u8 getNextTaskHintText(void);

/* conditional init/free pair. */
void SaveGame_gplayClearRestartPoint(void);

extern void loadMapForCurrentSaveGame(void);

void SaveGame_gplayGotoRestartPoint(void);

void SaveGame_gplayGotoSavegame(void);

extern void unlockLevel(int a, int b, int c);
extern void cutsceneExit(void);
extern void audioStopByMask(int mask);
extern void stopRumble2(void);
extern void resetYbutton(void);
extern void mapLoadByCoords(f32 x, f32 y, f32 z, int act);
extern int getCurUiDll(void);
extern void loadUiDll(int dll);
extern void screenTransitionFn_800d7b04(int duration, int type);

void loadMapForCurrentSaveGame(void);

extern void* Obj_GetPlayerObject(void);
extern int fn_802966D4(int obj, int* out);
extern void playerSetHeldObject(void* player, int held);
extern f32 lbl_803E06D8;
extern uint buttonGetDisabled(int idx);
extern void buttonDisable(int index, uint flags);
extern uint getButtonsJustPressed(int idx);
extern int fn_80295BF0(void* player);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int hitDetectFn_80065e50(u8* obj, f32 x, f32 y, f32 z, f32*** list, int a, int b);
extern f32 timeDelta;
void saveGame_saveObjectPos(int* obj);
extern const f32 lbl_803E06DC, lbl_803E06E0, lbl_803E06E4, lbl_803E06E8;

int Carryable_updateHeld(u8* obj);

void objSaveFn_800ea774(int* obj);

void saveGame_saveObjectPos(int* obj);

void Carryable_stopCarrying(int* obj, u8* param2);

int Carryable_updateRenderState(int* obj, int flag);


void SaveGame_setCamActionNo(s16 actionNo);
void* SaveGame_getLast(void);
s32 SaveGame_getCamActionNo(void);
void* saveGameGetEnvState(void);
f32 SaveGame_getPlayTime(void);
extern f32 lbl_803E06D0;
extern f32 lbl_803E06D4;

void SaveGame_updateTimes(void);

f32 SaveGame_gplayGetTime(int id);

int SaveGame_gplayShouldNotSaveTime(int id);

void SaveGame_gplayAddTime(int id, f32 time);

void* SaveGame_getTrickyEnergy(void);
void SaveGame_setCharacter(u8 c);
u8 SaveGame_getCurChar(void);
char* getSaveFileName(void);

void* SaveGame_getCurCharPos(void);

void* SaveGame_getCurCharacterState(void);

s32 SaveGame_gplayGetRestartGameNotCleared(void);
u16 SaveGame_getMapObjGroupBit(int idx);

void SaveGame_setMapActLut(int val, int idx);

extern u32 lbl_803DD4A0;
extern u32 lbl_803DD4A4;
extern u32 lbl_803DD4A8;
extern u32 lbl_803DD4AC;

void screens_initialise(void);

void updateSavedHealth(void);

extern void* gameTextGet(int idx);

void* saveGameGetCurHint(void);

u32 SaveGame_mapGetObjGroups(int idx);

void mapClearBit(int idx, int bit);

void SaveGame_resetObjGroups(int idx);

void SaveGame_mapUpdateObjGroups(int idx);

u8 SaveGame_getMapAct(int idx);

int SaveGame_gplayGetObjGroupStatus(int idx, int shift);

void SaveGame_gplaySetAct(int idx, int act);

s8 SaveGame_findTransientMapBit(int a, int b);

void SaveGame_gplaySavePoint(f32* pos, s16 angle, int flags, int mapByte);

extern int fn_80296AE8(int obj);
extern void playerAddHealth(u8* player, int v);
extern void* mmAlloc(int size, int heap, int flags);

void SaveGame_gplayRestartPoint(f32* pos, s16 angle, int b691, int flag);

extern char* sMapDirectoryNameTable[];
extern u8 lbl_803A4218[];

void loadTaskTexts(void);

void SaveGame_updateTransientMapBits(void);

extern s16 lbl_803119E0[];

u8 getCurTaskHintTextMap(void);

void hintTextFn_800ea174(u8* out);

extern int getCurGameText(void);
extern void gameTextLoadDir(int dirId);

int hintTextMapFn_800ea264(void);

void gameBitFn_800ea2e0(u8 id);

void* fn_800E888C(u8 a, u8 b);

void screens_remove(void);

void screens_remove2(void);

extern void loadAssetFileById(void** out, int id);

void screens_show(int id);

extern u8 lbl_80313A40[];
extern f32 lbl_803E0A58;
extern f32 lbl_803E0A5C;
extern f32 lbl_803E0A60;
extern f32 lbl_803E0A64;
extern f32 lbl_803E0A68;
extern f32 lbl_803E0A6C;

void dll_6B_func03(int sourceObj, int variant, int posSource, uint flags);

extern u8 lbl_80311C58[];
extern u8 lbl_80311F20[];
extern u8 lbl_80312130[];
extern u8 lbl_80312650[];
extern u8 lbl_803128E8[];
extern u8 lbl_803129C8[];
extern u8 lbl_80312D18[];
extern u8 lbl_80312E58[];
extern u8 lbl_803131A8[];
extern u8 lbl_803133B8[];
extern u8 lbl_803135C8[];
extern u8 lbl_803137F8[];
extern u8 lbl_803138A0[];
extern u8 lbl_80313AF0[];
extern u8 lbl_80313C30[];
extern u8 lbl_80313CC0[];
extern u8 lbl_80313E98[];
extern u8 lbl_80314060[];
extern u8 lbl_80314288[];
extern u8 lbl_803144B0[];
extern u8 lbl_80314950[];
extern u8 lbl_80314980[];
extern u8 lbl_803149B0[];
extern u8 lbl_80314BD0[];
extern f32 lbl_803E06F0;
extern f32 lbl_803E06F4;
extern f32 lbl_803E06F8;
extern f32 lbl_803E06FC;
extern f32 lbl_803E0700;
extern f32 lbl_803E0704;
extern f32 lbl_803E0708;
extern f32 lbl_803E0760;
extern f32 lbl_803E0764;
extern f32 lbl_803E0768;
extern f32 lbl_803E076C;
extern f32 lbl_803E0770;
extern f32 lbl_803E0774;
extern f32 lbl_803E0778;
extern f32 lbl_803E077C;
extern f32 lbl_803E0780;
extern f32 lbl_803E0784;
extern f32 lbl_803E078C;
extern f32 lbl_803E0790;
extern f32 lbl_803E0794;
extern f32 lbl_803E0798;
extern f32 lbl_803E079C;
extern f32 lbl_803E07A0;
extern f32 lbl_803E07A4;
extern f32 lbl_803E07A8;
extern f32 lbl_803E07AC;
extern f32 lbl_803E07B0;
extern f32 lbl_803E07B4;
extern f32 lbl_803E07BC;
extern f32 lbl_803E0800;
extern f32 lbl_803E0804;
extern f32 lbl_803E0808;
extern f32 lbl_803E080C;
extern f32 lbl_803E0810;
extern f32 lbl_803E0814;
extern f32 lbl_803E0818;
extern f32 lbl_803E081C;
extern f32 lbl_803E0820;
extern f32 lbl_803E0824;
extern f32 lbl_803E0828;
extern f32 lbl_803E0858;
extern f32 lbl_803E085C;
extern f32 lbl_803E0860;
extern f32 lbl_803E0864;
extern f32 lbl_803E0868;
extern f32 lbl_803E0870;
extern f32 lbl_803E0874;
extern f32 lbl_803E0878;
extern f32 lbl_803E087C;
extern f32 lbl_803E0880;
extern f32 lbl_803E0884;
extern f32 lbl_803E088C;
extern f32 lbl_803E0898;
extern f32 lbl_803E08A0;
extern f32 lbl_803E08A4;
extern f32 lbl_803E08A8;
extern f32 lbl_803E08AC;
extern f32 lbl_803E08B0;
extern f32 lbl_803E08B4;
extern f32 lbl_803E0908;
extern f32 lbl_803E090C;
extern f32 lbl_803E0910;
extern f32 lbl_803E0914;
extern f32 lbl_803E0918;
extern f32 lbl_803E091C;
extern f32 lbl_803E0920;
extern f32 lbl_803E0924;
extern f32 lbl_803E0930;
extern f32 lbl_803E0934;
extern f32 lbl_803E0938;
extern f32 lbl_803E093C;
extern f32 lbl_803E0940;
extern f32 lbl_803E0944;
extern f32 lbl_803E0948;
extern f32 lbl_803E094C;
extern f32 lbl_803E0950;
extern f32 lbl_803E0954;
extern f32 lbl_803E0958;
extern f32 lbl_803E0990;
extern f32 lbl_803E0994;
extern f32 lbl_803E0998;
extern f32 lbl_803E099C;
extern f32 lbl_803E09A0;
extern f32 lbl_803E09A4;
extern f32 lbl_803E09A8;
extern f32 lbl_803E09AC;
extern f32 lbl_803E09B0;
extern f32 lbl_803E09B4;
extern f32 lbl_803E09B8;
extern f32 lbl_803E09BC;
extern f32 lbl_803E09C0;
extern f32 lbl_803E09C8;
extern f32 lbl_803E09CC;
extern f32 lbl_803E09D0;
extern f32 lbl_803E09D4;
extern f32 lbl_803E09D8;
extern f32 lbl_803E09DC;
extern f32 lbl_803E09E0;
extern f32 lbl_803E09E4;
extern f32 lbl_803E09E8;
extern f32 lbl_803E09EC;
extern f32 lbl_803E09F0;
extern f32 lbl_803E09F4;
extern f32 lbl_803E09F8;
extern f32 lbl_803E0A00;
extern f32 lbl_803E0A04;
extern f32 lbl_803E0A08;
extern f32 lbl_803E0A0C;
extern f32 lbl_803E0A10;
extern f32 lbl_803E0A28;
extern f32 lbl_803E0A2C;
extern f32 lbl_803E0A30;
extern f32 lbl_803E0A34;
extern f32 lbl_803E0A38;
extern f32 lbl_803E0A3C;
extern f32 lbl_803E0A40;
extern f32 lbl_803E0A44;
extern f32 lbl_803E0A48;
extern f32 lbl_803E0A4C;
extern f32 lbl_803E0A78;
extern f32 lbl_803E0A7C;
extern f32 lbl_803E0A80;
extern f32 lbl_803E0A84;
extern f32 lbl_803E0A88;
extern f32 lbl_803E0A8C;
extern f32 lbl_803E0A90;
extern f32 lbl_803E0A98;
extern f32 lbl_803E0A9C;
extern f32 lbl_803E0AA0;
extern f32 lbl_803E0AA4;
extern f32 lbl_803E0AA8;
extern f32 lbl_803E0AAC;
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
extern f32 lbl_803E0B38;
extern f32 lbl_803E0B3C;
extern f32 lbl_803E0B40;
extern f32 lbl_803E0B44;
extern f32 lbl_803E0B48;
extern f32 lbl_803E0B4C;
extern f32 lbl_803E0B50;
extern f32 lbl_803E0B54;
extern f32 lbl_803E0B58;
extern f32 lbl_803E0B60;
extern f32 lbl_803E0B64;
extern f32 lbl_803E0B68;
extern f32 lbl_803E0B6C;
extern f32 lbl_803E0B70;
extern f32 lbl_803E0B74;
extern f32 lbl_803E0B78;
extern f32 lbl_803E0B7C;
extern f32 lbl_803E0B80;
extern f32 lbl_803E0B84;
extern f32 lbl_803E0B88;
extern f32 lbl_803E0B8C;
extern f32 lbl_803E0B90;
extern f32 lbl_803E0B94;
extern f32 lbl_803E0B98;
extern f32 lbl_803E0B9C;
extern f32 lbl_803E0BA0;
extern f32 lbl_803E0BA4;
extern f32 lbl_803E0BA8;
extern f32 lbl_803E0BAC;
extern f32 lbl_803E0C40;
extern f32 lbl_803E0C44;
extern f32 lbl_803E0C48;
extern f32 lbl_803E0C4C;
extern f32 lbl_803E0C50;
extern f32 lbl_803E0C54;
extern f32 lbl_803E0C58;
extern f32 lbl_803E0C5C;
extern f32 lbl_803E0C60;
extern f32 lbl_803E0C64;
extern f32 lbl_803E0C68;
extern f32 lbl_803E0C6C;
extern f32 lbl_803E0C70;
extern f32 lbl_803E0C74;
extern f32 lbl_803E0C78;
extern f32 lbl_803E0C7C;
extern f32 lbl_803E0C80;
extern f32 lbl_803E0C88;
extern f32 lbl_803E0C8C;
extern f32 lbl_803E0C90;
extern f32 lbl_803E0C94;
extern f32 lbl_803E0C98;
extern f32 lbl_803E0C9C;
extern f32 lbl_803E0CA0;
extern f32 lbl_803E0D08;
extern f32 lbl_803E0D0C;
extern f32 lbl_803E0D10;
extern f32 lbl_803E0D14;
extern f32 lbl_803E0D18;
extern f32 lbl_803E0D1C;

void dll_59_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_5C_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_5D_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_5F_func03(int sourceObj, int variant, int posSource, uint flags);

extern f32 lbl_803E086C;
extern f32 lbl_803E0888;

void dll_61_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

void dll_62_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_64_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

void dll_65_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_66_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_67_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_68_func03(int sourceObj, int variant, int posSource, uint flags);

extern f32 lbl_803E0A00, lbl_803E0A04, lbl_803E0A08, lbl_803E0A0C, lbl_803E0A10, lbl_803E0A14, lbl_803E0A18;

void dll_69_func03(u8* sourceObj, int variant, u8* posSource, uint flags, int param_5, int* overrideParams);

void dll_6A_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

void dll_6D_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_6E_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_6F_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_70_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_71_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_72_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_73_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

void dll_76_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_77_func03(int sourceObj, int variant, int posSource, uint flags);

extern f32 lbl_803E0C84;

void dll_78_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

extern u8 lbl_80312F98[];
extern f32 lbl_803E0830;
extern f32 lbl_803E0834;
extern f32 lbl_803E0838;
extern f32 lbl_803E083C;
extern f32 lbl_803E0840;
extern f32 lbl_803E0844;
extern f32 lbl_803E0848;
extern f32 lbl_803E084C;
extern f32 lbl_803E0968;
extern f32 lbl_803E096C;
extern f32 lbl_803E0970;
extern f32 lbl_803E0974;
extern f32 lbl_803E0978;
extern f32 lbl_803E097C;
extern f32 lbl_803E0984;
extern u8 lbl_80312790[];
extern f32 lbl_803E0D08, lbl_803E0D0C, lbl_803E0D10, lbl_803E0D14, lbl_803E0D18, lbl_803E0D1C;
extern f32 lbl_803E0D20, lbl_803E0D24, lbl_803E0D28, lbl_803E0D2C;

int dll_7A_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

void dll_60_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

void dll_A3_func03(int sourceObj, int variant, int posSource, uint flags);

extern u8 lbl_803146D8[];
extern f32 lbl_803E0BB8, lbl_803E0BBC, lbl_803E0BC0, lbl_803E0BC4, lbl_803E0BC8, lbl_803E0BCC;
extern f32 lbl_803E0BD0, lbl_803E0BD4, lbl_803E0BD8, lbl_803E0BDC, lbl_803E0BE0, lbl_803E0BE4;

void dll_74_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

extern u8 lbl_80312BD8[];
extern f32 lbl_803E08C8, lbl_803E08CC, lbl_803E08D0, lbl_803E08D4, lbl_803E08D8, lbl_803E08DC;
extern f32 lbl_803E08E0, lbl_803E08E4, lbl_803E08E8, lbl_803E08EC, lbl_803E08F0, lbl_803E08F4;
extern f32 lbl_803E08F8, lbl_803E08FC;

void dll_63_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

extern u8 lbl_80314AF0[];
extern u8 lbl_803DB8D8;
extern f32 lbl_803E0CB0, lbl_803E0CB4, lbl_803E0CB8, lbl_803E0CBC, lbl_803E0CC0, lbl_803E0CC4;
extern f32 lbl_803E0CC8, lbl_803E0CCC, lbl_803E0CD0, lbl_803E0CD4, lbl_803E0CD8, lbl_803E0CDC;
extern f32 lbl_803E0CE0, lbl_803E0CE4, lbl_803E0CE8, lbl_803E0CEC, lbl_803E0CF0, lbl_803E0CF4;
extern f32 lbl_803E0CF8, lbl_803E0CFC;

int dll_79_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

extern u8 lbl_80314CB0[];
extern f32 lbl_803E0D38, lbl_803E0D3C, lbl_803E0D40, lbl_803E0D44, lbl_803E0D48, lbl_803E0D4C;
extern f32 lbl_803E0D50, lbl_803E0D54, lbl_803E0D58, lbl_803E0D5C, lbl_803E0D60, lbl_803E0D64;
extern f32 lbl_803E0D68, lbl_803E0D6C, lbl_803E0D70, lbl_803E0D74, lbl_803E0D78;

void dll_7B_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

extern void vecRotateZXY(void* p, f32* v);
extern u8 lbl_80311DA8[];
extern u8 lbl_803DB898, lbl_803DB8A0, lbl_803DB8A8;
extern const f32 lbl_803E0710, lbl_803E0714, lbl_803E0718, lbl_803E071C, lbl_803E0720;

void StaffCollision_func03(u8* sourceObj, int variant, u8* spawnParams, uint spawnFlags, int modelId, int* colorArgs);

extern u8 lbl_80312340[];
extern f32 lbl_803E07C0, lbl_803E07C4, lbl_803E07C8, lbl_803E07CC, lbl_803E07D0, lbl_803E07D4;
extern f32 lbl_803E07D8, lbl_803E07DC, lbl_803E07E0, lbl_803E07E4, lbl_803E07E8, lbl_803E07EC;
extern f32 lbl_803E07F0, lbl_803E07F4, lbl_803E07F8;


void dll_5E_func03(int sourceObj, int variant, u8* posSource, uint flags);

extern s16 lbl_80314920[8];
extern f32 lbl_803E0BE8, lbl_803E0BEC, lbl_803E0BF0, lbl_803E0BF4, lbl_803E0BF8, lbl_803E0BFC;
extern f32 lbl_803E0C00, lbl_803E0C04, lbl_803E0C08, lbl_803E0C0C, lbl_803E0C10, lbl_803E0C14;
extern f32 lbl_803E0C18, lbl_803E0C1C, lbl_803E0C20, lbl_803E0C24, lbl_803E0C28, lbl_803E0C2C;
extern f32 lbl_803E0C30, lbl_803E0C34, lbl_803E0C38, lbl_803E0C3C;

void dll_75_func03(u8* sourceObj, int variant, u8* posSource, uint flags)
{
    struct
    {
        GfxCmd* cmds;
        u8* ctx;
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
    GfxCmd* entries;
    GfxCmd* e;
    f32 fa = lbl_803E0BE8;
    f32 fb = lbl_803E0BEC;
    int fl = 100;
    if (variant == 0)
    {
        fl = 0x8c;
    }
    else if (variant == 1)
    {
        fa = lbl_803E0BF0;
        fb = lbl_803E0BF4;
        fl = 0x8c;
    }
    else if (variant == 2)
    {
        fa = lbl_803E0BF8;
        fb = lbl_803E0BFC;
        fl = 0x8c;
    }
    else if (variant == 3)
    {
        fa = lbl_803E0C00;
        fb = lbl_803E0C04;
        fl = 0x8c;
    }
    else if (variant == 4)
    {
        fa = lbl_803E0C08;
        fb = lbl_803E0C0C;
        fl = 0x154;
    }
    else if (variant == 5)
    {
        fa = lbl_803E0C10;
        fb = lbl_803E0C14;
        fl = 0x280;
        lbl_80314920[2] = 800;
    }
    else if (variant == 6)
    {
        fa = lbl_803E0C18;
        fb = lbl_803E0C1C;
        fl = 100;
        lbl_80314920[2] = 0x14;
    }
    else if (variant == 7)
    {
        fa = lbl_803E0C20;
        fb = lbl_803E0C24;
        fl = 200;
        lbl_80314920[1] = 0x14;
        lbl_80314920[2] = 0x14;
        lbl_80314920[3] = 0x14;
    }
    else if (variant == 8)
    {
        fa = lbl_803E0C28;
        fb = lbl_803E0C2C;
        fl = 0x41;
        lbl_80314920[1] = 0x14;
        lbl_80314920[2] = 0x14;
        lbl_80314920[3] = 0x14;
    }
    entries = buf.entries;
    entries[0].layer = 0;
    entries[0].flags = fl;
    entries[0].tex = (void*)0;
    entries[0].mode = 0x20000000;
    entries[0].x = lbl_803E0C30;
    entries[0].y = fa;
    entries[0].z = fb;
    e = &entries[1];
    if (variant == 0)
    {
        e[0].layer = 0;
        e[0].flags = 0;
        e[0].tex = (void*)0;
        e[0].mode = 0x80000;
        e[0].x = lbl_803E0C34;
        e[0].y = lbl_803E0C38;
        e[0].z = lbl_803E0C34;
        e[1].layer = 1;
        e[1].flags = 0;
        e[1].tex = (void*)0;
        e[1].mode = 0x80000;
        e[1].x = lbl_803E0C34;
        e[1].y = lbl_803E0C34;
        e[1].z = lbl_803E0C34;
        e[2].layer = 3;
        e[2].flags = 0;
        e[2].tex = (void*)0;
        e[2].mode = 0x80000;
        e[2].x = lbl_803E0C34;
        e[2].y = lbl_803E0C38;
        e[2].z = lbl_803E0C34;
        e += 3;
    }
    else if (variant == 6)
    {
        e[0].layer = 3;
        e[0].flags = 1;
        e[0].tex = (void*)0;
        e[0].mode = 0x2000;
        e[0].x = lbl_803E0C34;
        e[0].y = lbl_803E0C34;
        e[0].z = lbl_803E0C34;
        e += 1;
    }
    else if (variant == 8)
    {
        e[0].layer = 3;
        e[0].flags = 1;
        e[0].tex = (void*)0;
        e[0].mode = 0x2000;
        e[0].x = lbl_803E0C34;
        e[0].y = lbl_803E0C34;
        e[0].z = lbl_803E0C34;
        e += 1;
    }
    e[0].layer = 4;
    e[0].flags = 0;
    e[0].tex = (void*)0;
    e[0].mode = 0x20000000;
    e[0].x = lbl_803E0C30;
    e[0].y = fa;
    e[0].z = fb;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0C34;
    buf.pos[1] = lbl_803E0C34;
    buf.pos[2] = lbl_803E0C34;
    buf.col[0] = lbl_803E0C34;
    buf.col[1] = lbl_803E0C34;
    buf.col[2] = lbl_803E0C34;
    buf.scale = lbl_803E0C3C;
    buf.v40 = 0;
    buf.v3c = 0;
    buf.v59 = 0;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (e + 1) - entries;
    buf.hw[0] = lbl_80314920[0];
    buf.hw[1] = lbl_80314920[1];
    buf.hw[2] = lbl_80314920[2];
    buf.hw[3] = lbl_80314920[3];
    buf.hw[4] = lbl_80314920[4];
    buf.hw[5] = lbl_80314920[5];
    buf.hw[6] = lbl_80314920[6];
    buf.cmds = buf.entries;
    buf.flags = 0x10800;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0C34 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = lbl_803E0C34 + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = lbl_803E0C34 + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0C34 + ((PartFxSpawnParams*)posSource)->unkC;
            buf.pos[1] = lbl_803E0C34 + ((PartFxSpawnParams*)posSource)->unk10;
            buf.pos[2] = lbl_803E0C34 + ((PartFxSpawnParams*)posSource)->unk14;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0, 0, 0, 0, 0, 0);
}

extern void* textureIdxToPtr(int idx);
extern void debugPrintf(char* fmt, ...);
extern u8 lbl_80311E30[];
extern u8 lbl_803DB8B0, lbl_803DB8B4;
extern u32 lbl_803E0730;
extern const f32 lbl_803E0734, lbl_803E0738, lbl_803E073C, lbl_803E0740, lbl_803E0744;
extern const f32 lbl_803E0748, lbl_803E074C, lbl_803E0750, lbl_803E0754;

int modgfx_func03(u8* sourceObj, int effectId, u8* spawnParams, uint spawnFlags, int modelId, s16* countRange);
