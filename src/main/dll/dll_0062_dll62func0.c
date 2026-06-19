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

void FUN_800e8630(int param_1)
{
    int iVar1;
    u8* puVar2;
    int iVar3;
    int iVar4;
    int iVar5;

    if ((*(u16*)&((GameObject*)param_1)->anim.flags & 0x2000) != 0)
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
    (&DAT_803a4070)[iVar4 * 4] = *(u32*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    (&DAT_803a4074)[iVar4 * 4] = *(u32*)&((GameObject*)param_1)->anim.localPosX;
    (&DAT_803a4078)[iVar4 * 4] = *(u32*)&((GameObject*)param_1)->anim.localPosY;
    (&DAT_803a407c)[iVar4 * 4] = *(u32*)&((GameObject*)param_1)->anim.localPosZ;
    *(u32*)(*(int*)&((GameObject*)param_1)->anim.placementData + 8) = *(u32*)&((GameObject*)param_1)->anim
        .localPosX;
    *(u32*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0xc) = *(u32*)&((GameObject*)param_1)->
        anim.localPosY;
    *(u32*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x10) = *(u32*)&((GameObject*)param_1)->
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
    u32 uVar1;
    u32 uVar2;
    u32 uVar3;
    char* pcVar4;
    int iVar5;
    short* psVar6;
    char* pcVar7;
    char cVar8;
    u64 uVar9;
    u64 uVar10;

    uVar10 = FUN_80286840();
    uVar3 = DAT_802c28f8;
    uVar2 = DAT_802c28f4;
    uVar1 = DAT_802c28f0;
    pcVar7 = (char*)((u64)uVar10 >> 0x20);
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
    iVar5 = 0;
    psVar6 = &DAT_80312370;
    do
    {
        if (*psVar6 != 0)
        {
            (*gMapEventInterface)->setMapAct(iVar5, 1);
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
    (&DAT_803a458c)[DAT_803a3f28 * 4] = uVar1;
    (&DAT_803a4590)[DAT_803a3f28 * 4] = uVar2;
    (&DAT_803a4594)[DAT_803a3f28 * 4] = uVar3;
    DAT_803a4465 = 1;
    if (pcVar7 == 0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        pcVar7 = 0x0;
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
    cVar8 = uVar10;
    if ((cVar8 != -1) && (DAT_803dc4f0 = cVar8, pcVar7 != 0x0))
    {
        FUN_80072564(uVar9, param_2, param_3, param_4, param_5, param_6, param_7, param_8, uVar10 & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(u32 param_1, u32 param_2, int param_3)
{
    bool bVar1;
    char cVar2;
    u32 uVar3;
    char cVar4;
    short* psVar5;
    char* pcVar6;
    u32* puVar7;
    u32 uVar8;
    u32 uVar9;
    u32 uVar10;
    char* pcVar11;
    int iVar12;
    int iVar13;
    s64 lVar14;

    lVar14 = FUN_80286830();
    uVar10 = (u32)((u64)lVar14 >> 0x20);
    uVar8 = lVar14;
    pcVar11 = &DAT_803a3be0;
    if (0x4fffffffff < lVar14)
    {
        uVar10 = (u32)(u8)(&DAT_803a3dac)[uVar10];
    }
    if ((int)uVar10 < 0x78)
    {
        if ((u16)(&DAT_80312460)[uVar10] != 0)
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
            uVar3 = FUN_80017690((u32)(u16)(&DAT_80312460)[uVar10]);
            if (param_3 == 0)
            {
                uVar9 = uVar3 & ~(1 << uVar8);
            }
            else
            {
                uVar9 = uVar3 | 1 << uVar8;
            }
            FUN_80017698((u32)(u16)(&DAT_80312460)[uVar10], uVar9);
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
                        if ((((((uVar10 == (int)*pcVar6) && (cVar2 = cVar4, uVar8 == pcVar6[1])) ||
                                    ((cVar2 = cVar4 + '\x01', uVar10 == pcVar6[3] && (uVar8 == pcVar6[4])))
                                ) || ((cVar2 = cVar4 + '\x02', uVar10 == pcVar6[6] &&
                                    (uVar8 == pcVar6[7])))) ||
                                ((cVar2 = cVar4 + '\x03', uVar10 == pcVar6[9] && (uVar8 == pcVar6[10]))))
                            || ((uVar10 == pcVar6[0xc] &&
                                (cVar2 = cVar4 + '\x04', uVar8 == pcVar6[0xd]))))
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
                                (&DAT_803a3be0)[iVar12] = uVar10;
                                (&DAT_803a3be1)[iVar12] = lVar14;
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

void FUN_800e9e9c(void)
{
    u32 uVar1;
    int iVar2;
    u32 extraout_r4;
    u32 uVar3;
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
    uVar3 = 0x884;
    FUN_800033a8(-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    uVar1 = DAT_803a3f28;
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

u32
FUN_800ea8c8(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
    u32 uVar1;
    u8* puVar2;

    uVar1 = FUN_80017498();
    puVar2 = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (u32)(u8)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (u32)(u8)puVar2[5] * 2)
    ]
    )
    ;
    return uVar1;
}

u8 FUN_800ea9ac(void)
{
    u8* puVar1;

    puVar1 = FUN_800e82d8();
    return puVar1[5];
}

void FUN_800ea9b8(void)
{
    u32 uVar1;
    u8* puVar2;
    short sVar3;
    u32 uVar4;
    u32 uVar5;
    u32 uVar6;
    u32 unaff_r27;
    u32 uVar7;
    u32 uVar8;
    short* psVar9;

    uVar1 = FUN_80286834();
    puVar2 = FUN_800e82d8();
    uVar7 = 0xffffffff;
    if (puVar2[6] == '\0')
    {
        psVar9 = &DAT_80312632;
        for (uVar8 = 1; uVar8 < 0xce; uVar8 = uVar8 + 1)
        {
            if ((*psVar9 == 0xffff) || (*psVar9 == -1))
            {
                uVar5 = 1 << (uVar8 & 0x1f);
                uVar6 = (u32)(short)((short)((uVar8 & 0xff) >> 5) + 0x12f);
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
    uVar4 = (u32)(short)((short)((uVar1 & 0xff) >> 5) + 0x12f);
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
        *puVar2 = uVar1;
        if ((u32)(u8)puVar2[5] == (uVar1 & 0xff)
        )
        {
            do
            {
                puVar2[5] = puVar2[5] + '\x01';
                uVar1 = (u32)(short)(((u8)puVar2[5] >> 5) + 0x12f);
                if (uVar1 != (int)(short)uVar7)
                {
                    unaff_r27 = FUN_80017690(uVar1);
                    uVar7 = uVar1;
                }
            }
            while ((unaff_r27 & 1 << ((u8)puVar2[5] & 0x1f)) != 0);
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
    u8* base = lbl_803129C8;
    int ctx;
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
    ctx = sourceObj;
    buf.ctx = ctx;
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
    buf.cmds = buf.entries;
    buf.flags = 0xc0400c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] += *(f32*)(ctx + 0x18);
            buf.pos[1] += *(f32*)(ctx + 0x1c);
            buf.pos[2] += *(f32*)(ctx + 0x20);
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, &base[0], 0x18, &base[212], 0x5e0, 0);
}

void dll_64_func03(u8* sourceObj, int variant, u8* posSource, u32 flags);

