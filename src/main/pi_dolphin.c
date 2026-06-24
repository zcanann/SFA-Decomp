#include "dolphin/PPCArch.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/pi_dolphin.h"
#include "main/newshadows.h"
#include "main/mm.h"
#include "dolphin/os/OSCache.h"
#include "string.h"
#include "main/pad.h"
#include "main/dll/FRONT/n_options.h"
#include "dolphin/os/OSResetSW.h"
#include "dolphin/gx/GXCull.h"
#include "main/track_dolphin.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/os/OSArena.h"
#include "dolphin/gx/GXLighting.h"
#include "sfa_light_decls.h"

#define GX_CULL_NONE 0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK 2
extern u32 FUN_80003494();
extern u32 FUN_8000697c();
extern u32 FUN_80006988();
extern u32 FUN_80006a90();
extern u32 FUN_80006aa8();
extern u32 FUN_80006c30();
extern double FUN_80017714();
extern u64 FUN_80017814();
extern int FUN_80017830();
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern u32 FUN_800723a0();
extern u32 FUN_802420b0();
extern u32 FUN_80242114();
extern u32 FUN_80243e74();
extern u32 FUN_80243e9c();
extern u32 FUN_80246190();
extern u32 FUN_802461cc();
extern u64 FUN_80246298();
extern u32 FUN_80246308();
extern u32 FUN_802464ec();
extern u32 FUN_802471c4();
extern u32 FUN_80247618();
extern u32 PSVECDotProduct();
extern int FUN_80249300();
extern u32 FUN_802493c8();
extern u32 FUN_8024de40();
extern u32 FUN_80256b2c();
extern u64 FUN_80256c08();
extern u32 FUN_80258664();
extern u32 FUN_80258674();
extern u32 FUN_80258a04();
extern u32 FUN_80258b60();
extern u32 FUN_80259858();
extern u64 FUN_80259a9c();
extern u32 FUN_8025aeac();
extern u32 FUN_8025b054();
extern u32 FUN_8025b210();
extern u32 FUN_8025b94c();
extern u32 FUN_8025b9e8();
extern u32 FUN_8025bb48();
extern u32 FUN_8025bd1c();
extern u32 FUN_8025be80();
extern u32 FUN_8025c1a4();
extern u32 FUN_8025c224();
extern u32 FUN_8025c2a8();
extern u32 FUN_8025c368();
extern u32 FUN_8025c510();
extern u32 GXSetBlendMode();
extern u32 FUN_8025c65c();
extern u32 FUN_8025c828();
extern u64 FUN_8025ce2c();
extern u32 FUN_8025d8c4();
extern u32 FUN_8025dc78();
extern int FUN_80286718();
extern u32 FUN_80286834();
extern u64 FUN_8028683c();
extern u64 FUN_80286840();
extern u32 FUN_80286880();
extern u32 FUN_80286888();
extern u32 FUN_8028688c();
extern double FUN_80286cd0();

extern u32 DAT_800000f8;
extern u32 DAT_802c24e8;
extern u32 DAT_802c24ec;
extern u32 DAT_802c24f0;
extern u32 DAT_802c24f4;
extern u32 DAT_802c24f8;
extern u32 DAT_802c24fc;
extern int DAT_802cc8a8;
extern u32 DAT_8032f2b4;
extern int DAT_80360048;
extern u32 DAT_80360390;
extern u32 DAT_803dc070;
extern u32 DAT_803dc071;
extern u32 DAT_803dc22c;
extern u32 DAT_803dc22e;
extern u32 DAT_803dc234;
extern u32 DAT_803dd5d0;
extern u32* DAT_803dd71c;
extern u32 DAT_803dd927;
extern u32 DAT_803dd92c;
extern u32 DAT_803dd944;
extern u32 DAT_803dd950;
extern u32 DAT_803dd954;
extern u32 DAT_803dd95c;
extern u32 DAT_803dd968;
extern u32 DAT_803dd96c;
extern u32* DAT_803dd970;
extern u32 DAT_803dd988;
extern u32 DAT_803dd9a8;
extern u32 DAT_803dd9b0;
extern u32 DAT_803dd9b1;
extern u32 DAT_803dd9e8;
extern u32 DAT_803dd9e9;
extern u32 DAT_803dd9ea;
extern u32 DAT_803dd9ec;
extern u32 DAT_803dd9f0;
extern u32 DAT_803dd9f4;
extern u32 DAT_803dd9fc;
extern u32 DAT_803dda00;
extern u32 DAT_803dda08;
extern u32 DAT_803dda0c;
extern u32 DAT_803dda10;
extern u32 DAT_cc008000;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DC250;
extern f32 lbl_803DD934;
extern f32 lbl_803DD940;
extern f32 lbl_803DD9B4;
extern f32 lbl_803DD9B8;
extern f32 lbl_803DD9BC;
extern f32 lbl_803DD9C0;
extern f32 lbl_803DD9C4;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DF6F0;
extern f32 lbl_803DF6F4;
extern f32 lbl_803DF6F8;
extern f32 lbl_803DF6FC;
extern f32 lbl_803DF71C;
extern f32 lbl_803DF720;
extern f32 lbl_803DF744;
extern f32 lbl_803DF748;
extern f32 lbl_803DF74C;
extern f32 lbl_803DF760;
extern f32 lbl_803DF788;
extern f32 lbl_803DF7A8;
extern f32 lbl_803DF7AC;
extern char* sResourceFileNameTable[];
extern char sRomlistZlbPathFormat[];
extern u8 uRam803dc24f;
extern char sResourceFileNameAudioTab[];
extern u8 lbl_80345E10[];
extern char sArchivePathFormat;
extern s16 lbl_803DCC92;
extern int lbl_803DCC70;
extern int lbl_803DCC7C;
extern int lbl_803DCC80;
extern int lbl_803DCC8C;

extern int AtomicSList_Pop(int list);
extern void AtomicSList_Push(int list, int e);
extern int DVDOpen(char* fileName, void* fileInfo);
extern int DVDRead(void* fileInfo, void* buf, int size, int offset);
extern int DVDClose(void* fileInfo);
extern int DVDReadAsyncPrio(void* fi, void* addr, int len, int off, void (*cb)(), int prio);
extern void mergeTableFiles(void* buf, int a, int b, int n);
extern void animCurvReadCb();
extern void animCurvTabReadCb();
extern void voxMapReadCb();
extern void voxMapTabReadCb();
extern void blocksReadCb();
extern void blocksTabReadCb();
extern void tex1ReadCb();
extern void tex1tab1readCb();
extern void tex1tab2readCb();
extern void tex0readCb();
extern void tex0tab1readCb();
extern void tex0tab2readCb();
extern void animReadCb();
extern void animTabReadCb();
extern void modelsReadCb();
extern void modelsTabReadCb();

struct MldfNames
{
    u8 pad0[0x3ac];
    char* fileNames[0x22e];
    char* mapNames[0x49];
    int remapGroups[0x4b];
    s16 adjacency[0x2be];
    char fmtAnimCurvBin[0x10];
    char fmtAnimCurvTab[0x10];
    char fmtVoxmapBin[0x10];
    char fmtWarlockVoxmap[0x14];
    char fmtVoxmapTab[0x10];
    char fmtModBin[0x14];
    char fmtModTab[0x10];
};

struct MldfTables
{
    u8 pad0[0x160];
    int fileInfo[0x58];
    u8 mergeAnimCurv[0x7f40];
    u8 mergeVoxMap[0x2000];
    u8 mergeBlocks[0x2000];
    u8 mergeTex1[0x4000];
    u8 mergeTex0[0x4000];
    u8 mergeAnim[0x2ee0];
    u8 mergeModels[0x2058];
    int ids[0x58];
    int sizes[0x58];
    int romList[0x78];
    u32 ptrs[0x58];
    s16 owners[0x60];
};

#define MLDF_MAP_NAME(i) (nm->mapNames[i])
#define MLDF_FILE_NAME(i) (nm->fileNames[i])
#define MLDF_ADJ(i) (nm->adjacency[i])
#define MLDF_REMAP (nm->remapGroups)
#define MLDF_FINFO(s) (*(int *)&t->pad0[((s) << 2) + 0x160])
#define MLDF_ID(s) (*(int *)&t->pad0[((s) << 2) + 0x19138])
#define MLDF_SIZE(s) (*(int *)&t->pad0[((s) << 2) + 0x19298])
#define MLDF_PTR(s) (*(u32 *)&t->pad0[((s) << 2) + 0x195D8])
#define MLDF_OWNER(s) (*(s16 *)&t->pad0[((s) << 1) + 0x19738])
#define MLDF_FINFO4(s4) (*(int *)&t->pad0[(slot << 2) + 0x160])
#define MLDF_SP_ID(p) (*(int *)&t->pad0[(slot << 2) + 0x19138])
#define MLDF_SP_SIZE(p) (*(int *)&t->pad0[(slot << 2) + 0x19298])
#define MLDF_SP_PTR(p) (*(u32 *)&t->pad0[(slot << 2) + 0x195D8])

#pragma scheduling off
#pragma peephole off
u32 mapLoadDataFile(int mapId, int fileId)
{
    struct MldfNames* nm = (struct MldfNames*)sResourceFileNameAudioTab;
    struct MldfTables* t = (struct MldfTables*)lbl_80345E10;
    int fi;
    int sync = 0;
    u32 result;
    int adj;
    int slot;
    int ok;
    u32 tmp;
    char buf[56];

    if (lbl_803DCC92 != 0)
    {
        lbl_803DCC92 = 0;
        sync = 1;
    }
    adj = MLDF_ADJ(mapId);
    if (adj != -1)
    {
        int c = 0;
        s16 o25 = MLDF_OWNER(0x25);
        s16 o47;
        if (o25 != -1)
        {
            c = 1;
        }
        o47 = MLDF_OWNER(0x47);
        if (o47 != -1)
        {
            c = c + 1;
        }
        if (c == 0)
        {
            lbl_803DCC92 = tmp = 1;
            if (o25 == adj)
            {
                tmp = 0;
            }
            else if (o47 == adj)
            {
            }
            else
            {
                tmp = -1;
            }
            if ((int)tmp == -1)
            {
                mapLoadDataFile(adj, fileId);
            }
            sync = 1;
        }
    }
    sync = sync | lbl_803DCC70;
    switch (fileId)
    {
    case 0xd:
    case 0x55:
        result = MLDF_PTR(0xd);
        if ((result != 0) && (MLDF_OWNER(0xd) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x55);
        if ((result != 0) && (MLDF_OWNER(0x55) == mapId))
        {
            return result;
        }
        {
            if (MLDF_ID(0xd) == mapId)
            {
                slot = 0xd;
                MLDF_ID(0xd) = -1;
            }
            else if (MLDF_ID(0x55) == mapId)
            {
                slot = 0x55;
                MLDF_ID(0x55) = -1;
            }
            else if (MLDF_OWNER(0xd) == -1)
            {
                slot = 0xd;
            }
            else if (MLDF_OWNER(0x55) == -1)
            {
                slot = 0x55;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtAnimCurvBin, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                if (MLDF_SP_SIZE(x) == 0)
                {
                    return 0;
                }
                else
                {
                    MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                    DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                    tmp = MLDF_SP_PTR(x);
                    if (tmp == 0)
                    {
                        if (MLDF_ID(fileId) == -1)
                        {
                            texRestructRefs(1);
                        }
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        MLDF_SP_SIZE(x) = 0;
                        MLDF_SP_ID(x) = mapId;
                        return 0;
                    }
                    else
                    {
                        if (sync != 0)
                        {
                            DVDRead((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                            DVDClose((void*)fi);
                            AtomicSList_Push(lbl_803DCC8C, fi);
                            if (((lbl_803DCC80 & 0x20000000) == 0) && ((lbl_803DCC80 & 0x80000000) == 0))
                            {
                                mergeTableFiles(t->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
                            }
                        }
                        else
                        {
                            if (slot == 0xd)
                            {
                                lbl_803DCC80 = lbl_803DCC80 | 0x10000000;
                            }
                            else
                            {
                                lbl_803DCC80 = lbl_803DCC80 | 0x40000000;
                            }
                            DVDReadAsyncPrio((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0, animCurvReadCb, 2);
                            MLDF_FINFO4(x) = fi;
                        }
                        MLDF_OWNER(slot) = mapId;
                        return MLDF_SP_PTR(x);
                    }
                }
            }
        }
        break;
    case 0xe:
    case 0x56:
        result = MLDF_PTR(0xe);
        if ((result != 0) && (MLDF_OWNER(0xe) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x56);
        if ((result != 0) && (MLDF_OWNER(0x56) == mapId))
        {
            return result;
        }
        {
            if (MLDF_OWNER(0xe) == -1)
            {
                slot = 0xe;
            }
            else if (MLDF_OWNER(0x56) == -1)
            {
                slot = 0x56;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtAnimCurvTab, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                if (MLDF_SP_SIZE(x) == 0)
                {
                    return 0;
                }
                else
                {
                    MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                    DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x20000000) == 0) && ((lbl_803DCC80 & 0x80000000) == 0))
                        {
                            mergeTableFiles(t->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
                        }
                    }
                    else
                    {
                        if (slot == 0xe)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x20000000;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x80000000;
                        }
                        DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animCurvTabReadCb, 2);
                        MLDF_FINFO4(x) = fi;
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
        }
        break;
    case 0x1b:
    case 0x54:
        result = MLDF_PTR(0x1b);
        if ((result != 0) && (MLDF_OWNER(0x1b) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x54);
        if ((result != 0) && (MLDF_OWNER(0x54) == mapId))
        {
            return result;
        }
        {
            if (MLDF_OWNER(0x1b) == -1)
            {
                slot = 0x1b;
            }
            else if (MLDF_OWNER(0x54) == -1)
            {
                slot = 0x54;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtVoxmapBin, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                sprintf(buf, nm->fmtWarlockVoxmap);
                ok = DVDOpen(buf, (void*)fi);
                if (ok == 0)
                {
                    return 0;
                    break;
                }
            }
            MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
            if (MLDF_SP_SIZE(x) == 0)
            {
                sprintf(buf, nm->fmtWarlockVoxmap);
                ok = DVDOpen(buf, (void*)fi);
                if (ok == 0)
                {
                    return 0;
                    break;
                }
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
            }
            MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
            DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
            if (sync != 0)
            {
                DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                DVDClose((void*)fi);
                AtomicSList_Push(lbl_803DCC8C, fi);
                if (((lbl_803DCC80 & 0x2000000) == 0) && ((lbl_803DCC80 & 0x8000000) == 0))
                {
                    mergeTableFiles(t->mergeVoxMap, 0x1a, 0x53, 0x800);
                }
            }
            else
            {
                if (slot == 0x1b)
                {
                    lbl_803DCC80 = lbl_803DCC80 | 0x1000000;
                }
                else
                {
                    lbl_803DCC80 = lbl_803DCC80 | 0x4000000;
                }
                MLDF_FINFO4(x) = fi;
                DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapReadCb, 2);
            }
            MLDF_OWNER(slot) = mapId;
            return MLDF_SP_PTR(x);
        }
        break;
    case 0x1a:
    case 0x53:
        result = MLDF_PTR(0x1a);
        if ((result != 0) && (MLDF_OWNER(0x1a) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x53);
        if ((result != 0) && (MLDF_OWNER(0x53) == mapId))
        {
            return result;
        }
        {
            if (MLDF_OWNER(0x1a) == -1)
            {
                slot = 0x1a;
            }
            else if (MLDF_OWNER(0x53) == -1)
            {
                slot = 0x53;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtVoxmapTab, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                if (MLDF_SP_SIZE(x) == 0)
                {
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    return 0;
                }
                else
                {
                    MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                    DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x2000000) == 0) && ((lbl_803DCC80 & 0x8000000) == 0))
                        {
                            mergeTableFiles(t->mergeVoxMap, 0x1a, 0x53, 0x800);
                        }
                    }
                    else
                    {
                        if (slot == 0x1a)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x2000000;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x8000000;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapTabReadCb, 2);
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
        }
        break;
    case 0x25:
    case 0x47:
        result = MLDF_PTR(0x25);
        if ((result != 0) && (MLDF_OWNER(0x25) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x47);
        if ((result != 0) && (MLDF_OWNER(0x47) == mapId))
        {
            return result;
        }
        {
            if (MLDF_ID(0x25) == mapId)
            {
                slot = 0x25;
                MLDF_ID(0x25) = -1;
            }
            else if (MLDF_ID(0x47) == mapId)
            {
                slot = 0x47;
                MLDF_ID(0x47) = -1;
            }
            else if (MLDF_OWNER(0x25) == -1)
            {
                slot = 0x25;
            }
            else if (MLDF_OWNER(0x47) == -1)
            {
                slot = 0x47;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            if (mapId > 4)
            {
                sprintf(buf, nm->fmtModBin, MLDF_MAP_NAME(mapId), mapId + 1);
            }
            else
            {
                sprintf(buf, nm->fmtModBin, MLDF_MAP_NAME(mapId), mapId);
            }
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x20000) == 0) && ((lbl_803DCC80 & 0x80000) == 0))
                        {
                            mergeTableFiles(t->mergeBlocks, 0x26, 0x48, 0x800);
                        }
                    }
                    else
                    {
                        if (slot == 0x25)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x10000;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x40000;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0, blocksReadCb, 2);
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
        }
        break;
    case 0x26:
    case 0x48:
        {
            int idx;
            int* grp;
            int n;
            result = MLDF_PTR(0x26);
            if ((result != 0) && (MLDF_OWNER(0x26) == mapId))
            {
                return result;
            }
            result = MLDF_PTR(0x48);
            if ((result != 0) && (MLDF_OWNER(0x48) == mapId))
            {
                return result;
            }
            {
                if (MLDF_OWNER(0x26) == -1)
                {
                    slot = 0x26;
                }
                else if (MLDF_OWNER(0x48) == -1)
                {
                    slot = 0x48;
                }
                else
                {
                    return 0;
                }
                if (MLDF_SP_PTR(x) != 0)
                {
                    mm_free((void*)MLDF_SP_PTR(x));
                    MLDF_SP_PTR(x) = 0;
                }
                idx = 0;
                grp = MLDF_REMAP;
                for (n = 0xf; n != 0; n--)
                {
                    if (mapId == grp[0]) goto remap_found;
                    idx = idx + 1;
                    if (mapId == grp[1]) goto remap_found;
                    idx = idx + 1;
                    if (mapId == grp[2]) goto remap_found;
                    idx = idx + 1;
                    if (mapId == grp[3]) goto remap_found;
                    idx = idx + 1;
                    if (mapId == grp[4]) goto remap_found;
                    grp = grp + 5;
                    idx = idx + 1;
                }
            remap_found:
                piRomLoadSection(0, idx, 0);
                if (mapId > 4)
                {
                    sprintf(buf, nm->fmtModTab, MLDF_MAP_NAME(mapId), mapId + 1);
                }
                else
                {
                    sprintf(buf, nm->fmtModTab, MLDF_MAP_NAME(mapId), mapId);
                }
                fi = AtomicSList_Pop(lbl_803DCC8C);
                ok = DVDOpen(buf, (void*)fi);
                if (ok == 0)
                {
                    return 0;
                }
                else
                {
                    MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                    MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                    DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x20000) == 0) && ((lbl_803DCC80 & 0x80000) == 0))
                        {
                            mergeTableFiles(t->mergeBlocks, 0x26, 0x48, 0x800);
                        }
                    }
                    else
                    {
                        if (slot == 0x26)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x20000;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x80000;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, blocksTabReadCb, 2);
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
            break;
        }
    case 0x2b:
    case 0x46:
        result = MLDF_PTR(0x2b);
        if ((result != 0) && (MLDF_OWNER(0x2b) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x46);
        if ((result != 0) && (MLDF_OWNER(0x46) == mapId))
        {
            return result;
        }
        {
            if (MLDF_ID(0x2b) == mapId)
            {
                slot = 0x2b;
                MLDF_ID(0x2b) = -1;
            }
            else if (MLDF_ID(0x46) == mapId)
            {
                slot = 0x46;
                MLDF_ID(0x46) = -1;
            }
            else if (MLDF_OWNER(0x2b) == -1)
            {
                slot = 0x2b;
            }
            else if (MLDF_OWNER(0x46) == -1)
            {
                slot = 0x46;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 4) == 0) && ((lbl_803DCC80 & 8) == 0))
                        {
                            mergeTableFiles(t->mergeModels, 0x2a, 0x45, 0x800);
                        }
                        lbl_803DCC7C = lbl_803DCC7C + 1;
                    }
                    else
                    {
                        lbl_803DCC7C = lbl_803DCC7C + 1;
                        if (slot == 0x2b)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 1;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 2;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0, modelsReadCb, 2);
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
        }
        break;
    case 0x2a:
    case 0x45:
        result = MLDF_PTR(0x2a);
        if ((result != 0) && (MLDF_OWNER(0x2a) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x45);
        if ((result != 0) && (MLDF_OWNER(0x45) == mapId))
        {
            return result;
        }
        {
            if (MLDF_OWNER(0x2a) == -1)
            {
                slot = 0x2a;
            }
            else if (MLDF_OWNER(0x45) == -1)
            {
                slot = 0x45;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 4) == 0) && ((lbl_803DCC80 & 8) == 0))
                    {
                        mergeTableFiles(t->mergeModels, 0x2a, 0x45, 0x800);
                    }
                }
                else
                {
                    if (slot == 0x2a)
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 4;
                    }
                    else
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 8;
                    }
                    MLDF_FINFO4(x) = fi;
                    DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, modelsTabReadCb, 2);
                }
                MLDF_OWNER(slot) = mapId;
                return MLDF_SP_PTR(x);
            }
        }
        break;
    case 0x30:
    case 0x4a:
        result = MLDF_PTR(0x30);
        if ((result != 0) && (MLDF_OWNER(0x30) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x4a);
        if ((result != 0) && (MLDF_OWNER(0x4a) == mapId))
        {
            return result;
        }
        {
            if (MLDF_ID(0x30) == mapId)
            {
                slot = 0x30;
                MLDF_ID(0x30) = -1;
            }
            else if (MLDF_ID(0x4a) == mapId)
            {
                slot = 0x4a;
                MLDF_ID(0x4a) = -1;
            }
            else if (MLDF_OWNER(0x30) == -1)
            {
                slot = 0x30;
            }
            else if (MLDF_OWNER(0x4a) == -1)
            {
                slot = 0x4a;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x40) == 0) && ((lbl_803DCC80 & 0x80) == 0))
                        {
                            mergeTableFiles(t->mergeAnim, 0x2f, 0x49, 3000);
                        }
                    }
                    else
                    {
                        if (slot == 0x30)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x10;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x20;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0, animReadCb, 2);
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
        }
        break;
    case 0x2f:
    case 0x49:
        result = MLDF_PTR(0x2f);
        if ((result != 0) && (MLDF_OWNER(0x2f) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x49);
        if ((result != 0) && (MLDF_OWNER(0x49) == mapId))
        {
            return result;
        }
        {
            if (MLDF_OWNER(0x2f) == -1)
            {
                slot = 0x2f;
            }
            else if (MLDF_OWNER(0x49) == -1)
            {
                slot = 0x49;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 0x40) == 0) && ((lbl_803DCC80 & 0x80) == 0))
                    {
                        mergeTableFiles(t->mergeAnim, 0x2f, 0x49, 3000);
                    }
                }
                else
                {
                    if (slot == 0x2f)
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x40;
                    }
                    else
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x80;
                    }
                    MLDF_FINFO4(x) = fi;
                    DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animTabReadCb, 2);
                }
                MLDF_OWNER(slot) = mapId;
                return MLDF_SP_PTR(x);
            }
        }
        break;
    case 0x23:
    case 0x4d:
        result = MLDF_PTR(0x23);
        if ((result != 0) && (MLDF_OWNER(0x23) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x4d);
        if ((result != 0) && (MLDF_OWNER(0x4d) == mapId))
        {
            return result;
        }
        {
            if (MLDF_ID(0x23) == mapId)
            {
                slot = 0x23;
                MLDF_ID(0x23) = -1;
            }
            else if (MLDF_ID(0x4d) == mapId)
            {
                slot = 0x4d;
                MLDF_ID(0x4d) = -1;
            }
            else if (MLDF_OWNER(0x23) == -1)
            {
                slot = 0x23;
            }
            else if (MLDF_OWNER(0x4d) == -1)
            {
                slot = 0x4d;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x400) == 0) && ((lbl_803DCC80 & 0x800) == 0))
                        {
                            mergeTableFiles(t->mergeTex0, 0x24, 0x4e, 0x1000);
                        }
                    }
                    else
                    {
                        if (slot == 0x23)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x100;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x200;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0, tex0readCb, 2);
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
        }
        break;
    case 0x24:
    case 0x4e:
        result = MLDF_PTR(0x24);
        if ((result != 0) && (MLDF_OWNER(0x24) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x4e);
        if ((result != 0) && (MLDF_OWNER(0x4e) == mapId))
        {
            return result;
        }
        {
            if (MLDF_OWNER(0x24) == -1)
            {
                slot = 0x24;
            }
            else if (MLDF_OWNER(0x4e) == -1)
            {
                slot = 0x4e;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 0x400) == 0) && ((lbl_803DCC80 & 0x800) == 0))
                    {
                        mergeTableFiles(t->mergeTex0, 0x24, 0x4e, 0x1000);
                    }
                }
                else
                {
                    MLDF_FINFO4(x) = fi;
                    if (slot == 0x24)
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x400;
                        DVDReadAsyncPrio((void*)fi, (void*)MLDF_PTR(0x24), MLDF_SIZE(0x24), 0, tex0tab1readCb, 2);
                    }
                    else
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x800;
                        DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex0tab2readCb, 2);
                    }
                }
                MLDF_OWNER(slot) = mapId;
                return MLDF_SP_PTR(x);
            }
        }
        break;
    case 0x20:
    case 0x4b:
        result = MLDF_PTR(0x20);
        if ((result != 0) && (MLDF_OWNER(0x20) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x4b);
        if ((result != 0) && (MLDF_OWNER(0x4b) == mapId))
        {
            return result;
        }
        {
            if (MLDF_ID(0x20) == mapId)
            {
                slot = 0x20;
                MLDF_ID(0x20) = -1;
            }
            else if (MLDF_ID(0x4b) == mapId)
            {
                slot = 0x4b;
                MLDF_ID(0x4b) = -1;
            }
            else if (MLDF_OWNER(0x20) == -1)
            {
                slot = 0x20;
            }
            else if (MLDF_OWNER(0x4b) == -1)
            {
                slot = 0x4b;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose((void*)fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x4000) == 0) && ((lbl_803DCC80 & 0x8000) == 0))
                        {
                            mergeTableFiles(t->mergeTex1, 0x21, 0x4c, 0x1000);
                        }
                    }
                    else
                    {
                        if (slot == 0x20)
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x1000;
                        }
                        else
                        {
                            lbl_803DCC80 = lbl_803DCC80 | 0x2000;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio((void*)fi, (void*)tmp, MLDF_SP_SIZE(x), 0, tex1ReadCb, 2);
                    }
                    MLDF_OWNER(slot) = mapId;
                    return MLDF_SP_PTR(x);
                }
            }
        }
        break;
    case 0x21:
    case 0x4c:
        result = MLDF_PTR(0x21);
        if ((result != 0) && (MLDF_OWNER(0x21) == mapId))
        {
            return result;
        }
        result = MLDF_PTR(0x4c);
        if ((result != 0) && (MLDF_OWNER(0x4c) == mapId))
        {
            return result;
        }
        {
            if (MLDF_OWNER(0x21) == -1)
            {
                slot = 0x21;
            }
            else if (MLDF_OWNER(0x4c) == -1)
            {
                slot = 0x4c;
            }
            else
            {
                return 0;
            }
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE(x) = *(int*)(fi + 0x34);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose((void*)fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 0x4000) == 0) && ((lbl_803DCC80 & 0x8000) == 0))
                    {
                        mergeTableFiles(t->mergeTex1, 0x21, 0x4c, 0x1000);
                    }
                }
                else
                {
                    MLDF_FINFO4(x) = fi;
                    if (slot == 0x21)
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x4000;
                        DVDReadAsyncPrio((void*)fi, (void*)MLDF_PTR(0x21), MLDF_SIZE(0x21), 0, tex1tab1readCb, 2);
                    }
                    else
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x8000;
                        DVDReadAsyncPrio((void*)fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex1tab2readCb, 2);
                    }
                }
                MLDF_OWNER(slot) = mapId;
                return MLDF_SP_PTR(x);
            }
        }
        break;
    default:
        return 0;
        break;
    }
    return result;
}





extern void mmFreeTick(int arg);

extern u8 gDvdErrorPauseActive;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern u8 framesThisStep;
extern char sZlbBlockTag;
extern int return0_8002A5B8(int p);

extern asm BOOL OSRestoreInterrupts(register BOOL level);
extern char sDirBlockTag;
extern int zlbDecompress(void* dst, int size, int out, void* src);
extern u32 ObjModel_GetUnpackedResourceSize(int p, u32 size);
extern void ObjModel_UnpackResourcePayload(int p, u32 size, int dst, u32 unpacked);
void loadDataFiles(int);
int GXFlush_(u8 visible, int unused);

#pragma dont_inline on
void loadAndDecompressDataFile(int fileId, int destBuf, int offsetFlags, u32 length, u32* sizeOut, int entryIndex,
                               u32 flagBits)
{
    struct MldfTables* t = (struct MldfTables*)lbl_80345E10;
    u32 b = 0;
    u32 a = 0;
    u8 frame = 0;
    u32 hi;
    int flags;
    int entryOff;
    int moff;
    int s;
    int i;
    int k;
    int fileBuf;
    u32 alignedSize;
    int tmp;
    u32 decompSize;
    char buf[0x3c];

    switch (fileId)
    {
    case 0xd:
        s = OSDisableInterrupts();
        entryIndex = lbl_803DCC80;
        OSRestoreInterrupts(s);
        if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0)
        {
            b = MLDF_PTR(0xe);
        }
        if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0)
        {
            a = MLDF_PTR(0x56);
        }
        hi = offsetFlags & 0x80000000;
        if (hi != 0 && b == 0)
        {
            while (s = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(s), entryIndex != 0)
            {
                if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0)
                {
                    b = *(u32*)((char*)&MLDF_PTR(0) + 0x80000000);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        else if ((offsetFlags & 0x20000000) != 0 && a == 0)
        {
            while (s = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(s), entryIndex != 0)
            {
                if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0)
                {
                    a = MLDF_PTR(0);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        if ((offsetFlags & 0x20000000) != 0 && a != 0)
        {
            fileId = 0x55;
        }
        else if (hi != 0 && b != 0)
        {
            fileId = 0xd;
        }
        else if (b != 0)
        {
            fileId = 0xd;
        }
        else if (a != 0)
        {
            fileId = 0x55;
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x1b:
        s = OSDisableInterrupts();
        entryIndex = lbl_803DCC80;
        OSRestoreInterrupts(s);
        if ((entryIndex & 0x2000000) == 0 && (entryIndex & 0x1000000) == 0)
        {
            b = MLDF_PTR(0x1a);
        }
        if ((entryIndex & 0x8000000) == 0 && (entryIndex & 0x4000000) == 0)
        {
            a = MLDF_PTR(0x53);
        }
        hi = offsetFlags & 0x80000000;
        if (hi != 0 && b == 0)
        {
            while (s = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(s), entryIndex != 0)
            {
                if ((entryIndex & 0x2000000) == 0 && (entryIndex & 0x1000000) == 0)
                {
                    b = MLDF_PTR(0x1a);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        else if ((offsetFlags & 0x20000000) != 0 && a == 0)
        {
            while (s = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(s), entryIndex != 0)
            {
                if ((entryIndex & 0x8000000) == 0 && (entryIndex & 0x4000000) == 0)
                {
                    a = MLDF_PTR(0x53);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        if ((offsetFlags & 0x20000000) != 0 && a != 0)
        {
            fileId = 0x54;
        }
        else if (hi != 0 && b != 0)
        {
            fileId = 0x1b;
        }
        else if (b != 0)
        {
            fileId = 0x1b;
        }
        else if (a != 0)
        {
            fileId = 0x54;
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x25:
        s = OSDisableInterrupts();
        entryIndex = lbl_803DCC80;
        OSRestoreInterrupts(s);
        if ((entryIndex & 0x20000) == 0 && (entryIndex & 0x10000) == 0)
        {
            b = MLDF_PTR(0x26);
        }
        if ((entryIndex & 0x80000) == 0 && (entryIndex & 0x40000) == 0)
        {
            a = MLDF_PTR(0x48);
        }
        if ((offsetFlags & 0x20000000) != 0 && a != 0)
        {
            fileId = 0x47;
        }
        else if ((offsetFlags & 0x10000000) != 0 && b != 0)
        {
            fileId = 0x25;
        }
        else if (b != 0)
        {
            fileId = 0x25;
        }
        else if (a != 0)
        {
            fileId = 0x47;
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x2b:
        s = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(s);
        if ((flags & 4) == 0 && (flags & 1) == 0)
        {
            b = MLDF_PTR(0x2a);
        }
        if ((flags & 8) == 0 && (flags & 2) == 0)
        {
            a = MLDF_PTR(0x45);
        }
        if ((offsetFlags & 0x10000000) != 0 && b == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 4) == 0 && (flags & 1) == 0)
                {
                    b = MLDF_PTR(0x2a);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        else if ((offsetFlags & 0x20000000) != 0 && a == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 8) == 0 && (flags & 2) == 0)
                {
                    a = MLDF_PTR(0x45);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        if (a != 0 && (offsetFlags & 0x20000000) != 0)
        {
            fileId = 0x46;
            if (sizeOut != NULL)
            {
                moff = ((int*)a)[entryIndex] & 0xffffff;
                i = 0;
                if (moff == 0)
                {
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - moff;
                }
                else if (moff < (((int*)(a - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while (moff != (((int*)a)[k] & 0xffffff));
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - moff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - moff;
                }
            }
        }
        else if (b != 0 && (offsetFlags & 0x10000000) != 0)
        {
            fileId = 0x2b;
            if (sizeOut != NULL)
            {
                moff = ((int*)b)[entryIndex] & 0xffffff;
                i = 0;
                if (moff == 0)
                {
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - moff;
                }
                else if (moff < (((int*)(b - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while (moff != (((int*)b)[k] & 0xffffff));
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - moff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - moff;
                }
            }
        }
        else if (b != 0)
        {
            fileId = 0x2b;
            if (sizeOut != NULL)
            {
                moff = ((int*)b)[entryIndex] & 0xffffff;
                i = 0;
                if (moff == 0)
                {
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - moff;
                }
                else if (moff < (((int*)(b - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while (moff != (((int*)b)[k] & 0xffffff));
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - moff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - moff;
                }
            }
        }
        else if (a != 0)
        {
            fileId = 0x46;
            if (sizeOut != NULL)
            {
                moff = ((int*)a)[entryIndex] & 0xffffff;
                i = 0;
                if (moff == 0)
                {
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - moff;
                }
                else if (moff < (((int*)(a - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while (moff != (((int*)a)[k] & 0xffffff));
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - moff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= moff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - moff;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x30:
        s = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(s);
        if ((flags & 0x40) == 0 && (flags & 0x10) == 0)
        {
            b = MLDF_PTR(0x2f);
        }
        if ((flags & 0x80) == 0 && (flags & 0x20) == 0)
        {
            a = MLDF_PTR(0x49);
        }
        if ((offsetFlags & 0x10000000) != 0 && b == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 0x40) == 0 && (flags & 0x10) == 0)
                {
                    b = MLDF_PTR(0x2f);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        else if ((offsetFlags & 0x20000000) != 0 && a == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 0x80) == 0 && (flags & 0x20) == 0)
                {
                    a = MLDF_PTR(0x49);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        if ((offsetFlags & 0x20000000) != 0)
        {
            fileId = 0x4a;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(a + 4))[entryIndex] & 0xfffffff) - (((u32*)a)[entryIndex] & 0xfffffff);
            }
        }
        else if ((offsetFlags & 0x10000000) != 0)
        {
            fileId = 0x30;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(b + 4))[entryIndex] & 0xfffffff) - (((u32*)b)[entryIndex] & 0xfffffff);
            }
        }
        else if (b != 0)
        {
            fileId = 0x30;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(b + 4))[entryIndex] & 0xfffffff) - (((u32*)b)[entryIndex] & 0xfffffff);
            }
        }
        else if (a != 0)
        {
            fileId = 0x4a;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(a + 4))[entryIndex] & 0xfffffff) - (((u32*)a)[entryIndex] & 0xfffffff);
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        if (((u8)flagBits & 1) != 0)
        {
            fileBuf = MLDF_PTR(fileId);
            tmp = return0_8002A5B8(fileBuf + offsetFlags);
            if (tmp != 0)
            {
                *sizeOut = ObjModel_GetUnpackedResourceSize(fileBuf + offsetFlags, *sizeOut);
            }
        }
        break;
    case 0x51:
        if (MLDF_PTR(0x52) != 0)
        {
            fileId = 0x51;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(MLDF_PTR(0x52) + 4))[entryIndex] & 0xfffffff) -
                    (((u32*)MLDF_PTR(0x52))[entryIndex] & 0xfffffff);
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        if (((u8)flagBits & 1) != 0)
        {
            fileBuf = MLDF_PTR(fileId);
            tmp = return0_8002A5B8(fileBuf + offsetFlags);
            if (tmp != 0)
            {
                *sizeOut = ObjModel_GetUnpackedResourceSize(fileBuf + offsetFlags, *sizeOut);
            }
        }
        break;
    case 0x23:
        s = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(s);
        if ((flags & 0x100) == 0 && (flags & 0x100) == 0)
        {
            b = MLDF_PTR(0x24);
        }
        if ((flags & 0x800) == 0 && (flags & 0x200) == 0)
        {
            a = MLDF_PTR(0x4e);
        }
        if ((offsetFlags & 0x40000000) != 0 && b == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 0x100) == 0 && (flags & 0x100) == 0)
                {
                    b = MLDF_PTR(0x24);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        else if ((offsetFlags & 0x80000000) != 0 && a == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 0x800) == 0 && (flags & 0x200) == 0)
                {
                    a = MLDF_PTR(0x4e);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        if (a != 0 && (((u32*)t->mergeTex0)[entryIndex] & 0x80000000) != 0)
        {
            fileId = 0x4d;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)a)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (b != 0 && (((u32*)t->mergeTex0)[entryIndex] & 0x40000000) != 0)
        {
            fileId = 0x23;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)b)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (b != 0)
        {
            fileId = 0x23;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)b)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (a != 0)
        {
            fileId = 0x4d;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)a)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x20:
        s = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(s);
        if ((flags & 0x4000) == 0 && (flags & 0x1000) == 0)
        {
            b = MLDF_PTR(0x21);
        }
        if ((flags & 0x8000) == 0 && (flags & 0x2000) == 0)
        {
            a = MLDF_PTR(0x4c);
        }
        if ((offsetFlags & 0x40000000) != 0 && b == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 0x1000) == 0 && (flags & 0x1000) == 0)
                {
                    b = MLDF_PTR(0x21);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        else if ((offsetFlags & 0x80000000) != 0 && a == 0)
        {
            while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0)
            {
                if ((flags & 0x8000) == 0 && (flags & 0x2000) == 0)
                {
                    a = MLDF_PTR(0x4c);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0)
                {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0)
                {
                    frame = 1;
                }
            }
        }
        if (a != 0 && (((u32*)t->mergeTex1)[entryIndex] & 0x80000000) != 0)
        {
            fileId = 0x4b;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)a)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (b != 0 && (((u32*)t->mergeTex1)[entryIndex] & 0x40000000) != 0)
        {
            fileId = 0x20;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)b)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (b != 0)
        {
            fileId = 0x20;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)b)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)b)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(b - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (a != 0)
        {
            fileId = 0x4b;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)a)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)a)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(a - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x4f:
        flags = MLDF_PTR(0x50);
        if (flags != 0)
        {
            fileId = 0x4f;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)flags)[entryIndex] & 0xffffff;
                if (entryOff == 0)
                {
                    i = 0;
                    do
                    {
                        k = i;
                        i = i + 1;
                    }
                    while ((((int*)flags)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(flags - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    do
                    {
                        k = entryIndex;
                        entryIndex = entryIndex + 1;
                    }
                    while ((((int*)flags)[k] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(flags - 4))[entryIndex] & 0xffffff) - entryOff;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    }
    if (((u8)flagBits & 1) != 0)
    {
        return;
    }
    fileBuf = MLDF_PTR(fileId);
    if (fileBuf == 0)
    {
        if (fileId == 0x20 || fileId == 0x4b)
        {
            DVDOpen(sResourceFileNameTable[fileId], buf);
            alignedSize = (length + 0x1f) & 0xffffffe0;
            fileBuf = (int)mmAlloc(alignedSize, 0x7f7f7fff, 0);
            DVDRead(buf, (void*)fileBuf, alignedSize, offsetFlags & 0xffffff);
            DVDClose(buf);
            DCStoreRange((void*)fileBuf, length);
            if (strncmp(&sDirBlockTag, (char*)fileBuf, 3) == 0)
            {
                for (;;)
                {
                }
            }
            if (strncmp((char*)fileBuf, &sZlbBlockTag, 3) == 0)
            {
                decompSize = *(u32*)(fileBuf + 8);
                zlbDecompress((void*)(fileBuf + 0x10), *(int*)(fileBuf + 0xc), destBuf, &decompSize);
            }
            mm_free((void*)fileBuf);
        }
        else
        {
            DVDOpen(sResourceFileNameTable[fileId], buf);
            if (((u32)destBuf & 0x1f) == 0 && (length & 0x1f) == 0)
            {
                DVDRead(buf, (void*)destBuf, length, offsetFlags);
            }
            else
            {
                alignedSize = (length + 0x1f) & 0xffffffe0;
                tmp = (int)mmAlloc(alignedSize, 0x7f7f7fff, 0);
                DVDRead(buf, (void*)tmp, alignedSize, offsetFlags);
                memcpy((void*)destBuf, (void*)tmp, length);
                mm_free((void*)tmp);
            }
            DCStoreRange((void*)destBuf, length);
            DVDClose(buf);
        }
    }
    else if (fileId == 0xd || fileId == 0x55)
    {
        if (fileBuf == 0)
        {
            return;
        }
        memcpy((void*)destBuf, (void*)(fileBuf + offsetFlags), length);
    }
    else if (fileId == 0x1b || fileId == 0x54)
    {
        if (fileBuf == 0)
        {
            return;
        }
        fileBuf = fileBuf + offsetFlags;
        if (strncmp((char*)fileBuf, &sZlbBlockTag, 3) != 0)
        {
            return;
        }
        decompSize = *(u32*)(fileBuf + 8);
        zlbDecompress((void*)(MLDF_PTR(fileId) + offsetFlags + 0x10), *(int*)(fileBuf + 0xc), destBuf, &decompSize);
        DCStoreRange((void*)destBuf, decompSize);
    }
    else if (fileId == 0x25 || fileId == 0x47)
    {
        if (fileBuf == 0)
        {
            return;
        }
        fileBuf = fileBuf + offsetFlags;
        if (strncmp((char*)fileBuf, &sZlbBlockTag, 3) != 0)
        {
            return;
        }
        decompSize = *(u32*)(fileBuf + 8);
        zlbDecompress((void*)(MLDF_PTR(fileId) + offsetFlags + 0x10), *(int*)(fileBuf + 0xc), destBuf, &decompSize);
        DCStoreRange((void*)destBuf, decompSize);
    }
    else if (fileId == 0x2b || fileId == 0x46)
    {
        int* p = (int*)(fileBuf + offsetFlags);
        if (*p == 0xe0e0e0e0)
        {
            memcpy((void*)destBuf, (void*)((int)p + p[2] + 0x18), p[1]);
        }
        else if (*p == 0xfacefeed)
        {
            zlbDecompress((void*)((int)p + p[2] + 0x28), p[3] - 0x10, destBuf, p + 1);
            DCStoreRange((void*)destBuf, p[1]);
        }
    }
    else if (fileId == 0x23 || fileId == 0x4d)
    {
        fileBuf = fileBuf + (offsetFlags & 0xffffff);
        decompSize = *(u32*)(fileBuf + 8);
        zlbDecompress((void*)(fileBuf + 0x10), *(int*)(fileBuf + 0xc), destBuf, &decompSize);
        DCStoreRange((void*)destBuf, decompSize);
    }
    else if (fileId == 0x20 || fileId == 0x4b)
    {
        offsetFlags = offsetFlags & 0xffffff;
        fileBuf = fileBuf + offsetFlags;
        if (strncmp(&sDirBlockTag, (char*)fileBuf, 3) == 0)
        {
            return;
        }
        if (strncmp((char*)fileBuf, &sZlbBlockTag, 3) == 0)
        {
            decompSize = *(u32*)(fileBuf + 8);
            zlbDecompress((void*)(MLDF_PTR(fileId) + offsetFlags + 0x10), *(int*)(fileBuf + 0xc), destBuf, &decompSize);
            DCStoreRange((void*)destBuf, decompSize);
        }
    }
    else if (fileId == 0x4f)
    {
        offsetFlags = offsetFlags & 0xffffff;
        fileBuf = fileBuf + offsetFlags;
        if (strncmp(&sDirBlockTag, (char*)fileBuf, 3) == 0)
        {
            return;
        }
        if (strncmp((char*)fileBuf, &sZlbBlockTag, 3) == 0)
        {
            decompSize = *(u32*)(fileBuf + 8);
            zlbDecompress((void*)(MLDF_PTR(0x4f) + offsetFlags + 0x10), *(int*)(fileBuf + 0xc), destBuf, &decompSize);
            DCStoreRange((void*)destBuf, decompSize);
        }
    }
    else if (fileId == 0x30 || fileId == 0x51 || fileId == 0x4a)
    {
        fileBuf = fileBuf + offsetFlags;
        tmp = return0_8002A5B8(fileBuf);
        if (tmp == 0)
        {
            memcpy((void*)destBuf, (void*)(MLDF_PTR(fileId) + offsetFlags), length);
        }
        else
        {
            alignedSize = ObjModel_GetUnpackedResourceSize(fileBuf, *sizeOut);
            ObjModel_UnpackResourcePayload(fileBuf, *sizeOut, destBuf, alignedSize);
        }
    }
    else
    {
        memcpy((void*)destBuf, (void*)(fileBuf + offsetFlags), length);
    }
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void FUN_800443fc(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
}

void FUN_80044400(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  u32 param_9, u32 param_10, u32 param_11, u32 param_12, u32* param_13,
                  int param_14, u32 param_15, u32 param_16)
{
}

u32 FUN_80044404(int idx)
{
    if (0x4a < idx)
    {
        return 5;
    }
    return (&DAT_802cc8a8)[idx];
}

void FUN_80044424(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
}

extern int lbl_8035F208[];
extern u32 lbl_8035F3E8[];
extern char* sMapFileNameTable[];
extern int lbl_803DCC74;
extern void romListReadCb();
#pragma scheduling off
#pragma peephole off
void piRomLoadSection(int romOffset, int mapIndex, int destBuf)
{
    char buf[1024];
    int fi;
    int ok;
    int* p;

    if (((void*)destBuf == NULL) && ((void*)lbl_8035F208[mapIndex] == NULL))
    {
        sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
        fi = AtomicSList_Pop(lbl_803DCC8C);
        ok = DVDOpen(buf, (void*)fi);
        if (ok != 0)
        {
            lbl_8035F208[mapIndex] = (int)mmAlloc(*(int*)(fi + 0x34), 0x7d7d7d7d, 0);
            lbl_803DCC74 = 1;
            DVDReadAsyncPrio((void*)fi, (void*)lbl_8035F208[mapIndex], *(int*)(fi + 0x34), 0, romListReadCb, 2);
        }
    }
    else
    {
        if ((void*)lbl_8035F208[mapIndex] == NULL)
        {
            sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, (void*)fi);
            if (ok == 0)
            {
                return;
            }
            lbl_8035F208[mapIndex] = (int)mmAlloc(*(int*)(fi + 0x34), 0x7d7d7d7d, 0);
            DVDRead((void*)fi, (void*)lbl_8035F208[mapIndex], *(int*)(fi + 0x34), 0);
            DVDClose((void*)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
        }
        p = (int*)(lbl_8035F3E8[0x1d] + romOffset);
        if (*p == 0xfacefeed)
        {
            zlbDecompress((void*)(lbl_8035F208[mapIndex] + 0x10), p[3], destBuf, p + 1);
            DCStoreRange((void*)destBuf, p[1]);
        }
    }
}

#pragma scheduling on
#pragma peephole on
void FUN_80045328(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  u32 param_9, u32 param_10, u32 param_11, u32 param_12,
                  u32 param_13, u32 param_14, u32 param_15, u32 param_16)
{
    u32 aligned;
    int resIdx;
    u32 scratch;
    u32 dst;
    u64 extraout_f1;
    u64 src;
    u64 pairWord;
    int aiStack_58[22];

    pairWord = FUN_80286840();
    resIdx = (int)(pairWord >> 0x20);
    dst = pairWord;
    if (param_12 != 0)
    {
        if ((&DAT_80360048)[resIdx] == 0)
        {
            src = extraout_f1;
            FUN_80249300(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         sResourceFileNameTable[resIdx], aiStack_58);
            if (((pairWord & 0x1f) == 0) && ((param_12 & 0x1f) == 0))
            {
                FUN_802420b0(dst, param_12);
                FUN_80006c30(src, param_2, param_3, param_4, param_5, param_6, param_7, param_8, aiStack_58, dst,
                             param_12, param_11, param_13, param_14, param_15, param_16);
            }
            else
            {
                aligned = param_12 + 0x1f & ~0x1f;
                scratch = FUN_80017830(aligned, 0x7d7d7d7d);
                FUN_802420b0(scratch, aligned);
                FUN_80006c30(src, param_2, param_3, param_4, param_5, param_6, param_7, param_8, aiStack_58, scratch,
                             aligned, param_11, param_13, param_14, param_15, param_16);
                FUN_80003494(dst, scratch, param_12);
                FUN_80017814(scratch);
            }
            FUN_802493c8(aiStack_58);
            FUN_80242114(dst, param_12);
        }
        else
        {
            FUN_80003494(dst, (&DAT_80360048)[resIdx] + param_11, param_12);
            FUN_80242114(dst, param_12);
        }
    }
    FUN_8028688c();
    return;
}

void FUN_80045be8(void)
{
    if ((DAT_803dd970 == &DAT_8032f2b4) || (DAT_803dd970[0x18] != '\0'))
    {
        FUN_80259858(DAT_803dd970[0x19], DAT_803dd970 + 0x1a, '\0', DAT_803dd970 + 0x32);
    }
    else
    {
        FUN_80259858(DAT_803dd970[0x19], DAT_803dd970 + 0x1a, '\x01', &DAT_803dc234);
    }
    return;
}

u32 FUN_80045c4c(char tick)
{
    bool wasFront;
    u32 one;
    u32* matPtr;
    u64 pairWord;
    u32 mat0;
    u32 uStack_24;
    u32 local_20;
    u32 local_1c;
    u32 local_18;

    one = 1;
    gxSetZMode_(1, 3, 1);
    pairWord = FUN_8025ce2c(1);
    FUN_80258a04((int)((u64)pairWord >> 0x20), pairWord, one);
    matPtr = &mat0;
    FUN_80256b2c(DAT_803dd954, &uStack_24, matPtr);
    local_20 = mat0;
    local_1c = 0;
    local_18 = DAT_803dd950;
    FUN_80243e74();
    FUN_80006aa8((short*)&DAT_80360390,  & local_20);
    if (DAT_803dd927 == '\0')
    {
        FUN_80256c08(mat0);
        DAT_803dd927 = '\x01';
    }
    FUN_80243e9c();
    FUN_80258b60((u32)DAT_803dc22e);
    pairWord = FUN_80259a9c(DAT_803dd950, 1);
    FUN_80258a04((int)((u64)pairWord >> 0x20), pairWord, matPtr);
    DAT_803dc22e = DAT_803dc22e + 1;
    wasFront = DAT_803dd950 == DAT_803dd96c;
    DAT_803dd950 = DAT_803dd96c;
    if (wasFront)
    {
        DAT_803dd950 = DAT_803dd968;
    }
    if (((tick != '\0') && (DAT_803dc22c != '\0')) &&
        (DAT_803dc22c = DAT_803dc22c + -1, DAT_803dc22c == '\0'))
    {
        FUN_8024de40(0);
        DAT_803dc22c = '\0';
    }
    return 0;
}

void fn_8004A8F8(char enabled)
{
    if (enabled == '\0')
    {
        *(u8*)&DAT_cc008000 = 0x61;
        DAT_cc008000 = 0x24000000;
        *(u8*)&DAT_cc008000 = 0x61;
        DAT_cc008000 = 0x23000000;
        *(u8*)&DAT_cc008000 = 0x10;
        *(u16*)&DAT_cc008000 = 0;
        *(u16*)&DAT_cc008000 = 0x1006;
        DAT_cc008000 = 0;
    }
    else
    {
        FUN_8025dc78(0x23, 0x16);
        *(u8*)&DAT_cc008000 = 0x61;
        DAT_cc008000 = 0x2402c004;
        *(u8*)&DAT_cc008000 = 0x61;
        DAT_cc008000 = 0x23000020;
        *(u8*)&DAT_cc008000 = 0x10;
        *(u16*)&DAT_cc008000 = 0;
        *(u16*)&DAT_cc008000 = 0x1006;
        DAT_cc008000 = 0x84400;
    }
}

void FUN_8004600c(void)
{
    u32 frac;
    u32 whole;
    double elapsed;
    u64 pairWord;

    FUN_802461cc(-0x7fc9fd20);
    pairWord = FUN_80246298(-0x7fc9fd20);
    elapsed = FUN_80286cd0((u32)((u64)pairWord >> 0x20), pairWord);
    lbl_803DD940 =
        (float)(elapsed / (double)(float)((double)(u32)(DAT_800000f8 / 4000)));
    FUN_80246308(-0x7fc9fd20);
    FUN_80246190(-0x7fc9fd20);
    lbl_803DC074 = lbl_803DF71C * lbl_803DF720 * lbl_803DD940;
    if (DAT_803dd5d0 != '\0')
    {
        lbl_803DC074 = lbl_803DF6F0;
    }
    if (lbl_803DF6F4 < lbl_803DC074)
    {
        lbl_803DC074 = lbl_803DF6F4;
    }
    lbl_803DC078 = lbl_803DF6F8;
    if (lbl_803DF6FC < lbl_803DC074)
    {
        lbl_803DC078 = lbl_803DF6F8 / lbl_803DC074;
    }
    whole = (u32)(lbl_803DC074 + lbl_803DD934);
    frac = whole & 0xff;
    DAT_803dc071 = (u8)whole;
    lbl_803DD934 =
        (lbl_803DC074 + lbl_803DD934) -
        (float)((double)(u32)frac);
    DAT_803dc070 = DAT_803dc071;
    if (frac == 0)
    {
        DAT_803dc070 = 1;
    }
    FUN_80243e74();
    DAT_803dd95c = FUN_802464ec();
    if (*(short*)(DAT_803dd95c + 0x2c8) != 2)
    {
        FUN_800723a0();
    }
    whole = FUN_80006a90((short*)&DAT_80360390);
    if (1 < whole)
    {
        DAT_803dd92c = 0;
        FUN_802471c4((int*)&DAT_803dd944);
    }
    FUN_80243e9c();
    FUN_80006988();
    FUN_80258664();
    FUN_8025b210();
    return;
}

u32 FUN_800461b4(int* ctx, int* entry)
{
    u32 clz;
    int node;
    int target;
    int matchVal;
    int base;
    int i;
    int remaining;

    matchVal = ctx[4];
    target = *entry;
    if (*(char*)(target + 0x19) != '$')
    {
        clz = countLeadingZeros(target - matchVal);
        return clz >> 5;
    }
    if ((*(u8*)(entry + 3) & 0x80) == 0)
    {
        if (*(u8*)(target + 3) != 0)
        {
            clz = countLeadingZeros((u32) * (u8*)(target + 3) - matchVal);
            return clz >> 5;
        }
        base = *(int*)(*ctx + (u32) * (u8*)(entry + 3) * 0x10);
        i = 0;
        remaining = 4;
        node = base;
        do
        {
            if (*(int*)(target + 0x14) == *(int*)(node + 0x1c))
            {
                clz = countLeadingZeros((u32) * (u8*)(i + base + 4) - matchVal);
                return clz >> 5;
            }
            node = node + 4;
            i = i + 1;
            remaining = remaining + -1;
        }
        while (remaining != 0);
    }
    return 0;
}

void FUN_80046270(int heap, int size, int idx)
{
    u16 tag;
    u32* slot;
    u32 childKey;
    u32* child;
    u32 key;
    int childIdx;

    key = *(u32*)(heap + idx * 8);
    tag = *(u16*)(heap + idx * 8 + 4);
    while (idx <= size >> 1)
    {
        childIdx = idx * 2;
        if ((childIdx < size) && (child = (u32*)(heap + idx * 0x10), *child < child[2]))
        {
            childIdx = childIdx + 1;
        }
        child = (u32*)(heap + childIdx * 8);
        childKey = *child;
        if (childKey <= key) break;
        slot = (u32*)(heap + idx * 8);
        *slot = childKey;
        *(u16*)(slot + 1) = *(u16*)(child + 1);
        idx = childIdx;
    }
    *(u32*)(heap + idx * 8) = key;
    *(u16*)(heap + idx * 8 + 4) = tag;
    return;
}

void fn_8004B11C(u32 ctxArg, u32 entryArg, u8 key)
{
    int sel;
    u32 mask;
    int ctxHi;
    int found;
    u32 uval;
    int* ctx;
    int bit;
    int ent;
    int entCur;
    double fval;
    u64 pairWord;

    pairWord = FUN_80286834();
    ctxHi = (int)((u64)pairWord >> 0x20);
    ctx = (int*)pairWord;
    ent = *ctx;
    if (*(char*)(ctxHi + 0x28) == '\0')
    {
        mask = ~(int)*(char*)(ent + 0x1b);
    }
    else
    {
        mask = (u32) * (char*)(ent + 0x1b);
    }
    bit = 0;
    entCur = ent;
    do
    {
        sel = DAT_803dd988;
        if ((((-1 < *(int*)(entCur + 0x1c)) && ((mask & 0xff & 1 << bit) != 0)) &&
                (found = (**(VtableFn**)(*DAT_803dd71c + 0x1c))(), sel = DAT_803dd988, found != 0)) &&
            (sel = found, *(char*)(found + 0x19) == '$'))
        {
            GameBit_Get(0x4e2);
            if (((((int)*(short*)(found + 0x30) == -1) ||
                        (uval = GameBit_Get((int)*(short*)(found + 0x30)), sel = DAT_803dd988, uval != 0))
                    && (((int)*(short*)(found + 0x32) == -1 ||
                        (uval = GameBit_Get((int)*(short*)(found + 0x32)), sel = DAT_803dd988,
                            uval == 0)))) &&
                ((*(char*)(found + 0x1a) != '\b' || (*(char*)(ent + 0x1a) != '\t'))))
            {
                fval = FUN_80017714((float*)(ent + 8), (float*)(found + 8));
                uval = FUN_80286718((double)(float)((double)(float)((double)(u32)ctx[2]) + fval));
                FUN_800462f8((u32)ctxHi, (u32)(u32)ctx, key, uval, found);
                sel = DAT_803dd988;
            }
        }
        DAT_803dd988 = sel;
        entCur = entCur + 4;
        bit = bit + 1;
    }
    while (bit < 4);
    FUN_80286880();
}

u32 FUN_800469d0(int list)
{
    short cur;

    cur = *(short*)(list + 0x2c);
    if ((int)cur < (int)*(short*)(list + 0x2a))
    {
        *(short*)(list + 0x2c) = cur + 1;
        return *(u32*)(*(int*)(list + 8) + cur * 4);
    }
    return 0;
}

void fn_8004B394(void)
{
    short count;
    bool done;
    int* heapCtx;
    int heapArr;
    u32 uval;
    int* entry;
    u32 poppedKey;
    int remaining;
    u64 pairWord;

    pairWord = FUN_8028683c();
    heapCtx = (int*)((u64)pairWord >> 0x20);
    done = false;
    for (remaining = pairWord; (!done && (remaining != 0)); remaining = remaining + -1)
    {
        heapArr = heapCtx[1];
        if (*(short*)((int)heapCtx + 0x22) == 0)
        {
            poppedKey = 0xffffffff;
        }
        else
        {
            poppedKey = (u32) * (u16*)(heapArr + 0xc);
            *(u32*)(heapArr + 8) = *(u32*)(heapArr + *(short*)((int)heapCtx + 0x22) * 8);
            count = *(short*)((int)heapCtx + 0x22);
            *(short*)((int)heapCtx + 0x22) = count + -1;
            *(u16*)(heapArr + 0xc) = *(u16*)(heapArr + count * 8 + 4);
            FUN_80046270(heapArr, (int)*(short*)((int)heapCtx + 0x22), 1);
        }
        if ((int)poppedKey < 0)
        {
            done = true;
        }
        else
        {
            entry = (int*)(*heapCtx + poppedKey * 0x10);
            heapCtx[7] = poppedKey;
            uval = FUN_800461b4(heapCtx, entry);
            if (uval == 0)
            {
                *(u8*)((int)entry + 0xe) = 1;
                fn_8004B11C((u32)heapCtx, (u32)entry, poppedKey);
            }
            else
            {
                done = true;
            }
        }
    }
    FUN_80286888();
    return;
}

u32 FUN_80046cd0(int* queue, int startNode, int targetPos, int param_4, u8 flag)
{
    u16 tag;
    short count;
    int idx;
    u32* heap;
    u32 key;
    int off8;
    int off10;
    int* entry;
    int remaining;
    double dist;

    idx = 0;
    *(u16*)((int)queue + 0x22) = 0;
    *(u16*)(queue + 8) = 0;
    off8 = 0;
    off10 = 0;
    remaining = 0x1f;
    do
    {
        *(u32*)(queue[1] + off8) = 0;
        *(u8*)(*queue + off10 + 0xe) = 0;
        *(u32*)(queue[1] + off8 + 8) = 0;
        *(u8*)(*queue + off10 + 0x1e) = 0;
        *(u32*)(queue[1] + off8 + 0x10) = 0;
        *(u8*)(*queue + off10 + 0x2e) = 0;
        *(u32*)(queue[1] + off8 + 0x18) = 0;
        *(u8*)(*queue + off10 + 0x3e) = 0;
        *(u32*)(queue[1] + off8 + 0x20) = 0;
        *(u8*)(*queue + off10 + 0x4e) = 0;
        *(u32*)(queue[1] + off8 + 0x28) = 0;
        *(u8*)(*queue + off10 + 0x5e) = 0;
        *(u32*)(queue[1] + off8 + 0x30) = 0;
        *(u8*)(*queue + off10 + 0x6e) = 0;
        *(u32*)(queue[1] + off8 + 0x38) = 0;
        *(u8*)(*queue + off10 + 0x7e) = 0;
        off8 = off8 + 0x40;
        off10 = off10 + 0x80;
        idx = idx + 8;
        remaining = remaining + -1;
    }
    while (remaining != 0);
    off8 = idx * 8;
    off10 = idx * 0x10;
    remaining = 0xfe - idx;
    if (idx < 0xfe)
    {
        do
        {
            *(u32*)(queue[1] + off8) = 0;
            *(u8*)(*queue + off10 + 0xe) = 0;
            off8 = off8 + 8;
            off10 = off10 + 0x10;
            remaining = remaining + -1;
        }
        while (remaining != 0);
    }
    queue[6] = startNode;
    queue[3] = targetPos;
    queue[4] = param_4;
    *(u8*)(queue + 10) = flag & 1;
    queue[9] = 10000;
    count = *(short*)(queue + 8);
    if (count == 0xfe)
    {
        entry = 0x0;
    }
    else
    {
        *(short*)(queue + 8) = count + 1;
        entry = (int*)(*queue + count * 0x10);
        *entry = startNode;
        entry[2] = 0;
        *(u8*)(entry + 3) = 0xff;
        dist = FUN_80017714((float*)(*entry + 8), (float*)queue[3]);
        idx = FUN_80286718(dist);
        entry[1] = idx;
    }
    off8 = entry[1];
    idx = entry[2];
    heap = (u32*)queue[1];
    count = *(short*)((int)queue + 0x22) + 1;
    *(short*)((int)queue + 0x22) = count;
    *(short*)(heap + count * 2 + 1) = *(short*)(queue + 8) + -1;
    heap[*(short*)((int)queue + 0x22) * 2] = -1 - (off8 + idx);
    idx = (int)*(short*)((int)queue + 0x22);
    key = heap[idx * 2];
    tag = *(u16*)(heap + idx * 2 + 1);
    *heap = 0xffffffff;
    while (off8 = idx >> 1, heap[off8 * 2] < key)
    {
        *(u16*)(heap + idx * 2 + 1) = *(u16*)(heap + off8 * 2 + 1);
        heap[idx * 2] = heap[off8 * 2];
        idx = off8;
    }
    heap[idx * 2] = key;
    *(u16*)(heap + idx * 2 + 1) = tag;
    return 0;
}

void FUN_80047d88(char* color, char doRgb, char doAlpha, u32* rgbOut, u32* alphaOut)
{
    char comp;
    bool rgbResolved;
    bool alphaResolved;
    u32 colorWord[2];

    rgbResolved = false;
    alphaResolved = false;
    if (doRgb == '\0')
    {
        rgbResolved = true;
    }
    else
    {
        comp = *color;
        if ((comp == color[1]) && (comp == color[2]))
        {
            if (comp == -1)
            {
                *rgbOut = 0;
                rgbResolved = true;
            }
            else if (comp == -0x20)
            {
                *rgbOut = 1;
                rgbResolved = true;
            }
            else if (comp == -0x40)
            {
                *rgbOut = 2;
                rgbResolved = true;
            }
            else if (comp == -0x60)
            {
                *rgbOut = 3;
                rgbResolved = true;
            }
            else if (comp == -0x80)
            {
                *rgbOut = 4;
                rgbResolved = true;
            }
            else if (comp == '`')
            {
                *rgbOut = 5;
                rgbResolved = true;
            }
            else if (comp == '@')
            {
                *rgbOut = 6;
                rgbResolved = true;
            }
            else if (comp == ' ')
            {
                *rgbOut = 7;
                rgbResolved = true;
            }
        }
        if (!rgbResolved)
        {
            *rgbOut = DAT_803dd9f0;
        }
    }
    if (doAlpha == '\0')
    {
        alphaResolved = true;
    }
    else
    {
        comp = color[3];
        if (comp == -1)
        {
            *alphaOut = 0;
            alphaResolved = true;
        }
        else if (comp == -0x20)
        {
            *alphaOut = 1;
            alphaResolved = true;
        }
        else if (comp == -0x40)
        {
            *alphaOut = 2;
            alphaResolved = true;
        }
        else if (comp == -0x60)
        {
            *alphaOut = 3;
            alphaResolved = true;
        }
        else if (comp == -0x80)
        {
            *alphaOut = 4;
            alphaResolved = true;
        }
        else if (comp == '`')
        {
            *alphaOut = 5;
            alphaResolved = true;
        }
        else if (comp == '@')
        {
            *alphaOut = 6;
            alphaResolved = true;
        }
        else if (comp == ' ')
        {
            *alphaOut = 7;
            alphaResolved = true;
        }
        if (!alphaResolved)
        {
            *alphaOut = DAT_803dd9ec;
        }
    }
    if ((!rgbResolved) || (!alphaResolved))
    {
        colorWord[0] = *(u32*)color;
        FUN_8025c510(DAT_803dd9f4, (u8*)colorWord);
        DAT_803dd9f4 = DAT_803dd9f4 + 1;
        DAT_803dd9f0 = DAT_803dd9f0 + 1;
        DAT_803dd9ec = DAT_803dd9ec + 1;
    }
    return;
}

void FUN_80047fdc(double value, u8 mode)
{
    uRam803dc24f = mode;
    lbl_803DC250 = (float)value;
    if (value <= (double)lbl_803DF748)
    {
        return;
    }
    lbl_803DC250 = lbl_803DF748;
    return;
}

void FUN_80048000(void)
{
    DAT_803dd9a8 = 0;
    return;
}

void FUN_8004800c(double param_1, double param_2, double param_3, double param_4, double param_5,
                  u8 param_6)
{
    DAT_803dd9a8 = 1;
    lbl_803DD9C4 = (float)param_1;
    lbl_803DD9C0 = (float)param_2;
    lbl_803DD9BC = (float)param_3;
    lbl_803DD9B8 = (float)param_4;
    lbl_803DD9B4 = (float)param_5;
    DAT_803dd9b1 = param_6;
    return;
}

u8 FUN_80048094(void)
{
    return DAT_803dd9a8;
}

int FUN_800480a0(int base, int idx)
{
    return base + idx * 8 + 0x24;
}

void FUN_8004812c(int tex, int arg)
{
    if (tex != 0)
    {
        if (*(char*)(tex + 0x48) == '\0')
        {
            FUN_8025b054((u32*)(tex + 0x20), arg);
        }
        else
        {
            FUN_8025aeac((u32*)(tex + 0x20), *(u32**)(tex + 0x40), arg);
        }
    }
    return;
}

void FUN_80049910(u32* obj)
{
    float scaleZ;
    float* viewMtx;
    u32 objHeader;
    float noiseScrollY;
    float noiseScrollX;
    int noiseTex;
    int blankShadowTex;
    float local_ec;
    u32 local_e8;
    u32 local_e4;
    u32 local_e0;
    u32 local_dc;
    u32 local_d8;
    float afStack_d4[12];
    float local_a4;
    float local_a0;
    float local_9c;
    float local_98;
    float local_94;
    float local_90;
    float local_8c;
    float local_88;
    float local_84;
    float local_80;
    float local_7c;
    float local_78;
    float local_74;
    float local_70;
    float local_6c;
    float local_68;
    float local_64;
    float local_60;
    float local_5c;
    float local_58;
    float local_54;
    float local_50;
    float local_4c;
    float local_48;
    float local_44;
    float local_40;
    float local_3c;
    float local_38;
    float local_34;
    float local_30;
    float local_2c;
    float local_28;
    float local_24;
    float local_20;
    float local_1c;
    float local_18;

    local_ec = DAT_802c24e8;
    local_e8 = DAT_802c24ec;
    local_e4 = DAT_802c24f0;
    local_e0 = DAT_802c24f4;
    local_dc = DAT_802c24f8;
    local_d8 = DAT_802c24fc;
    viewMtx = (float*)FUN_8000697c();
    local_44 = lbl_803DF74C;
    local_40 = lbl_803DF74C;
    local_3c = lbl_803DF744 / lbl_803DD9BC;
    local_38 = lbl_803DD9B8;
    scaleZ = lbl_803DF744 / (lbl_803DD9C4 - lbl_803DD9C0);
    local_34 = scaleZ * viewMtx[4];
    local_30 = scaleZ * viewMtx[5];
    local_2c = scaleZ * viewMtx[6];
    local_28 = scaleZ * viewMtx[7] + -lbl_803DD9C4 * scaleZ;
    local_24 = lbl_803DF74C;
    local_20 = lbl_803DF74C;
    local_1c = lbl_803DF74C;
    local_18 = lbl_803DF748;
    FUN_8025d8c4(&local_44, DAT_803dda00, 0);
    FUN_80258674(DAT_803dda08, 0, 0, 0, 0, DAT_803dda00);
    objHeader = *obj;
    FUN_8025c510(DAT_803dd9f4, (u8*)&objHeader);
    newshadows_getBlankShadowTexture(&blankShadowTex);
    if (blankShadowTex != 0)
    {
        if (*(char*)(blankShadowTex + 0x48) == '\0')
        {
            FUN_8025b054((u32*)(blankShadowTex + 0x20), DAT_803dda0c);
        }
        else
        {
            FUN_8025aeac((u32*)(blankShadowTex + 0x20), *(u32**)(blankShadowTex + 0x40), DAT_803dda0c);
        }
    }
    if (DAT_803dd9b1 == '\0')
    {
        FUN_8025c828(DAT_803dda10, DAT_803dda08, DAT_803dda0c, 0xff);
        FUN_8025c1a4(DAT_803dda10, 0, 0xe, 9, 0xf);
        FUN_8025c224(DAT_803dda10, 7, 7, 7, 0);
        FUN_8025c65c(DAT_803dda10, 0, 0);
        FUN_8025be80(DAT_803dda10);
        FUN_8025c2a8(DAT_803dda10, 0, 0, 0, 1, 0);
        FUN_8025c368(DAT_803dda10, 0, 0, 0, 1, 0);
        DAT_803dd9b0 = 1;
        GXSetBlendMode(DAT_803dda10, DAT_803dd9f0);
        DAT_803dda08 = DAT_803dda08 + 1;
        DAT_803dda10 = DAT_803dda10 + 1;
        DAT_803dda0c = DAT_803dda0c + 1;
        DAT_803dda00 = DAT_803dda00 + 3;
        DAT_803dd9ea = DAT_803dd9ea + '\x01';
        DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    }
    else
    {
        newshadows_getShadowNoiseScroll(&noiseScrollX, &noiseScrollY);
        noiseScrollY = noiseScrollY * lbl_803DF760;
        noiseScrollX = noiseScrollX * lbl_803DF788;
        FUN_8025b9e8(2, &local_ec, -2);
        FUN_8025bd1c(DAT_803dd9fc, DAT_803dda08 + 1, DAT_803dda0c + 1);
        local_74 = lbl_803DD9B4;
        local_70 = lbl_803DF74C;
        local_6c = lbl_803DF74C;
        local_68 = lbl_803DDA58 * lbl_803DD9B4 + noiseScrollX;
        local_64 = lbl_803DF74C;
        local_60 = lbl_803DD9B4;
        local_5c = lbl_803DF74C;
        local_58 = lbl_803DF74C;
        local_54 = lbl_803DF74C;
        local_50 = lbl_803DF74C;
        local_4c = lbl_803DF74C;
        local_48 = lbl_803DF748;
        PSVECDotProduct((double)lbl_803DF7A8, afStack_d4, 0x7a);
        FUN_80247618(afStack_d4, &local_74, &local_74);
        FUN_80247618(&local_74, viewMtx, &local_74);
        FUN_8025d8c4(&local_74, DAT_803dda00 + 3, 0);
        FUN_80258674(DAT_803dda08 + 1, 0, 0, 0, 0, DAT_803dda00 + 3);
        FUN_8025b94c(DAT_803dda10, DAT_803dd9fc, 0, 2, 2, 6, 6, 0, 0, 0);
        FUN_8025bb48(DAT_803dd9fc, 0, 0);
        FUN_8025bd1c(DAT_803dd9fc + 1, DAT_803dda08 + 2, DAT_803dda0c + 1);
        local_a4 = lbl_803DF74C;
        local_a0 = lbl_803DF74C;
        local_9c = lbl_803DD9B4;
        local_98 = lbl_803DDA5C * lbl_803DD9B4 + noiseScrollY;
        local_94 = lbl_803DF74C;
        local_90 = lbl_803DD9B4;
        local_8c = lbl_803DF74C;
        local_88 = lbl_803DF74C;
        local_84 = lbl_803DF74C;
        local_80 = lbl_803DF74C;
        local_7c = lbl_803DF74C;
        local_78 = lbl_803DF748;
        PSVECDotProduct((double)lbl_803DF7AC, afStack_d4, 0x78);
        FUN_80247618(afStack_d4, &local_a4, &local_a4);
        FUN_80247618(&local_a4, viewMtx, &local_a4);
        FUN_8025d8c4(&local_a4, DAT_803dda00 + 6, 0);
        FUN_80258674(DAT_803dda08 + 2, 0, 0, 0, 0, DAT_803dda00 + 6);
        FUN_8025b94c(DAT_803dda10 + 1, DAT_803dd9fc + 1, 0, 2, 2, 0, 0, 1, 0, 0);
        FUN_8025bb48(DAT_803dd9fc + 1, 0, 0);
        FUN_8025c828(DAT_803dda10, 0xff, 0xff, 0xff);
        FUN_8025c1a4(DAT_803dda10, 0xf, 0xf, 0xf, 0);
        FUN_8025c224(DAT_803dda10, 7, 7, 7, 0);
        FUN_8025c65c(DAT_803dda10, 0, 0);
        FUN_8025c2a8(DAT_803dda10, 0, 0, 0, 1, 0);
        FUN_8025c368(DAT_803dda10, 0, 0, 0, 1, 0);
        DAT_803dd9b0 = 1;
        FUN_8025c828(DAT_803dda10 + 1, DAT_803dda08, DAT_803dda0c, 0xff);
        FUN_8025c1a4(DAT_803dda10 + 1, 0, 0xe, 9, 0xf);
        FUN_8025c224(DAT_803dda10 + 1, 7, 7, 7, 0);
        FUN_8025c65c(DAT_803dda10 + 1, 0, 0);
        FUN_8025c2a8(DAT_803dda10 + 1, 0, 0, 0, 1, 0);
        FUN_8025c368(DAT_803dda10 + 1, 0, 0, 0, 1, 0);
        newshadows_getShadowNoiseTexture(&noiseTex);
        if (noiseTex != 0)
        {
            if (*(char*)(noiseTex + 0x48) == '\0')
            {
                FUN_8025b054((u32*)(noiseTex + 0x20), DAT_803dda0c + 1);
            }
            else
            {
                FUN_8025aeac((u32*)(noiseTex + 0x20), *(u32**)(noiseTex + 0x40), DAT_803dda0c + 1);
            }
        }
        GXSetBlendMode(DAT_803dda10 + 1, DAT_803dd9f0);
        DAT_803dda08 = DAT_803dda08 + 3;
        DAT_803dda10 = DAT_803dda10 + 2;
        DAT_803dda0c = DAT_803dda0c + 2;
        DAT_803dda00 = DAT_803dda00 + 9;
        DAT_803dd9fc = DAT_803dd9fc + 2;
        DAT_803dd9ea = DAT_803dd9ea + '\x02';
        DAT_803dd9e9 = DAT_803dd9e9 + '\x03';
        DAT_803dd9e8 = DAT_803dd9e8 + '\x02';
    }
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    return;
}

void FUN_8004bc68(char mode)
{
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10, 0xff, 0xff, 4);
    FUN_8025c65c(DAT_803dda10, 0, 0);
    if (mode == '\0')
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 0, 10, 6);
    }
    else
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 0, 4, 6);
    }
    FUN_8025c224(DAT_803dda10, 7, 7, 7, 0);
    FUN_8025c2a8(DAT_803dda10, 0, 0, 0, 1, 0);
    FUN_8025c368(DAT_803dda10, 0, 0, 0, 1, 0);
    DAT_803dd9b0 = 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    return;
}

extern u8 lbl_803DCD28;
u8 isHeavyFogEnabled(void) { return lbl_803DCD28; }

void disableHeavyFog(void) { lbl_803DCD28 = 0x0; }

extern f32 lbl_803DCD44;
extern f32 lbl_803DCD40;

void fn_8004C234(f32* p1, f32* p2)
{
    *p1 = lbl_803DCD44;
    *p2 = lbl_803DCD40;
}

extern u32 lbl_803DB5EC;
extern f32 lbl_803DB5F0;
extern f32 lbl_803DEAC8;
#pragma scheduling off
void fn_8004C1E4(u8 b, f32 scale)
{
    ((u8*)&lbl_803DB5EC)[3] = b;
    lbl_803DB5F0 = scale;
    if (scale > lbl_803DEAC8)
    {
        lbl_803DB5F0 = lbl_803DEAC8;
    }
}

#pragma peephole off
void* fn_8004B118(int* p)
{
    void** arr;
    int idx = *(s16*)((char*)p + 0x2c);
    if (idx < *(s16*)((char*)p + 0x2a))
    {
        arr = *(void***)((char*)p + 8);
        (*(s16*)((char*)p + 0x2c))++;
        return arr[idx];
    }
    return NULL;
}

int fn_8004B148(int* p)
{
    int node;
    u32 cur;
    u32 prev;
    int i;
    int count;
    int* entry;

    prev = p[7];
    node = *p + prev * 0x10;
    *(u8*)(node + 0xd) = 0xff;
    while ((cur = *(u8*)(node + 0xc)) != 0xff)
    {
        node = *p + cur * 0x10;
        *(u8*)(node + 0xd) = prev;
        prev = cur;
    }
    if (*(u8*)(node + 0xd) == 0xff)
    {
        entry = NULL;
    }
    else
    {
        entry = (int*)(*p + (u32) * (u8*)(node + 0xd) * 0x10);
    }
    count = 0;
    i = 0;
    while (entry != NULL)
    {
        *(int*)(p[2] + i) = *entry;
        i += 4;
        count++;
        if (count >= 100)
        {
            entry = NULL;
        }
        else if (*(u8*)((int)entry + 0xd) == 0xff)
        {
            entry = NULL;
        }
        else
        {
            entry = (int*)(*p + (u32) * (u8*)((int)entry + 0xd) * 0x10);
        }
    }
    *(s16*)((int)p + 0x2a) = count;
    *(u16*)(p + 0xb) = 0;
    return count;
}

extern f32 vec3f_distanceSquared(f32* a, f32* b);
#pragma ppc_unroll_speculative off
int fn_8004B31C(int* queue, int startNode, int targetPos, int pathId, u8 routeFlags)
{
    int i = 0;
    int o4;
    int o8;
    int* node;
    u32* heap;
    int s;
    u32 pri;
    int parent;
    u16 idx;
    u16* hh;
    u16 v;

    *(s16*)((char*)queue + 0x22) = i;
    *(s16*)((char*)queue + 0x20) = i;
    o4 = i;
    o8 = i;
    for (; i < 0xf8; i += 8)
    {
        *(int*)(queue[1] + o4) = 0;
        *(u8*)(*queue + o8 + 0xe) = 0;
        *(int*)(queue[1] + o4 + 8) = 0;
        *(u8*)(*queue + o8 + 0x1e) = 0;
        *(int*)(queue[1] + o4 + 0x10) = 0;
        *(u8*)(*queue + o8 + 0x2e) = 0;
        *(int*)(queue[1] + o4 + 0x18) = 0;
        *(u8*)(*queue + o8 + 0x3e) = 0;
        *(int*)(queue[1] + o4 + 0x20) = 0;
        *(u8*)(*queue + o8 + 0x4e) = 0;
        *(int*)(queue[1] + o4 + 0x28) = 0;
        *(u8*)(*queue + o8 + 0x5e) = 0;
        *(int*)(queue[1] + o4 + 0x30) = 0;
        *(u8*)(*queue + o8 + 0x6e) = 0;
        *(int*)(queue[1] + o4 + 0x38) = 0;
        *(u8*)(*queue + o8 + 0x7e) = 0;
        o4 += 0x40;
        o8 += 0x80;
    }
    for (; i < 0xfe; i++)
    {
        *(int*)(queue[1] + i * 8) = 0;
        *(u8*)(*queue + i * 16 + 0xe) = 0;
    }
    queue[6] = startNode;
    queue[3] = targetPos;
    queue[4] = pathId;
    *(u8*)((char*)queue + 0x28) = routeFlags & 1;
    queue[9] = 10000;
    s = *(s16*)((char*)queue + 0x20);
    if (s == 0xfe)
    {
        node = NULL;
    }
    else
    {
        node = (int*)(*queue + (*(s16*)((char*)queue + 0x20))++ * 0x10);
        *node = startNode;
        node[2] = 0;
        *(u8*)(node + 3) = 0xff;
        node[1] = (u32)vec3f_distanceSquared((f32*)(*node + 8), (f32*)queue[3]);
    }
    i = node[1] + node[2];
    heap = (u32*)queue[1];
    hh = (u16*)queue[1];
    v = *(s16*)((char*)queue + 0x20) - 1;
    hh[++(*(s16*)((char*)queue + 0x22)) * 4 + 2] = v;
    *(u32*)((int)heap + *(s16*)((char*)queue + 0x22) * 8) = -1 - i;
    i = *(s16*)((char*)queue + 0x22);
    pri = *(u32*)((int)heap + i * 8);
    idx = hh[i * 4 + 2];
    *heap = -1;
    while (parent = i >> 1, *(u32*)(hh + parent * 4) < pri)
    {
        *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
        *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
        i = parent;
    }
    *(u32*)((int)heap + i * 8) = pri;
    hh[i * 4 + 2] = idx;
    return 0;
}
#pragma ppc_unroll_speculative on

void texPreGetMipmap(u32 texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode)
{
    u32 base = lbl_8035F3E8[0x4f];
    if (base != 0)
    {
        if (queryMode == 1 && frameTable != 0)
        {
            int e = base + (texId & 0xffffff) * 2 + *(int*)(frameTable + count * 4) + 4;
            int v = *(int*)(e + 8);
            *outA = *(int*)(e + 4);
            *outB = v;
        }
        else if (queryMode == 2 && frameTable != 0)
        {
            memcpy(frameTable, (void*)(base + (texId & 0xffffff) * 2), (count + 1) * 4);
        }
        else
        {
            int e = base + (texId & 0xffffff) * 2;
            int v = *(int*)(e + 0xc);
            *outA = *(int*)(e + 8);
            if (strncmp(&sDirBlockTag, (char*)e, 3) == 0)
            {
                *outB = 0xffffffff;
            }
            else
            {
                *outB = v;
            }
        }
    }
}

void tex0GetFrame(int texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode)
{
    int idx = -1;
    if (lbl_8035F3E8[0x23] != 0 || lbl_8035F3E8[0x4d] != 0)
    {
        int s = OSDisableInterrupts();
        int flags = lbl_803DCC80;
        u32 f478;
        u32 f520;
        OSRestoreInterrupts(s);
        f478 = lbl_8035F3E8[0x24];
        f520 = lbl_8035F3E8[0x4e];
        if ((texId & 0x80000000) != 0 && (flags & 0x200) == 0)
        {
            idx = 0x4d;
        }
        else if ((texId & 0x40000000) != 0 && (flags & 0x100) == 0)
        {
            idx = 0x23;
        }
        else if (f478 != 0 && (flags & 0x100) == 0)
        {
            idx = 0x23;
        }
        else if (f520 != 0 && (flags & 0x200) == 0)
        {
            idx = 0x4d;
        }
        if (queryMode == 1 && frameTable != 0)
        {
            int base = lbl_8035F3E8[idx];
            int e = base + (texId & 0xffffff) * 2 + *(int*)(frameTable + count * 4) + 4;
            int v = *(int*)(e + 8);
            *outA = *(int*)(e + 4);
            *outB = v;
        }
        else if (queryMode == 2 && frameTable != 0)
        {
            memcpy(frameTable, (void*)(lbl_8035F3E8[idx] + (texId & 0xffffff) * 2), (count + 1) * 4);
        }
        else
        {
            int e = lbl_8035F3E8[idx] + (texId & 0xffffff) * 2 + 4;
            int v = *(int*)(e + 8);
            *outA = *(int*)(e + 4);
            *outB = v;
        }
    }
}

void tex1GetFrame(u32 texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode)
{
    int idx = -1;
    if (lbl_8035F3E8[0x20] != 0 || lbl_8035F3E8[0x4b] != 0)
    {
        int s = OSDisableInterrupts();
        int flags = lbl_803DCC80;
        u32 f46c;
        u32 f518;
        OSRestoreInterrupts(s);
        f46c = lbl_8035F3E8[0x21];
        f518 = lbl_8035F3E8[0x4c];
        if ((texId & 0x80000000) != 0 && (flags & 0x2000) == 0)
        {
            idx = 0x4b;
        }
        else if (((int)texId & 0x40000000) != 0 && (flags & 0x1000) == 0)
        {
            idx = 0x20;
        }
        else if (f46c != 0 && (flags & 0x1000) == 0 && lbl_8035F3E8[0x20] != 0)
        {
            idx = 0x20;
        }
        else if (f518 != 0 && (flags & 0x2000) == 0 && lbl_8035F3E8[0x4b] != 0)
        {
            idx = 0x4b;
        }
        {
            u32 base = lbl_8035F3E8[idx];
            if (base != 0)
            {
                if (queryMode == 1 && frameTable != 0)
                {
                    int e = (texId & 0xffffff) * 2 + *(int*)(frameTable + count * 4);
                    int v;
                    e = base + e + 4;
                    v = *(int*)(e + 4);
                    *outB = *(int*)(e + 8);
                    *outA = v;
                }
                else if (queryMode == 2 && frameTable != 0)
                {
                    memcpy(frameTable, (void*)(base + (texId & 0xffffff) * 2), (count + 1) * 4);
                }
                else
                {
                    int e = base + (texId & 0xffffff) * 2;
                    int v = *(int*)(e + 0xc);
                    *outA = *(int*)(e + 8);
                    if (strncmp(&sDirBlockTag, (char*)e, 3) == 0)
                    {
                        *outB = 0xffffffff;
                    }
                    else
                    {
                        *outB = v;
                    }
                }
            }
            else
            {
                char fileInfo[0x3c];
                int v;
                char* buf;
                DVDOpen(sResourceFileNameTable[idx], fileInfo);
                buf = mmAlloc(0x400, 0x7f7f7fff, 0);
                DVDRead(fileInfo, buf, 0x400, (texId & 0xffffff) * 2);
                DVDClose(fileInfo);
                DCStoreRange(buf, 0x400);
                if (queryMode == 1 && frameTable != 0)
                {
                    int e = *(int*)(frameTable + count * 4) + 4;
                    int v;
                    e = (int)buf + e;
                    v = *(int*)(e + 4);
                    *outB = *(int*)(e + 8);
                    *outA = v;
                }
                else if (queryMode == 2 && frameTable != 0)
                {
                    memcpy(frameTable, buf, (count + 1) * 4);
                }
                else
                {
                    v = *(int*)(buf + 0xc);
                    *outA = *(int*)(buf + 8);
                    if (strncmp(&sDirBlockTag, buf, 3) == 0)
                    {
                        *outB = 0xffffffff;
                    }
                    else
                    {
                        *outB = v;
                    }
                }
                mm_free(buf);
            }
        }
    }
}

extern u32 sMapFileNameIndexRemapTable[];
extern u8 lbl_803DB5D0;
extern u8 lbl_803DCD31;
extern f32 lbl_803DCD34;
extern f32 lbl_803DCD38;
extern f32 lbl_803DCD3C;

int mapGetDirIdx(int idx)
{
    if (idx >= 0x4b) return 5;
    return sMapFileNameIndexRemapTable[idx];
}

void setColor_803db5d0(u8 r, u8 g, u8 b)
{
    (&lbl_803DB5D0)[0] = r;
    (&lbl_803DB5D0)[1] = g;
    (&lbl_803DB5D0)[2] = b;
}

void enableHeavyFog(u8 mode, f32 a, f32 b, f32 c, f32 d, f32 e)
{
    lbl_803DCD28 = 1;
    lbl_803DCD44 = a;
    lbl_803DCD40 = b;
    lbl_803DCD3C = c;
    lbl_803DCD38 = d;
    lbl_803DCD34 = e;
    lbl_803DCD31 = mode;
}

void* Shader_getLayer(char* base, int idx) { return base + idx * 8 + 0x24; }

extern u8 lbl_803DCCB0;
extern void gxPerfFn_8004a77c(int);

void gxTransformFn_8004a83c(void)
{
    lbl_803DCCB0 = 0;
    gxPerfFn_8004a77c(0);
}

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} PiWGPipe;

extern volatile PiWGPipe GXWGFifo : (0xCC008000);
extern void GXSetGPMetric(int perf0, int perf1);
#pragma dont_inline on
void gxPerfFn_8004a77c(int enabled)
{
    if ((u8)enabled != 0)
    {
        GXSetGPMetric(0x23, 0x16);
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x2402c004;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000020;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0x84400;
    }
    else
    {
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x24000000;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000000;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0;
    }
}
#pragma dont_inline reset

extern void* lbl_803DCD10;

void allocSomething32bytes(void)
{
    lbl_803DCD10 = mmAlloc(0x20, 0xff, 0);
}

extern u32 lbl_8035F0A8[];

u32 getDataFileSize(int idx)
{
    if (lbl_8035F3E8[idx] != 0)
    {
        return lbl_8035F0A8[idx];
    }
    *(u8*)0 = 0;
    return 0;
}

extern void VISetBlack(int);

extern u8 lbl_803DB5CC;

void viFn_8004a56c(int val)
{
    int v = val;
    VISetBlack(1);
    VIFlush();
    lbl_803DB5CC = v;
}

void freeAndNull(void** p)
{
    if (*p != NULL)
    {
        mm_free(*p);
        *p = NULL;
    }
}

extern f32 lbl_803DEA70;
extern f32 lbl_803DEA78;
extern f32 lbl_803DEA88;
extern f32 lbl_803DEA8C;
extern f32 lbl_803DEA90;
extern f32 hudMatrix[];
extern void C_MTXOrtho(f32* mtx, f32 t, f32 b, f32 l, f32 r, f32 n, f32 f);

void initViewport(void)
{
    C_MTXOrtho(hudMatrix, lbl_803DEA70, lbl_803DEA88, *(f32*)&lbl_803DEA70, lbl_803DEA8C, lbl_803DEA78, lbl_803DEA90);
}

extern int lbl_803DCD88;
extern int lbl_803DCD8C;
extern int lbl_803DCD90;
extern u8 lbl_803DCD6A;
extern void GXSetTevDirect(GXTevStageID tev_stage);
extern void GXSetTevOrder(GXTevStageID stage, GXTexCoordID coord, GXTexMapID map, GXChannelID color);
extern void GXSetTevSwapMode(GXTevStageID stage, GXTevSwapSel ras_sel, GXTevSwapSel tex_sel);
extern void GXSetTevColorIn(GXTevStageID stage, GXTevColorArg a, GXTevColorArg b, GXTevColorArg c, GXTevColorArg d);
extern void GXSetTevAlphaIn(GXTevStageID stage, GXTevAlphaArg a, GXTevAlphaArg b, GXTevAlphaArg c, GXTevAlphaArg d);
extern void GXSetTevColorOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);
extern void GXSetTevAlphaOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);

void fn_80050F2C(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 255);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 15, 6, 8, 15);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

#pragma dont_inline on
int fn_8004AA24(int* ctx, int* ref)
{
    int* node;
    int target;
    target = ctx[4];
    node = (int*)ref[0];
    switch (((s8*)node)[0x19])
    {
    case 0x24:
        {
            u8 idx = ((u8*)ref)[0xc];
            if ((idx & 0x80) == 0)
            {
                if (((u8*)node)[3] != 0)
                {
                    return target == ((u8*)node)[3];
                }
                else
                {
                    int* p;
                    int* arr;
                    int i;
                    arr = (int*)*(int*)((char*)ctx[0] + (idx << 4));
                    for (i = 0, p = arr; i < 4; i++)
                    {
                        if ((u32)node[5] == *(u32*)((char*)p + 0x1c))
                        {
                            return target == ((u8*)arr)[i + 4];
                        }
                        p++;
                    }
                }
            }
            return 0;
        }
    default:
        return target == (int)node;
    }
}

void fn_8004AAD4(u8* arr, int size, int idx)
{
    u16* h = (u16*)arr;
    int half;
    u8* childptr;
    u32 key = *(u32*)((int)arr + idx * 8);
    u16 val = h[idx * 4 + 2];
    int child;
    u8* cp;
    half = size >> 1;
    while (idx <= half)
    {
        child = idx + idx;
        if (child < size)
        {
            cp = arr + child * 8;
            if (*(u32*)cp < *(u32*)(cp + 8))
            {
                child++;
            }
        }
        childptr = arr + child * 8;
        if (key >= *(u32*)childptr) break;
        *(u32*)(arr + idx * 8) = *(u32*)childptr;
        *(u16*)(arr + idx * 8 + 4) = *(u16*)(childptr + 4);
        idx = child;
    }
    *(u32*)((int)arr + idx * 8) = key;
    h[idx * 4 + 2] = val;
}
#pragma dont_inline reset

int fn_8004B218(void* q_, u32 n_)
{
    int n;
    int* q = q_;
    int idx;
    int done;
    int result;
    int* elem;
    int* heap;
    n = n_;
    done = 0;
    result = 0;
    while (done == 0 && n != 0)
    {
        heap = *(int**)((char*)q + 0x4);
        if (*(s16*)((char*)q + 0x22) == 0)
        {
            idx = -1;
        }
        else
        {
            idx = *(u16*)((char*)heap + 0xc);
            *(int*)((char*)heap + 0x8) = *(int*)((int)heap + *(s16*)((char*)q + 0x22) * 8);
            *(u16*)((char*)heap + 0xc) = *(u16*)((char*)heap + (*(s16*)((char*)q + 0x22))-- * 8 + 4);
            fn_8004AAD4((u8*)heap, *(s16*)((char*)q + 0x22), 1);
        }
        if (idx >= 0)
        {
            elem = (int*)(*(int*)((char*)q + 0) + idx * 16);
            *(int*)((char*)q + 0x1c) = idx;
            if (fn_8004AA24(q, elem) != 0)
            {
                done = 1;
                result = 1;
            }
            else
            {
                *((u8*)elem + 0xe) = 1;
                fn_8004AFA0(q, elem, idx);
            }
        }
        else
        {
            done = 1;
            result = -1;
        }
        n--;
    }
    return result;
}
extern char* lbl_803DCD08;

void fn_8004AFA0(int* q, int* elem, int idx)
{
    u8 mask;
    char* p;
    char* node;
    char* obj;
    int bit;
    int t;
    node = (char*)elem[0];
    if (*(u8*)((char*)q + 0x28) != 0)
    {
        t = *(s8*)(node + 0x1b);
    }
    else
    {
        t = ~*(s8*)(node + 0x1b);
    }
    bit = 0;
    p = node;
    mask = t;
    for (; bit < 4; bit++)
    {
        int nodeId = *(int*)(p + 0x1c);
        if (nodeId > -1 && (mask & (1 << bit)) != 0)
        {
            obj = (char*)(*gRomCurveInterface)->getById(nodeId);
            if (obj != 0)
            {
                switch (*(s8*)(obj + 0x19))
                {
                case 0x24:
                    {
                        s16 ev1;
                        s16 ev2;
                        GameBit_Get(0x4e2);
                        ev1 = *(s16*)(obj + 0x30);
                        if (ev1 == -1 || GameBit_Get(ev1) != 0)
                        {
                            ev2 = *(s16*)(obj + 0x32);
                            if (ev2 == -1 || GameBit_Get(ev2) == 0)
                            {
                                if (!(*(s8*)(obj + 0x1a) == 8 && *(s8*)(node + 0x1a) == 9))
                                {
                                    f32 d = vec3f_distanceSquared((f32*)(node + 8), (f32*)(obj + 8));
                                    fn_8004AB5C(q, elem, idx, (u32)((f32)(u32)elem[2] + d), obj);
                                }
                            }
                        }
                        break;
                    }
                default:
                    lbl_803DCD08 = obj;
                    break;
                }
            }
        }
        p += 4;
    }
}

void fn_8004AB5C(int* q, int* elem, int idx, u32 d, char* obj)
{
    int pos;
    u16* hh;
    u16 v;
    int cnt2;
    int* node;
    u32* heap;
    u32 pri;
    u16 idx16;
    int parent;
    int i;
    int idx2;
    int off;
    int n;
    int* node4;
    int visited;
    int cnt;
    if (fn_8004AA24(q, elem) != 0)
    {
        cnt = *(s16*)((char*)q + 0x20);
        if (cnt != 0xfe)
        {
            node = (int*)(*q + ((*(s16*)((char*)q + 0x20))++) * 0x10);
            *node = (int)obj;
            node[2] = d;
            *(u8*)(node + 3) = (u16)idx;
            node[1] = (u32)vec3f_distanceSquared((f32*)(*node + 8), (f32*)q[3]);
        }
        heap = (u32*)q[1];
        hh = (u16*)q[1];
        v = cnt;
        hh[++(*(s16*)((char*)q + 0x22)) * 4 + 2] = v;
        *(u32*)((int)heap + *(s16*)((char*)q + 0x22) * 8) = 0xfffffffe;
        i = *(s16*)((char*)q + 0x22);
        pri = *(u32*)((int)heap + i * 8);
        idx16 = hh[i * 4 + 2];
        *heap = -1;
        while (parent = i >> 1, *(u32*)(hh + parent * 4) < pri)
        {
            *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
            *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
            i = parent;
        }
        *(u32*)((int)heap + i * 8) = pri;
        hh[i * 4 + 2] = idx16;
    }
    idx2 = 0;
    off = idx2;
    cnt2 = *(s16*)((char*)q + 0x20);
    for (n = cnt2; n > 0; n--)
    {
        char** node2 = (char**)(*q + off);
        if (*node2 == obj)
        {
            visited = *(u8*)((char*)node2 + 0xe);
            goto found;
        }
        off += 0x10;
        idx2++;
    }
    idx2 = -1;
found:
    if (idx2 >= 0 && visited == 0)
    {
        int* node3 = (int*)(*q + idx2 * 0x10);
        if (d < node3[2])
        {
            u32 newpri;
            int s2;
            int j;
            u16 target;
            u32* entry;
            u32 old;
            *(u8*)((char*)node3 + 0xc) = idx;
            node3[2] = d;
            newpri = node3[1] + node3[2];
            s2 = *(s16*)((char*)q + 0x22);
            heap = (u32*)q[1];
            hh = (u16*)heap;
            j = 0;
            target = idx2;
            for (; j <= s2; j++)
            {
                if (target == *(u16*)(heap + j * 2 + 1))
                {
                    pos = j;
                    j = s2 + 1;
                }
            }
            entry = heap + pos * 2;
            old = *entry;
            *entry = newpri;
            if (newpri < old)
            {
                fn_8004AAD4((u8*)heap, s2, pos);
            }
            else if (newpri > old)
            {
                pri = *entry;
                idx16 = ((u16*)entry)[2];
                *heap = -1;
                while (parent = pos >> 1, *(u32*)(hh + parent * 4) < pri)
                {
                    *(u16*)((int)heap + pos * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
                    *(u32*)((int)heap + pos * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
                    pos = parent;
                }
                *(u32*)((int)heap + pos * 8) = pri;
                hh[pos * 4 + 2] = idx16;
            }
        }
    }
    else if (idx2 < 0)
    {
        if (cnt2 == 0xfe)
        {
            node4 = NULL;
        }
        else
        {
            node4 = (int*)(*q + ((*(s16*)((char*)q + 0x20))++) * 0x10);
            *node4 = (int)obj;
            node4[2] = d;
            *(u8*)(node4 + 3) = (u16)idx;
            node4[1] = (u32)vec3f_distanceSquared((f32*)(*node4 + 8), (f32*)q[3]);
        }
        if (node4 != NULL)
        {
            if ((u32)node4[1] > q[9])
            {
                u32 newpri = node4[1] + node4[2];
                heap = (u32*)q[1];
                hh = (u16*)heap;
                v = cnt2;
                hh[++(*(s16*)((char*)q + 0x22)) * 4 + 2] = v;
                *(u32*)((int)heap + *(s16*)((char*)q + 0x22) * 8) = -1 - newpri;
                i = *(s16*)((char*)q + 0x22);
                pri = *(u32*)((int)heap + i * 8);
                idx16 = hh[i * 4 + 2];
                *heap = -1;
                while (parent = i >> 1, *(u32*)(hh + parent * 4) < pri)
                {
                    *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
                    *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
                    i = parent;
                }
                *(u32*)((int)heap + i * 8) = pri;
                hh[i * 4 + 2] = idx16;
            }
            else
            {
                u32 newpri;
                if ((u32)node4[1] < q[9])
                {
                    q[9] = node4[1];
                }
                newpri = node4[1] + node4[2];
                heap = (u32*)q[1];
                hh = (u16*)heap;
                v = cnt2;
                hh[++(*(s16*)((char*)q + 0x22)) * 4 + 2] = v;
                *(u32*)((int)heap + *(s16*)((char*)q + 0x22) * 8) = -1 - newpri;
                i = *(s16*)((char*)q + 0x22);
                pri = *(u32*)((int)heap + i * 8);
                idx16 = hh[i * 4 + 2];
                *heap = -1;
                while (parent = i >> 1, *(u32*)(hh + parent * 4) < pri)
                {
                    *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
                    *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
                    i = parent;
                }
                *(u32*)((int)heap + i * 8) = pri;
                hh[i * 4 + 2] = idx16;
            }
        }
    }
}

extern void GXSetAlphaUpdate(GXBool update_enable);
extern void GXFlush(void);
extern void GXGetFifoPtrs(void* fifo, void** out_g, void** out_p);
extern void Queue_Push(void* q, void* item);
extern void GXEnableBreakPt(void* p);
extern void GXSetDrawSync(u16 v);
extern void GXCopyDisp(void* fb, u8 clear);
extern void* lbl_803DCCD4;
extern void* renderFrameBuffer;
extern void* externalFrameBuffer0;
extern void* externalFrameBuffer1;
extern u8 lbl_803DCCA7;
extern u16 lbl_803DB5CE;
extern char lbl_8035F730[];

int GXFlush_(u8 visible, int unused)
{
    void* fifo_get;
    void* fifo_put;
    void* item[3];
    int s;
    void* next;
    gxSetZMode_(1, 3, 1);
    GXSetAlphaUpdate(GX_TRUE);
    GXFlush();
    GXGetFifoPtrs(lbl_803DCCD4, &fifo_get, &fifo_put);
    item[0] = fifo_put;
    item[1] = 0;
    item[2] = renderFrameBuffer;
    s = OSDisableInterrupts();
    Queue_Push(&lbl_8035F730[0], item);
    if (lbl_803DCCA7 == 0)
    {
        GXEnableBreakPt(fifo_put);
        lbl_803DCCA7 = 1;
    }
    OSRestoreInterrupts(s);
    GXSetDrawSync(lbl_803DB5CE);
    GXCopyDisp(renderFrameBuffer, 1);
    GXFlush();
    lbl_803DB5CE = (u16)(lbl_803DB5CE + 1);
    next = renderFrameBuffer == externalFrameBuffer0 ? externalFrameBuffer1 : externalFrameBuffer0;
    renderFrameBuffer = next;
    if (visible != 0 && lbl_803DB5CC != 0)
    {
        lbl_803DB5CC--;
        if (lbl_803DB5CC == 0)
        {
            VISetBlack(0);
            lbl_803DB5CC = 0;
        }
    }
    return 0;
}
#pragma optimize_for_size reset

extern u8 GXNtsc480Prog[];
extern u8 lbl_803DB5D4;
extern GXRenderModeObj* gRenderModeObj;
extern void GXSetCopyFilter(u8 aa, u8* pat, u8 vf_en, u8* vfilter);
#pragma peephole on
void setDisplayCopyFilter(void)
{
    u8* p = (u8*)gRenderModeObj;
    if (p == GXNtsc480Prog || p[0x18] != 0)
    {
        GXSetCopyFilter(p[0x19], p + 0x1a, 0, p + 0x32);
    }
    else
    {
        GXSetCopyFilter(p[0x19], p + 0x1a, 1, &lbl_803DB5D4);
    }
}

extern void GXLoadTexObj(void* obj, int id);
extern void GXLoadTexObjPreLoaded(void* obj, void* region, int id);
extern void fn_80053C40(u8* tex, void* out);
extern u8 lbl_803779A0[];
#pragma peephole off
void textureFn_8004c264(u8* tex, int mapId)
{
    void* base;
    if (tex == NULL) return;
    base = &tex[32];
    if (tex[72] != 0)
    {
        GXLoadTexObjPreLoaded(base, *(void**)(tex + 64), mapId);
    }
    else
    {
        GXLoadTexObj(base, mapId);
    }
    if (*(void**)(tex + 80) != NULL)
    {
        fn_80053C40(tex, lbl_803779A0);
        GXLoadTexObj(lbl_803779A0, 1);
    }
}

void selectTexture(u8* tex, int mapId)
{
    void* base;
    if (tex == NULL) return;
    base = &tex[0x20];
    if (tex[0x48] != 0)
    {
        GXLoadTexObjPreLoaded(base, *(void**)(tex + 0x40), mapId);
    }
    else
    {
        GXLoadTexObj(base, mapId);
    }
}

void loadModelsBin(int a, int* p1c, int* p20, int* p18, int* p4)
{
    u32 v31 = 0;
    u32 v30 = 0;
    int idx = -1;
    int flags;
    int saved;
    char* p;
    if (lbl_8035F3E8[0x2b] != 0 || lbl_8035F3E8[0x46] != 0)
    {
        saved = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(saved);
        if ((flags & 4) == 0 && (flags & 1) == 0)
        {
            v31 = lbl_8035F3E8[0x2a];
        }
        if ((flags & 8) == 0 && (flags & 2) == 0)
        {
            v30 = lbl_8035F3E8[0x45];
        }
        if (v30 != 0 && (a & 0x20000000) != 0)
        {
            idx = 0x46;
        }
        else if (v31 != 0 && (a & 0x10000000) != 0)
        {
            idx = 0x2b;
        }
        else if (v31 != 0)
        {
            idx = 0x2b;
        }
        else if (v30 != 0)
        {
            idx = 0x46;
        }
        p = (char*)lbl_8035F3E8[idx] + (a & 0x0fffffff);
        *p18 = *(int*)(p + 0x18);
        *p1c = *(int*)(p + 0x1c);
        *p20 = *(int*)(p + 0x20);
        *p4 = *(int*)(p + 0x4);
    }
}

void checkLoadBlock(int a, int* pc, int* p8)
{
    int idx = -1;
    int flags;
    int saved;
    char* blk;
    u32 t25, t47;
    if ((lbl_8035F3E8[0x26] != 0 && lbl_8035F3E8[0x25] != 0) ||
        (lbl_8035F3E8[0x48] != 0 && lbl_8035F3E8[0x47] != 0))
    {
        saved = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(saved);
        t25 = lbl_8035F3E8[0x25];
        t47 = lbl_8035F3E8[0x47];
        if (t25 != 0 && (a & 0x10000000) != 0 && (flags & 0x10000) == 0)
        {
            idx = 0x25;
        }
        else if (t47 != 0 && (a & 0x20000000) != 0 && (flags & 0x40000) == 0)
        {
            idx = 0x47;
        }
        else if (t25 != 0 && (flags & 0x10000) == 0)
        {
            idx = 0x25;
        }
        else if (t47 != 0 && (flags & 0x40000) == 0)
        {
            idx = 0x47;
        }
        blk = (char*)lbl_8035F3E8[idx] + (a & 0x00ffffff);
        if (strncmp(blk, &sZlbBlockTag, 3) != 0)
        {
            *p8 = 0;
            *pc = 0;
        }
        else
        {
            {
                int vc = *(int*)(blk + 0xc);
                *p8 = *(int*)(blk + 0x8);
                *pc = vc;
            }
        }
    }
    else
    {
        *p8 = 0;
        *pc = 0;
    }
}

void loadVoxMaps(int a, int* pc, int* p8)
{
    int idx = -1;
    int flags;
    int saved;
    char* blk;
    u32 t1b, t54;
    if ((lbl_8035F3E8[0x1a] != 0 && lbl_8035F3E8[0x1b] != 0) ||
        (lbl_8035F3E8[0x53] != 0 && lbl_8035F3E8[0x54] != 0))
    {
        saved = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(saved);
        t1b = lbl_8035F3E8[0x1b];
        t54 = lbl_8035F3E8[0x54];
        if (t1b != 0 && (a & 0x80000000) != 0 && (flags & 0x1000000) == 0)
        {
            idx = 0x1b;
        }
        else if (t54 != 0 && (a & 0x20000000) != 0 && (flags & 0x4000000) == 0)
        {
            idx = 0x54;
        }
        else if (t1b != 0 && (flags & 0x1000000) == 0)
        {
            idx = 0x1b;
        }
        else if (t54 != 0 && (flags & 0x4000000) == 0)
        {
            idx = 0x54;
        }
        if ((a & 0xf0000000) != 0)
        {
            blk = (char*)lbl_8035F3E8[idx] + (a & 0x00ffffff);
            if (strncmp(blk, &sZlbBlockTag, 3) != 0)
            {
                *p8 = 0;
                *pc = 0;
            }
            else
            {
                {
                    int vc = *(int*)(blk + 0xc);
                    *p8 = *(int*)(blk + 0x8);
                    *pc = vc;
                }
            }
        }
        else
        {
            *p8 = 0;
            *pc = 0;
        }
    }
    else
    {
        *p8 = 0;
        *pc = 0;
    }
}

void fn_80050FF4(u8 mode)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mode != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 1, 4, 6);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 1, 0xa, 6);
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern u8 lbl_803DCD30;

void gxTextureFn_80050e28(u8 mode)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mode != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 6);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xa, 6);
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern void GXSetTevIndRepeat(int stage);
extern void PSMTXScale(f32 m[3][4], f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32 m[3][4], f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 dst[3][4], f32 a[3][4], f32 b[3][4]);
extern void GXLoadTexMtxImm(const f32 mtx[][4], u32 id, GXTexMtxType type);
extern void GXSetTexCoordGen2(GXTexCoordID dst_coord, GXTexGenType func, GXTexGenSrc src_param, u32 mtx, GXBool normalize, u32 pt_texmtx);
extern void GXSetTevSwapModeTable(GXTevSwapSel table, GXTevColorChan red, GXTevColorChan green, GXTevColorChan blue, GXTevColorChan alpha);
extern u8 lbl_803DCD68;
extern int lbl_803DCD80;
extern u8 lbl_803DCD69;
extern f32 lbl_803DEACC;
extern f32 Breaking_803DEB40;
extern f32 lbl_803DEADC;

void fn_800510F0(void* p1, u8 flag2, u8 flag3)
{
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    int texmap;
    if (lbl_803DCD68 == 0)
    {
        GXSetTevDirect(lbl_803DCD90);
    }
    if (flag2 != 0)
    {
        GXSetTevIndRepeat(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88 - 1, lbl_803DCD8C, 0xff);
    }
    else
    {
        PSMTXScale(mtxA, Breaking_803DEB40, *(f32*)&Breaking_803DEB40, lbl_803DEACC);
        PSMTXTrans(mtxB, lbl_803DEADC, *(f32*)&lbl_803DEADC, lbl_803DEAC8);
        PSMTXConcat(mtxB, mtxA, mtxA);
        GXLoadTexMtxImm(mtxA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, 1, 0x1e, 0, lbl_803DCD80);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
        lbl_803DCD80 = lbl_803DCD80 + 3;
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD69 += 1;
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 3, 7);
    if (flag2 != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 4, 0xf);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 0xf);
    }
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    if ((flag3 & 1) != 0)
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_GREEN);
    }
    else
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
    }
    GXSetTevSwapMode(lbl_803DCD90, 0, 3);
    texmap = lbl_803DCD8C;
    if (p1 != 0)
    {
        char* tex = (char*)p1 + 0x20;
        if (*(u8*)((char*)p1 + 0x48) != 0)
        {
            GXLoadTexObjPreLoaded(tex, *(void**)((char*)p1 + 0x40), texmap);
        }
        else
        {
            GXLoadTexObj(tex, texmap);
        }
    }
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 1;
}

extern void GXSetTevKColorSel(GXTevStageID stage, GXTevKColorSel sel);

void textureFn_80051348(void* p1, u8 p2)
{
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    u8 buf[3];
    int out_c;
    int out_8;
    int texmap;
    PSMTXScale(mtxA, Breaking_803DEB40, *(f32*)&Breaking_803DEB40, lbl_803DEACC);
    PSMTXTrans(mtxB, lbl_803DEADC, *(f32*)&lbl_803DEADC, lbl_803DEAC8);
    PSMTXConcat(mtxB, mtxA, mtxA);
    GXLoadTexMtxImm(mtxA, lbl_803DCD80, 0);
    buf[0] = p2;
    buf[1] = p2;
    buf[2] = p2;
    gxTextureFn_8004bf88(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTexCoordGen2(lbl_803DCD88, 1, 1, 0x1e, 0, lbl_803DCD80);
    if (lbl_803DCD68 == 0)
    {
        GXSetTevDirect(lbl_803DCD90);
    }
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0xa);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    texmap = lbl_803DCD8C;
    if (p1 != 0)
    {
        char* tex = (char*)p1 + 0x20;
        if (*(u8*)((char*)p1 + 0x48) != 0)
        {
            GXLoadTexObjPreLoaded(tex, *(void**)((char*)p1 + 0x40), texmap);
        }
        else
        {
            GXLoadTexObj(tex, texmap);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 1;
    lbl_803DCD69 += 1;
}

extern void objGetColor(int slot, u8* red, u8* green, u8* blue);
extern int lbl_803DCD78;

void fn_80051528(void* p1, void* mtx)
{
    u8 buf[3];
    int out_c;
    int out_8;
    objGetColor(0, &buf[0], &buf[1], &buf[2]);
    if (mtx != 0)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    gxTextureFn_8004bf88(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 0xa, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevOrder(lbl_803DCD90 + 1, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
    GXSetTevColorIn(lbl_803DCD90 + 1, 0, 0xa, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapMode(lbl_803DCD90 + 2, 0, 0);
    GXSetTevColorIn(lbl_803DCD90 + 2, 0xf, 0, 8, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, 7, 7, 7, 4);
    GXSetTevColorOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    {
        int id = lbl_803DCD8C;
        if (p1 != 0)
        {
            void* obj = (char*)p1 + 0x20;
            if (*(u8*)((char*)p1 + 0x48) != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)((char*)p1 + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 3;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 3;
    lbl_803DCD69 += 1;
}

typedef struct
{
    f32 v[2][3];
} IndTexMtx23;

extern IndTexMtx23 lbl_802C1E28;
extern u8* lbl_803DCD2C;
extern int lbl_803DB5F4;
extern u8 lbl_803DB5F8;
extern f32 Prepared_803DEAD8;
extern f32 lbl_803DEAE0;
extern int lbl_803DCD7C;
extern void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 b8, u8 b9, u8 b10, u8 b11);
extern u32 randomGetRange(int min, int max);
extern void newshadows_getReflectionScrollOffsets(f32 * x, f32 * y);
extern float mathSinf(float x);
extern void GXSetIndTexMtx(GXIndTexMtxID mtx_id, const f32 offset[2][3], s8 scale_exp);
extern void GXSetIndTexOrder(GXIndTexStageID ind_stage, GXTexCoordID tex_coord, GXTexMapID tex_map);
extern void GXSetTevIndirect(GXTevStageID tev_stage, GXIndTexStageID ind_stage, GXIndTexFormat format, GXIndTexBiasSel bias_sel, GXIndTexMtxID matrix_sel, GXIndTexWrap wrap_s, GXIndTexWrap wrap_t, GXBool add_prev, GXBool utc_lod, GXIndTexAlphaSel alpha_sel);

void textureFn_8004c330(void* p1, void* mtx)
{
    IndTexMtx23 m;
    f32 sx;
    f32 sy;
    int out_c;
    int out_8;
    int y;
    int x;
    int v1;
    u8* dst;
    int v2;
    int v3;
    m = lbl_802C1E28;
    if (lbl_803DCD2C == 0)
    {
        lbl_803DCD2C = textureAlloc(0x20, 0x20, 4, 0, 0, 1, 1, 1, 1);
        for (y = 0; y < 0x20; y++)
        {
            int yhi;
            int ylo;
            x = 0;
            yhi = (y >> 2) * 0x20;
            ylo = (y & 3) * 2;
            for (; x < 0x20; x++)
            {
                dst = lbl_803DCD2C + ylo;
                dst = dst + yhi + (x & 3) * 8 + (x >> 2) * 0x100;
                v1 = randomGetRange(0x80, 0xff);
                v2 = v1 - randomGetRange(0, 0x40);
                v3 = v1 - randomGetRange(0x40, 0x80);
                *(u16*)(dst + 0x60) =
                    ((v1 & 0xf8) >> 3) | ((v2 & 0xf8) << 8 | (v3 & 0xfc) << 3);
            }
        }
        DCFlushRange(lbl_803DCD2C + 0x60, *(u32*)(lbl_803DCD2C + 0x44));
    }
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    m.v[0][1] = lbl_803DEAE0 * mathSinf(Prepared_803DEAD8 * sx) + lbl_803DEADC;
    m.v[1][2] = lbl_803DEAE0 * mathSinf(Prepared_803DEAD8 * sy) + lbl_803DEADC;
    GXSetTevOrder(lbl_803DCD90, 0, lbl_803DCD8C + 1, 8);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != 0)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    GXSetIndTexMtx(1, m.v, (s8)lbl_803DB5F4);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88, lbl_803DCD8C);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 7, 1, 0, 0, 0, 0, 3);
    gxTextureFn_8004bf88(&lbl_803DB5F8, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTevColorIn(lbl_803DCD90, 0xe, 8, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevOrder(lbl_803DCD90 + 1, 0xff, 0xff, 0xff);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevColorIn(lbl_803DCD90 + 1, 2, 0, 1, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    {
        int id = lbl_803DCD8C;
        if (p1 != 0)
        {
            void* obj = (char*)p1 + 0x20;
            if (*(u8*)((char*)p1 + 0x48) != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)((char*)p1 + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    {
        int id2 = lbl_803DCD8C + 1;
        u8* tex = lbl_803DCD2C;
        if (tex != 0)
        {
            void* obj = tex + 0x20;
            if (*(u8*)(tex + 0x48) != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(tex + 0x40), id2);
            }
            else
            {
                GXLoadTexObj(obj, id2);
            }
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 1;
    lbl_803DCD68 += 1;
}

typedef struct
{
    int a;
    int b;
} PiColorS10;

extern int WidthTable_803DEAB0;
extern int CharsInSheet_803DEAB4;
extern int lbl_803DEAB8;
extern int lbl_803DEABC;
extern int lbl_803DEAC0;
extern int lbl_803DCD74;
extern int lbl_803DCD70;
extern int lbl_803DCD6C;
extern void GXSetTevKAlphaSel(GXTevStageID stage, GXTevKAlphaSel sel);
extern void GXSetTevColorS10(int id, void* color);
extern void GXSetTevKColor(int id, void* color);
extern void GXInitTexObj(void* obj, void* img, u16 w, u16 h, int fmt, int wrap_s, int wrap_t, int mipmap);
extern void GXInitTexObjLOD(void* obj, int min_filt, int mag_filt, f32 min_lod, f32 max_lod, f32 lod_bias,
                            int bias_clamp, int do_edge_lod, int max_aniso);

void fn_8004C7AC(void* tex0, void* tex1, void* tex2, int w, int h)
{
    u8 buf5c[0x20];
    u8 buf3c[0x20];
    u8 buf1c[0x20];
    PiColorS10 cs10;
    int ck1;
    int ck2;
    int ck3;
    int h2;
    int w2;
    if (lbl_803DCD6A > 0xb || lbl_803DCD69 > 6 || lbl_803DCD8C > 5 || lbl_803DCD74 > 1)
    {
        return;
    }
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, 4, 0x3c, 0, 0x7d);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 1, 4, 0x3c, 0, 0x7d);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88 + 1, lbl_803DCD8C + 1, 0xff);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 2);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 0, 2);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 6, 1);
        GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 0, 2);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevKAlphaSel(lbl_803DCD90, lbl_803DCD6C);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C + 2, 0xff);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 8, 0xe, 4);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 1, 0, 2);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 4, 6, 2);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 1, 0, 0, 0, 2);
        GXSetTevKColorSel(lbl_803DCD90 + 1, lbl_803DCD70 + 1);
        GXSetTevKAlphaSel(lbl_803DCD90 + 1, lbl_803DCD6C + 1);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88, lbl_803DCD8C, 0xff);
        GXSetTevDirect(lbl_803DCD90 + 2);
        GXSetTevColorIn(lbl_803DCD90 + 2, 0xf, 8, 0xc, 4);
        GXSetTevColorOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 2);
        GXSetTevAlphaIn(lbl_803DCD90 + 2, 4, 7, 7, 2);
        GXSetTevAlphaOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 2);
        GXSetTevSwapMode(lbl_803DCD90 + 2, 0, 0);
        GXSetTevOrder(lbl_803DCD90 + 3, 0xff, 0xff, 0xff);
        GXSetTevDirect(lbl_803DCD90 + 3);
        GXSetTevColorIn(lbl_803DCD90 + 3, 5, 4, 0xe, 0xf);
        GXSetTevColorOp(lbl_803DCD90 + 3, 0, 0, 0, 1, 2);
        GXSetTevAlphaIn(lbl_803DCD90 + 3, 7, 7, 7, 7);
        GXSetTevAlphaOp(lbl_803DCD90 + 3, 0, 0, 0, 1, 2);
        GXSetTevSwapMode(lbl_803DCD90 + 3, 0, 0);
        GXSetTevKColorSel(lbl_803DCD90 + 3, lbl_803DCD70 + 2);
        GXSetTevOrder(lbl_803DCD90 + 4, 0xff, 0xff, 0xff);
        GXSetTevDirect(lbl_803DCD90 + 4);
        GXSetTevColorIn(lbl_803DCD90 + 4, 0, 4, 0xe, 0xf);
        GXSetTevColorOp(lbl_803DCD90 + 4, 0, 0, 0, 1, 0);
        GXSetTevAlphaIn(lbl_803DCD90 + 4, 7, 7, 7, 0);
        GXSetTevAlphaOp(lbl_803DCD90 + 4, 0, 0, 0, 1, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 4, 0, 0);
        GXSetTevKColorSel(lbl_803DCD90 + 4, 6);
        lbl_803DCD30 = 1;
        cs10.a = WidthTable_803DEAB0;
        cs10.b = CharsInSheet_803DEAB4;
        GXSetTevColorS10(1, &cs10);
        ck1 = lbl_803DEAB8;
        GXSetTevKColor(lbl_803DCD74, &ck1);
        ck2 = lbl_803DEABC;
        GXSetTevKColor(lbl_803DCD74 + 1, &ck2);
        ck3 = lbl_803DEAC0;
        GXSetTevKColor(lbl_803DCD74 + 2, &ck3);
        GXInitTexObj(buf5c, tex0, w, h, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD(buf5c, 0, 0, lbl_803DEACC, lbl_803DEACC, lbl_803DEACC, 0, 0, 0);
        GXLoadTexObj(buf5c, lbl_803DCD8C);
        GXInitTexObj(buf3c, tex1, w2 = (s16)w >> 1, h2 = (s16)h >> 1, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD(buf3c, 0, 0, lbl_803DEACC, lbl_803DEACC, lbl_803DEACC, 0, 0, 0);
        GXLoadTexObj(buf3c, lbl_803DCD8C + 1);
        GXInitTexObj(buf1c, tex2, w2, h2, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD(buf1c, 0, 0, lbl_803DEACC, lbl_803DEACC, lbl_803DEACC, 0, 0, 0);
        GXLoadTexObj(buf1c, lbl_803DCD8C + 2);
        lbl_803DCD90 = lbl_803DCD90 + 5;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 3;
        lbl_803DCD74 = lbl_803DCD74 + 3;
        lbl_803DCD70 = lbl_803DCD70 + 3;
        lbl_803DCD6C = lbl_803DCD6C + 3;
        lbl_803DCD6A += 5;
        lbl_803DCD69 += 2;
    }
}

extern IndTexMtx23 lbl_802C1DC8;
extern IndTexMtx23 lbl_802C1DE0;
extern float mathCosf(float x);
extern void fn_80293C64(f32 angle, f32* s, f32* c);
extern void fn_8006C504(void* out);
extern void getTextureFn_8006c5e4(void* out);
extern void mapTextureScrollGetOffset(u8 idx, f32* x, f32* y);
extern void PSMTXIdentity(f32 m[3][4]);
extern void PSMTXRotRad(f32 m[3][4], int axis, f32 rad);
extern void GXSetIndTexCoordScale(GXIndTexStageID ind_state, GXIndTexScale scale_s, GXIndTexScale scale_t);
extern f32 SaveEnd_803DEAD4;
extern f32 lbl_803DEB04;
extern f32 lbl_803DEB08;
extern f32 lbl_803DEB0C;
extern f32 lbl_803DEB10;
extern f32 lbl_803DEB14;
extern f32 lbl_803DEB18;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void fn_8004DA54(char* p1)
{
    f32 mtxf4[3][4];
    f32 mtxc4[3][4];
    f32 mtx94[3][4];
    f32 mtx64[3][4];
    IndTexMtx23 m1;
    IndTexMtx23 m2;
    u8* tex30;
    u8* tex2c;
    f32 rx;
    f32 ry;
    f32 cv;
    f32 sv;
    f32 tsx;
    f32 tsy;
    int kc;
    f32 f31v;
    f32 s;
    f32 k;
    f32 t;
    u8* tex24;
    m1 = lbl_802C1DC8;
    m2 = lbl_802C1DE0;
    tex24 = *(u8**)(p1 + 0x24);
    if (tex24 != 0)
    {
        void* obj = tex24 + 0x20;
        if (*(u8*)(tex24 + 0x48) != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(tex24 + 0x40), 2);
        }
        else
        {
            GXLoadTexObj(obj, 2);
        }
    }
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x7d);
    newshadows_getReflectionScrollOffsets(&rx, &ry);
    fn_80293C64(Prepared_803DEAD8 * rx, &sv, &cv);
    s = mathCosf(Prepared_803DEAD8 * ry);
    k = lbl_803DEB08 * s + lbl_803DEB04;
    k = k * lbl_803DB5F0;
    cv = cv * k;
    sv = sv * k;
    m1.v[0][0] = cv;
    m1.v[0][1] = sv;
    m1.v[1][0] = -sv;
    m1.v[1][1] = cv;
    fn_80293C64(Prepared_803DEAD8 * -ry, &sv, &cv);
    s = mathCosf(Prepared_803DEAD8 * rx);
    f31v = lbl_803DEADC * s + lbl_803DEADC;
    k = lbl_803DEB08 * s + lbl_803DEB04;
    k = k * lbl_803DB5F0;
    cv = cv * k;
    sv = sv * k;
    m2.v[0][0] = cv;
    m2.v[0][1] = sv;
    m2.v[1][0] = -sv;
    m2.v[1][1] = cv;
    fn_8006C504(&tex2c);
    if (tex2c != 0)
    {
        void* obj = tex2c + 0x20;
        if (*(u8*)(tex2c + 0x48) != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(tex2c + 0x40), 0);
        }
        else
        {
            GXLoadTexObj(obj, 0);
        }
    }
    {
        u8 b = *(u8*)(p1 + 0x2a);
        if (b != 0xff)
        {
            mapTextureScrollGetOffset(b, &tsx, &tsy);
            PSMTXTrans(mtx64, tsx, tsy, lbl_803DEACC);
        }
        else
        {
            PSMTXIdentity(mtx64);
        }
    }
    GXLoadTexMtxImm(mtx64, 0x46, 0);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x46);
    getTextureFn_8006c5e4(&tex30);
    if (tex30 != 0)
    {
        void* obj = tex30 + 0x20;
        if (*(u8*)(tex30 + 0x48) != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(tex30 + 0x40), 1);
        }
        else
        {
            GXLoadTexObj(obj, 1);
        }
    }
    PSMTXScale(mtxf4, SaveEnd_803DEAD4, SaveEnd_803DEAD4, lbl_803DEAC8);
    mtxf4[1][3] = lbl_803DEB08 * ry;
    GXLoadTexMtxImm(mtxf4, 0x40, 0);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x40);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, m1.v, -2);
    GXSetIndTexMtx(2, m2.v, -2);
    GXSetTevIndirect(1, 0, 0, 7, 1, 6, 6, 0, 0, 0);
    PSMTXScale(mtxc4, lbl_803DEB0C, *(f32*)&lbl_803DEB0C, lbl_803DEAC8);
    PSMTXRotRad(mtx94, 0x7a, lbl_803DEB10);
    PSMTXConcat(mtx94, mtxc4, mtxc4);
    t = lbl_803DEB14 * rx;
    mtxc4[0][3] = t;
    mtxc4[1][3] = t;
    GXLoadTexMtxImm(mtxc4, 0x43, 0);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX3x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x43);
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetTevIndirect(2, 1, 0, 7, 2, 0, 0, 1, 0, 0);
    ((u8*)&lbl_803DB5EC)[0] = lbl_803DEB18 * f31v;
    ((u8*)&lbl_803DB5EC)[1] = 0;
    ((u8*)&lbl_803DB5EC)[2] = 0;
    kc = lbl_803DB5EC;
    GXSetTevKColor(lbl_803DCD74, &kc);
    GXSetTevKAlphaSel(0, lbl_803DCD6C);
    GXSetTevKColorSel(1, lbl_803DCD70);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_RED, GX_CH_GREEN, GX_CH_BLUE, GX_CH_RED);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP2, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP3);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_KONST, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD3, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_CPREV, GX_CC_TEXC, GX_CC_APREV, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD88 = 4;
    lbl_803DCD90 = 3;
    lbl_803DCD8C = 3;
    lbl_803DCD80 = 0x49;
    lbl_803DCD7C = 2;
    lbl_803DCD6A = 3;
    lbl_803DCD69 = 4;
    lbl_803DCD68 = 2;
    lbl_803DCD74 = 1;
    lbl_803DCD70 = 0xd;
    lbl_803DCD6C = 0x1d;
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

typedef struct
{
    f32 x, y, z;
} PiVec3;

struct piIndMtx;
extern struct piIndMtx lbl_802C1D50;
extern void* Camera_GetInverseViewMatrix(void);
extern void PSMTXRotAxisRad(f32 m[3][4], PiVec3* axis, f32 rad);
extern void fn_8006C510(void* out);
extern f32 lbl_803DEB1C;
extern f32 lbl_803DEB20;
extern f32 LastLength_803DEB24;
extern f32 lbl_803DEB28;
extern f32 SaveStart_803DEAD0;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

void fn_8004E0FC(void)
{
    f32 m1e8[3][4];
    f32 m1b8[3][4];
    f32 m188[3][4];
    f32 m158[3][4];
    f32 m128[3][4];
    f32 mf8[3][4];
    f32 mc8[3][4];
    f32 m98[3][4];
    f32 m68[3][4];
    IndTexMtx23 im;
    PiVec3 va;
    PiVec3 vb;
    PiVec3 vc;
    PiVec3 vd;
    u8* tex1c;
    u8* tex18;
    f32 rx;
    f32 ry;
    void* invView;
    va = ((PiVec3*)&lbl_802C1D50)[4];
    vb = ((PiVec3*)&lbl_802C1D50)[5];
    vc = ((PiVec3*)&lbl_802C1D50)[6];
    vd = ((PiVec3*)&lbl_802C1D50)[7];
    im = *(IndTexMtx23*)((PiVec3*)&lbl_802C1D50 + 8);
    invView = Camera_GetInverseViewMatrix();
    PSMTXRotAxisRad(mf8, &va, lbl_803DEAC8);
    PSMTXRotAxisRad(mc8, &vb, lbl_803DEAC8);
    PSMTXRotAxisRad(m98, &vc, lbl_803DEAC8);
    PSMTXRotAxisRad(m68, &vd, lbl_803DEAC8);
    m1e8[0][0] = lbl_803DEB1C;
    m1e8[0][1] = lbl_803DEACC;
    m1e8[0][2] = lbl_803DEACC;
    m1e8[0][3] = SaveStart_803DEAD0 * (*(f32*)&lbl_803DEB20 * playerMapOffsetX);
    m1e8[1][0] = lbl_803DEACC;
    m1e8[1][1] = lbl_803DEB1C;
    m1e8[1][2] = lbl_803DEACC;
    m1e8[1][3] = lbl_803DEACC;
    m1e8[2][0] = lbl_803DEACC;
    m1e8[2][1] = lbl_803DEACC;
    m1e8[2][2] = lbl_803DEB1C;
    m1e8[2][3] = SaveStart_803DEAD0 * (*(f32*)&lbl_803DEB20 * playerMapOffsetZ);
    m1b8[0][0] = LastLength_803DEB24;
    m1b8[0][1] = lbl_803DEACC;
    m1b8[0][2] = lbl_803DEACC;
    m1b8[0][3] = lbl_803DEADC * (lbl_803DEB20 * playerMapOffsetX);
    m1b8[1][0] = lbl_803DEACC;
    m1b8[1][1] = LastLength_803DEB24;
    m1b8[1][2] = lbl_803DEACC;
    m1b8[1][3] = lbl_803DEACC;
    m1b8[2][0] = lbl_803DEACC;
    m1b8[2][1] = lbl_803DEACC;
    m1b8[2][2] = LastLength_803DEB24;
    m1b8[2][3] = lbl_803DEADC * (lbl_803DEB20 * playerMapOffsetZ);
    PSMTXConcat(m1e8, invView, m1e8);
    PSMTXConcat(mf8, m1e8, m1e8);
    m1e8[2][0] = lbl_803DEACC;
    m1e8[2][1] = lbl_803DEACC;
    m1e8[2][2] = lbl_803DEACC;
    m1e8[2][3] = lbl_803DEAC8;
    PSMTXConcat(m1b8, invView, m1b8);
    PSMTXConcat(mc8, m1b8, m1b8);
    m1b8[2][0] = lbl_803DEACC;
    m1b8[2][1] = lbl_803DEACC;
    m1b8[2][2] = lbl_803DEACC;
    m1b8[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m1e8, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXLoadTexMtxImm(m1b8, lbl_803DCD80 + 3, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
    fn_8006C510(&tex1c);
    {
        int id = lbl_803DCD8C;
        if (tex1c != 0)
        {
            void* obj = tex1c + 0x20;
            if (*(u8*)(tex1c + 0x48) != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(tex1c + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    newshadows_getReflectionScrollOffsets(&rx, &ry);
    GXSetIndTexMtx(2, im.v, -1);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 + 2, lbl_803DCD8C + 1);
    m188[0][0] = lbl_803DEB20;
    m188[0][1] = lbl_803DEACC;
    m188[0][2] = lbl_803DEACC;
    m188[0][3] = lbl_803DEB20 * playerMapOffsetX + rx;
    m188[1][0] = lbl_803DEACC;
    m188[1][1] = lbl_803DEB20;
    m188[1][2] = lbl_803DEACC;
    m188[1][3] = lbl_803DEACC;
    m188[2][0] = lbl_803DEACC;
    m188[2][1] = lbl_803DEACC;
    m188[2][2] = lbl_803DEB20;
    m188[2][3] = lbl_803DEB20 * playerMapOffsetZ;
    PSMTXRotRad(m128, 0x79, lbl_803DEB28);
    PSMTXConcat(m128, m188, m188);
    PSMTXConcat(m188, invView, m188);
    PSMTXConcat(m98, m188, m188);
    m188[2][0] = lbl_803DEACC;
    m188[2][1] = lbl_803DEACC;
    m188[2][2] = lbl_803DEACC;
    m188[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m188, lbl_803DCD80 + 6, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 2, 0, 0, 0, 0, lbl_803DCD80 + 6);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 2, 2, 0, 0, 0, 0, 0);
    GXSetIndTexCoordScale(lbl_803DCD7C, 0, 0);
    GXSetIndTexOrder(lbl_803DCD7C + 1, lbl_803DCD88 + 3, lbl_803DCD8C + 1);
    m158[0][0] = lbl_803DEB20;
    m158[0][1] = lbl_803DEACC;
    m158[0][2] = lbl_803DEACC;
    m158[0][3] = lbl_803DEB20 * playerMapOffsetX;
    m158[1][0] = lbl_803DEACC;
    m158[1][1] = lbl_803DEB20;
    m158[1][2] = lbl_803DEACC;
    m158[1][3] = lbl_803DEACC;
    m158[2][0] = lbl_803DEACC;
    m158[2][1] = lbl_803DEACC;
    m158[2][2] = lbl_803DEB20;
    m158[2][3] = lbl_803DEB20 * playerMapOffsetZ + ry;
    PSMTXConcat(m158, invView, m158);
    PSMTXConcat(m68, m158, m158);
    m158[2][0] = lbl_803DEACC;
    m158[2][1] = lbl_803DEACC;
    m158[2][2] = lbl_803DEACC;
    m158[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m158, lbl_803DCD80 + 9, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 3, 0, 0, 0, 0, lbl_803DCD80 + 9);
    GXSetTevIndirect(lbl_803DCD90 + 1, lbl_803DCD7C + 1, 0, 2, 2, 0, 0, 1, 0, 0);
    GXSetIndTexCoordScale(lbl_803DCD7C + 1, 0, 0);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xb, 9, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, 4);
    GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 0xb, 9, 0);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    getTextureFn_8006c5e4(&tex18);
    {
        int id2 = lbl_803DCD8C + 1;
        if (tex18 != 0)
        {
            void* obj = tex18 + 0x20;
            if (*(u8*)(tex18 + 0x48) != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(tex18 + 0x40), id2);
            }
            else
            {
                GXLoadTexObj(obj, id2);
            }
        }
    }
    lbl_803DCD88 = lbl_803DCD88 + 4;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD80 = lbl_803DCD80 + 0xc;
    lbl_803DCD7C = lbl_803DCD7C + 2;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 4;
    lbl_803DCD68 += 2;
}

extern IndTexMtx23 lbl_802C1D68;
extern f32 lbl_803DEAC4;
extern void fn_8006C528(void* out);
extern f32 ResetCoverCallback_803DEB2C;

void renderHeavyFog(int* fogColorPtr)
{
    f32 mcc[3][4];
    f32 m9c[3][4];
    f32 m6c[3][4];
    f32 mrot[3][4];
    IndTexMtx23 im;
    u8* tex20;
    u8* tex1c;
    f32 a;
    f32 b;
    int kc;
    f32(*iv)[4];
    f32 k;
    im = lbl_802C1D68;
    iv = Camera_GetInverseViewMatrix();
    mcc[0][0] = lbl_803DEACC;
    mcc[0][1] = lbl_803DEACC;
    mcc[0][2] = lbl_803DEAC4 / lbl_803DCD3C;
    mcc[0][3] = lbl_803DCD38;
    k = lbl_803DEAC4 / (lbl_803DCD44 - lbl_803DCD40);
    mcc[1][0] = k * iv[1][0];
    mcc[1][1] = k * iv[1][1];
    mcc[1][2] = k * iv[1][2];
    mcc[1][3] = k * iv[1][3] + -lbl_803DCD44 * k;
    mcc[2][0] = lbl_803DEACC;
    mcc[2][1] = lbl_803DEACC;
    mcc[2][2] = lbl_803DEACC;
    mcc[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(mcc, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    kc = *fogColorPtr;
    GXSetTevKColor(lbl_803DCD74, &kc);
    fn_8006C528(&tex20);
    {
        int id = lbl_803DCD8C;
        if (tex20 != 0)
        {
            void* obj = tex20 + 0x20;
            if (*(u8*)(tex20 + 0x48) != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(tex20 + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    if (lbl_803DCD31 != 0)
    {
        newshadows_getReflectionScrollOffsets(&a, &b);
        b = b * lbl_803DEAE0;
        a = a * lbl_803DEB08;
        GXSetIndTexMtx(2, im.v, -2);
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 + 1, lbl_803DCD8C + 1);
        m9c[0][0] = lbl_803DCD34;
        m9c[0][1] = lbl_803DEACC;
        m9c[0][2] = lbl_803DEACC;
        m9c[0][3] = playerMapOffsetX * lbl_803DCD34 + a;
        m9c[1][0] = lbl_803DEACC;
        m9c[1][1] = lbl_803DCD34;
        m9c[1][2] = lbl_803DEACC;
        m9c[1][3] = lbl_803DEACC;
        m9c[2][0] = lbl_803DEACC;
        m9c[2][1] = lbl_803DEACC;
        m9c[2][2] = lbl_803DEACC;
        m9c[2][3] = lbl_803DEAC8;
        PSMTXRotRad(mrot, 0x7a, lbl_803DEB28);
        PSMTXConcat(mrot, m9c, m9c);
        PSMTXConcat(m9c, iv, m9c);
        GXLoadTexMtxImm(m9c, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
        GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 2, 2, 6, 6, 0, 0, 0);
        GXSetIndTexCoordScale(lbl_803DCD7C, 0, 0);
        GXSetIndTexOrder(lbl_803DCD7C + 1, lbl_803DCD88 + 2, lbl_803DCD8C + 1);
        m6c[0][0] = lbl_803DEACC;
        m6c[0][1] = lbl_803DEACC;
        m6c[0][2] = lbl_803DCD34;
        m6c[0][3] = playerMapOffsetZ * lbl_803DCD34 + b;
        m6c[1][0] = lbl_803DEACC;
        m6c[1][1] = lbl_803DCD34;
        m6c[1][2] = lbl_803DEACC;
        m6c[1][3] = lbl_803DEACC;
        m6c[2][0] = lbl_803DEACC;
        m6c[2][1] = lbl_803DEACC;
        m6c[2][2] = lbl_803DEACC;
        m6c[2][3] = lbl_803DEAC8;
        PSMTXRotRad(mrot, 0x78, ResetCoverCallback_803DEB2C);
        PSMTXConcat(mrot, m6c, m6c);
        PSMTXConcat(m6c, iv, m6c);
        GXLoadTexMtxImm(m6c, lbl_803DCD80 + 6, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 2, 0, 0, 0, 0, lbl_803DCD80 + 6);
        GXSetTevIndirect(lbl_803DCD90 + 1, lbl_803DCD7C + 1, 0, 2, 2, 0, 0, 1, 0, 0);
        GXSetIndTexCoordScale(lbl_803DCD7C + 1, 0, 0);
        GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        lbl_803DCD30 = 1;
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0, 0xe, 9, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        getTextureFn_8006c5e4(&tex1c);
        {
            int id2 = lbl_803DCD8C + 1;
            if (tex1c != 0)
            {
                void* obj = tex1c + 0x20;
                if (*(u8*)(tex1c + 0x48) != 0)
                {
                    GXLoadTexObjPreLoaded(obj, *(void**)(tex1c + 0x40), id2);
                }
                else
                {
                    GXLoadTexObj(obj, id2);
                }
            }
        }
        GXSetTevKColorSel(lbl_803DCD90 + 1, lbl_803DCD70);
        lbl_803DCD88 = lbl_803DCD88 + 3;
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 2;
        lbl_803DCD80 = lbl_803DCD80 + 9;
        lbl_803DCD7C = lbl_803DCD7C + 2;
        lbl_803DCD6A += 2;
        lbl_803DCD69 += 3;
        lbl_803DCD68 += 2;
    }
    else
    {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90, 0, 0xe, 9, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        lbl_803DCD30 = 1;
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 3;
        lbl_803DCD6A += 1;
        lbl_803DCD69 += 1;
    }
    lbl_803DCD74 = lbl_803DCD74 + 1;
    lbl_803DCD70 = lbl_803DCD70 + 1;
    lbl_803DCD6C = lbl_803DCD6C + 1;
}

void textureFn_8004ff20(void* p1)
{
    if (p1 != 0)
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, 1, 0x1e, 0, 0x7d);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 0xb, 8);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        lbl_803DCD30 = 1;
        {
            int id = lbl_803DCD8C;
            if (p1 != 0)
            {
                char* tex = (char*)p1 + 0x20;
                if (*(u8*)((char*)p1 + 0x48) != 0)
                {
                    GXLoadTexObjPreLoaded(tex, *(void**)((char*)p1 + 0x40), id);
                }
                else
                {
                    GXLoadTexObj(tex, id);
                }
            }
        }
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD69 += 1;
        lbl_803DCD6A += 1;
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 5);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 0xb, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD6A += 1;
    }
}

void gxTextureFn_8004bf88(void* bufp, u8 flag1, u8 flag2, int* out1, int* out2)
{
    u8* buf = bufp;
    u8 found1 = 0;
    u8 found2 = 0;
    if (flag1 != 0)
    {
        if (buf[0] == buf[1] && buf[0] == buf[2])
        {
            if (buf[0] == 0xff)
            {
                *out1 = 0;
                found1 = 1;
            }
            else if (buf[0] == 0xe0)
            {
                *out1 = 1;
                found1 = 1;
            }
            else if (buf[0] == 0xc0)
            {
                *out1 = 2;
                found1 = 1;
            }
            else if (buf[0] == 0xa0)
            {
                *out1 = 3;
                found1 = 1;
            }
            else if (buf[0] == 0x80)
            {
                *out1 = 4;
                found1 = 1;
            }
            else if (buf[0] == 0x60)
            {
                *out1 = 5;
                found1 = 1;
            }
            else if (buf[0] == 0x40)
            {
                *out1 = 6;
                found1 = 1;
            }
            else if (buf[0] == 0x20)
            {
                *out1 = 7;
                found1 = 1;
            }
        }
        if (found1 == 0)
        {
            *out1 = lbl_803DCD70;
        }
    }
    else
    {
        found1 = 1;
    }
    if (flag2 != 0)
    {
        if (buf[3] == 0xff)
        {
            *out2 = 0;
            found2 = 1;
        }
        else if (buf[3] == 0xe0)
        {
            *out2 = 1;
            found2 = 1;
        }
        else if (buf[3] == 0xc0)
        {
            *out2 = 2;
            found2 = 1;
        }
        else if (buf[3] == 0xa0)
        {
            *out2 = 3;
            found2 = 1;
        }
        else if (buf[3] == 0x80)
        {
            *out2 = 4;
            found2 = 1;
        }
        else if (buf[3] == 0x60)
        {
            *out2 = 5;
            found2 = 1;
        }
        else if (buf[3] == 0x40)
        {
            *out2 = 6;
            found2 = 1;
        }
        else if (buf[3] == 0x20)
        {
            *out2 = 7;
            found2 = 1;
        }
        if (found2 == 0)
        {
            *out2 = lbl_803DCD6C;
        }
    }
    else
    {
        found2 = 1;
    }
    if (found1 == 0 || found2 == 0)
    {
        int color = *(int*)bufp;
        GXSetTevKColor(lbl_803DCD74, &color);
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
    }
}

void gxTextureFn_8004d5b4(void* p1)
{
    u8 buf[3];
    int color;
    u8 b = *(u8*)((char*)p1 + 0x43);
    buf[2] = b;
    buf[1] = b;
    buf[0] = b;
    color = *(int*)buf;
    GXSetTevKColor(lbl_803DCD74, &color);
    GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 0, 2, 0xe, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD74 = lbl_803DCD74 + 1;
    lbl_803DCD70 = lbl_803DCD70 + 1;
    lbl_803DCD6C = lbl_803DCD6C + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

struct piIndMtx
{
    f32 m[2][3];
};

extern u8 lbl_803DB5E8;
extern int lbl_8030CEE0[];
extern f32 lbl_803DEB38;
extern f32 lbl_803DEB3C;
extern void GXSetTevOp(int stage, int mode);

int textureFn_80050ad8(void* p1, int p2, u8 p3, u32 p4)
{
    struct piIndMtx indmtx;
    f32 mtx[3][4];
    f32 v;
    int result;
    int texmap;
    int t;
    indmtx = lbl_802C1D50;
    t = lbl_803DB5E8 & 1;
    result = 0;
    if (t == 0)
    {
        return 0;
    }
    GXSetIndTexMtx(1, indmtx.m, 0);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 + p2, lbl_803DCD8C);
    if (p4 != 0)
    {
        void* texptr;
        u32 div;
        int p2v = (p3 & 0xf) * 4 + 1;
        texptr = textureIdxToPtr(p4);
        div = (u32) * (u16*)((char*)texptr + 0xa) / (u32)(*(u16*)((char*)p1 + 0xa) * p2v);
        if (div != 0)
        {
            GXSetIndTexCoordScale(lbl_803DCD7C, lbl_8030CEE0[div - 1], lbl_8030CEE0[div - 1]);
        }
        else
        {
            result = p2v & 0xff;
        }
    }
    else
    {
        result = 1;
    }
    v = lbl_803DEADC * (lbl_803DEB38 * ((f32)(s32)((p3 & 0xf0) >> 4) / lbl_803DEB3C - lbl_803DEAC8));
    PSMTXScale(mtx, v, v, lbl_803DEACC);
    mtx[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 1, 2, 0x1e, 0, lbl_803DCD80);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, 1, 3, 0x1e, 0, lbl_803DCD80);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 3, 5, 6, 6, 0, 0, 0);
    GXSetTevIndirect(lbl_803DCD90 + 1, lbl_803DCD7C, 0, 3, 9, 6, 6, 1, 0, 0);
    GXSetTevIndirect(lbl_803DCD90 + 2, lbl_803DCD7C, 0, 0, 0, 0, 0, 1, 0, 0);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, (lbl_803DCD8C + 1) | 0x100, 0xff);
    GXSetTevOp(lbl_803DCD90, 4);
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, (lbl_803DCD8C + 1) | 0x100, 0xff);
    GXSetTevOp(lbl_803DCD90 + 1, 4);
    texmap = lbl_803DCD8C;
    if (p1 != 0)
    {
        char* tex = (char*)p1 + 0x20;
        if (*(u8*)((char*)p1 + 0x48) != 0)
        {
            GXLoadTexObjPreLoaded(tex, *(void**)((char*)p1 + 0x40), texmap);
        }
        else
        {
            GXLoadTexObj(tex, texmap);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD7C = lbl_803DCD7C + 1;
    lbl_803DCD88 = lbl_803DCD88 + 2;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 2;
    lbl_803DCD68 += 1;
    lbl_803DCD69 += 2;
    return result;
}


extern struct piIndMtx lbl_802C1E10;
extern f32 lbl_80396820[3][4];
extern void selectReflectionTexture(int id);

void fn_8004D6D8(void)
{
    struct piIndMtx indmtx;
    void* tex;
    int id;
    f32 v;
    indmtx = lbl_802C1E10;
    v = lbl_803DEADC * fn_8006C670();
    indmtx.m[0][0] = v;
    indmtx.m[1][2] = v;
    if (lbl_803DCD88 > 0)
    {
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 - 1, lbl_803DCD8C + 1);
    }
    else
    {
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88, lbl_803DCD8C + 1);
    }
    GXSetIndTexCoordScale(lbl_803DCD7C, 0, 0);
    GXSetIndTexMtx(2, indmtx.m, -3);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 3, 2, 0, 0, 0, 0, 0);
    getTextureFn_8006c5e4(&tex);
    id = lbl_803DCD8C + 1;
    if (tex != NULL)
    {
        void* obj = (char*)tex + 0x20;
        if (*(u8*)((char*)tex + 0x48) != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)((char*)tex + 0x40), id);
        }
        else
        {
            GXLoadTexObj(obj, id);
        }
    }
    GXLoadTexMtxImm(lbl_80396820, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 8);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    selectReflectionTexture(lbl_803DCD8C);
    lbl_803DCD7C = lbl_803DCD7C + 1;
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD6A++;
    lbl_803DCD69++;
    lbl_803DCD68++;
}

extern void fn_8006C540(u8 * *out);

void fn_8004F380(f32 scale, int* colorIn, f32* pos)
{
    f32 matA[3][4];
    f32 matB[3][4];
    u8* src;
    int color;
    int id;
    f32 c8, cc, d1, f;
    if (!(lbl_803DCD74 <= 3) || lbl_803DCD6A >= 0xc || lbl_803DCD69 >= 7) { return; }
    {
        d1 = lbl_803DEADC;
        f = d1 / scale;
        cc = lbl_803DEACC;
        c8 = lbl_803DEAC8;
        matA[0][0] = f;
        matA[0][1] = cc;
        matA[0][2] = cc;
        matA[0][3] = -pos[0] * f + d1;
        matA[1][0] = cc;
        matA[1][1] = cc;
        matA[1][2] = f;
        matA[1][3] = -pos[2] * f + d1;
        matA[2][0] = cc;
        matA[2][1] = cc;
        matA[2][2] = cc;
        matA[2][3] = c8;
        matB[0][0] = cc;
        matB[0][1] = f;
        matB[0][2] = cc;
        matB[0][3] = -pos[1] * f + d1;
        matB[1][0] = cc;
        matB[1][1] = cc;
        matB[1][2] = cc;
        matB[1][3] = d1;
        matB[2][0] = cc;
        matB[2][1] = cc;
        matB[2][2] = cc;
        matB[2][3] = c8;
        fn_8006C540(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        color = *colorIn;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 2, 8, 4);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 2);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        id = lbl_803DCD8C;
        if (src != NULL)
        {
            u8* obj = src + 0x20;
            if (src[0x48] != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(src + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 += 2;
        lbl_803DCD6A += 2;
    }
}

void fn_8004F6D8(f32 scale, int* colorIn, f32* pos)
{
    f32 matA[3][4];
    f32 matB[3][4];
    u8* src;
    int color;
    int id;
    f32 c8, cc, d1, f;
    if (!(lbl_803DCD74 <= 3) || lbl_803DCD6A >= 0xc || lbl_803DCD69 >= 7) { return; }
    {
        d1 = lbl_803DEADC;
        f = d1 / scale;
        cc = lbl_803DEACC;
        c8 = lbl_803DEAC8;
        matA[0][0] = f;
        matA[0][1] = cc;
        matA[0][2] = cc;
        matA[0][3] = -pos[0] * f + d1;
        matA[1][0] = cc;
        matA[1][1] = cc;
        matA[1][2] = f;
        matA[1][3] = -pos[2] * f + d1;
        matA[2][0] = cc;
        matA[2][1] = cc;
        matA[2][2] = cc;
        matA[2][3] = c8;
        matB[0][0] = cc;
        matB[0][1] = f;
        matB[0][2] = cc;
        matB[0][3] = -pos[1] * f + d1;
        matB[1][0] = cc;
        matB[1][1] = cc;
        matB[1][2] = cc;
        matB[1][3] = d1;
        matB[2][0] = cc;
        matB[2][1] = cc;
        matB[2][2] = cc;
        matB[2][3] = c8;
        fn_8006C540(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        color = *colorIn;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 2, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 2);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        id = lbl_803DCD8C;
        if (src != NULL)
        {
            u8* obj = src + 0x20;
            if (src[0x48] != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(src + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 += 2;
        lbl_803DCD6A += 2;
    }
}

extern f32 lbl_803DEAE4;

void fn_8004FA30(f32 scale, int* colorIn, f32* pos)
{
    f32 matA[3][4];
    f32 matB[3][4];
    u8* src;
    int color;
    int id;
    f32 c8, cc, d1, f;
    if (!(lbl_803DCD74 <= 3) || lbl_803DCD6A >= 0x10 || lbl_803DCD69 >= 7) { return; }
    {
        if (scale < lbl_803DEAE4)
        {
            scale = lbl_803DEAE4;
        }
        d1 = lbl_803DEADC;
        f = d1 / scale;
        cc = lbl_803DEACC;
        c8 = lbl_803DEAC8;
        matA[0][0] = f;
        matA[0][1] = cc;
        matA[0][2] = cc;
        matA[0][3] = -pos[0] * f + d1;
        matA[1][0] = cc;
        matA[1][1] = cc;
        matA[1][2] = f;
        matA[1][3] = -pos[2] * f + d1;
        matA[2][0] = cc;
        matA[2][1] = cc;
        matA[2][2] = cc;
        matA[2][3] = c8;
        matB[0][0] = cc;
        matB[0][1] = f;
        matB[0][2] = cc;
        matB[0][3] = -pos[1] * f + d1;
        matB[1][0] = cc;
        matB[1][1] = cc;
        matB[1][2] = cc;
        matB[1][3] = d1;
        matB[2][0] = cc;
        matB[2][1] = cc;
        matB[2][2] = cc;
        matB[2][3] = c8;
        fn_8006C540(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        color = *colorIn;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 2, 8, 0);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        lbl_803DCD30 = 1;
        id = lbl_803DCD8C;
        if (src != NULL)
        {
            u8* obj = src + 0x20;
            if (src[0x48] != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(src + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 += 2;
        lbl_803DCD6A += 2;
    }
}

extern void fn_8006C5B8(void* out);

void fn_8005011C(int objInst)
{
    u8* src;
    f32 mtx[3][4];
    u8* obj2;
    int id;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevDirect(lbl_803DCD90 + 3);
    PSMTXConcat((f32 (*)[4])(objInst + 0x30), Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0x3c, 0, lbl_803DCD80);
    PSMTXConcat((f32 (*)[4])objInst, Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, lbl_803DCD80 + 3, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0x3c, 0, lbl_803DCD80 + 3);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C + 1, 0xff);
    GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88 + 1, lbl_803DCD8C + 1, 0xff);
    GXSetTevOrder(lbl_803DCD90 + 3, lbl_803DCD88 + 1, lbl_803DCD8C + 1, 0xff);
    GXSetTevKColorSel(lbl_803DCD90 + 2, 6);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevColorIn(lbl_803DCD90 + 1, 2, 8, 0xc, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 1, 8, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevColorIn(lbl_803DCD90 + 2, 4, 0xe, 2, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 2, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    GXSetTevColorIn(lbl_803DCD90 + 3, 6, 0xf, 2, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 3, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 3, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 3, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90 + 3, 0, 0, 0, 1, 0);
    fn_8006C5B8(&src);
    id = lbl_803DCD8C;
    if (src != NULL)
    {
        void* obj = src + 0x20;
        if (src[0x48] != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(src + 0x40), id);
        }
        else
        {
            GXLoadTexObj(obj, id);
        }
    }
    id = lbl_803DCD8C + 1;
    obj2 = *(u8**)(objInst + 0x60);
    if (obj2 != NULL)
    {
        void* obj = obj2 + 0x20;
        if (obj2[0x48] != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(obj2 + 0x40), id);
        }
        else
        {
            GXLoadTexObj(obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 6;
    lbl_803DCD88 = lbl_803DCD88 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD69 += 2;
    lbl_803DCD6A += 4;
    lbl_803DCD90 = lbl_803DCD90 + 4;
}

extern u8 lbl_803DCD6B;

void fn_80050558(u8* texSrc, void* texMtx, int stageMode, int compMode, int variant)
{
    int inputSel;
    int texmap;
    GXSetTevDirect(lbl_803DCD90);
    GXLoadTexMtxImm(texMtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    if (variant == 0 || variant == 2)
    {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    }
    else
    {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 5);
    }
    if (*(volatile int*)&lbl_803DCD90 == 0)
    {
        inputSel = 0xc;
    }
    else
    {
        inputSel = 4;
    }
    if (stageMode == 0)
    {
        if (compMode == 2)
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, inputSel, 8, 0xf);
        }
        else if (compMode == 3)
        {
            GXSetTevColorIn(lbl_803DCD90, inputSel, 0xf, 8, 0xf);
        }
        else if (compMode == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 8, inputSel);
        }
        else if (variant == 0 || variant == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 8, inputSel);
        }
        else
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xb, 8, inputSel);
        }
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        if (compMode == 1)
        {
            GXSetTevColorOp(lbl_803DCD90, 1, 0, 0, 1, 2);
            GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 2);
        }
        else
        {
            GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 2);
            GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 2);
        }
    }
    else if (stageMode == 1)
    {
        if (compMode == 2)
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 6, 8, 0xf);
        }
        else if (compMode == 3)
        {
            GXSetTevColorIn(lbl_803DCD90, 6, 0xf, 8, 0xf);
        }
        else if (compMode == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 8, 6);
        }
        else if (variant == 0 || variant == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 8, 6);
        }
        else
        {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xb, 8, 6);
        }
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        if (compMode == 1)
        {
            GXSetTevColorOp(lbl_803DCD90, 1, 0, 0, 1, 3);
            GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 3);
        }
        else
        {
            GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
            GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 3);
        }
    }
    else
    {
        lbl_803DCD6B = 1;
        lbl_803DCD30 = 1;
        GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
        GXSetTevSwapMode(lbl_803DCD90, 1, 1);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xc);
        if (compMode == 3)
        {
            GXSetTevAlphaIn(lbl_803DCD90, 7, 5, 4, 6);
            GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 0);
        }
        else
        {
            GXSetTevAlphaIn(lbl_803DCD90, 7, 5, 4, 7);
            GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        }
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    }
    texmap = lbl_803DCD8C;
    if (texSrc != NULL)
    {
        u8* tex = texSrc + 0x20;
        if (texSrc[0x48] != 0)
        {
            GXLoadTexObjPreLoaded(tex, *(void**)(texSrc + 0x40), texmap);
        }
        else
        {
            GXLoadTexObj(tex, texmap);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

extern void C_MTXLightOrtho(f32 m[3][4], f32 t, f32 b, f32 l, f32 r, f32 sS, f32 sT, f32 tS, f32 tT);
extern int fn_8006C754(void);
extern int fn_8006C74C(void);
extern void* Obj_GetPlayerObject(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern f32 lbl_803DEAF4;
extern f32 lbl_803DEAF8;
extern f32 lbl_803DEAFC;
extern f32 lbl_803DEB00;

#pragma scheduling off
#pragma opt_common_subs off
void fn_8004D230(void)
{
    f32 mtx1[4][4];
    f32 mtx2[3][4];
    u8* obj1;
    u8* player;
    u8* obj2;
    int id;
    f32 dist;
    f32 tmp;
    f32 t;

    obj1 = (u8*)fn_8006C754();
    C_MTXLightOrtho(mtx1, lbl_803DEAF4, lbl_803DEAF8, lbl_803DEAF8, lbl_803DEAF4,
                    lbl_803DEADC, lbl_803DEADC, lbl_803DEADC, lbl_803DEADC);
    GXLoadTexMtxImm(mtx1, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
    GXSetTevSwapMode(lbl_803DCD90, 1, 1);
    if (lbl_803DCD90 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xf);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0);
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 4);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 2);
    lbl_803DCD30 = 1;
    id = lbl_803DCD8C;
    if (obj1 != NULL)
    {
        void* obj = obj1 + 0x20;
        if (obj1[0x48] != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(obj1 + 0x40), id);
        }
        else
        {
            GXLoadTexObj(obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        dist = Camera_DistanceToCurrentViewPosition(*(f32*)(player + 0x18), *(f32*)(player + 0x1c),
                                                    *(f32*)(player + 0x20));
    }
    else
    {
        dist = lbl_803DEAFC;
    }
    tmp = dist - lbl_803DEB00;
    t = -(lbl_803DEAC8 / (dist - tmp));
    mtx2[0][0] = lbl_803DEACC;
    mtx2[0][1] = lbl_803DEACC;
    mtx2[0][2] = t;
    mtx2[0][3] = t * tmp;
    mtx2[1][0] = lbl_803DEACC;
    mtx2[1][1] = lbl_803DEACC;
    mtx2[1][2] = lbl_803DEACC;
    mtx2[1][3] = lbl_803DEACC;
    mtx2[2][0] = lbl_803DEACC;
    mtx2[2][1] = lbl_803DEACC;
    mtx2[2][2] = lbl_803DEACC;
    mtx2[2][3] = lbl_803DEACC;
    GXLoadTexMtxImm(mtx2, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 1, 1);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0);
    GXSetTevKAlphaSel(lbl_803DCD90, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 2, 4, 6);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    obj2 = (u8*)fn_8006C74C();
    id = lbl_803DCD8C;
    if (obj2 != NULL)
    {
        void* obj = obj2 + 0x20;
        if (obj2[0x48] != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(obj2 + 0x40), id);
        }
        else
        {
            GXLoadTexObj(obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6B = 1;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 2;
}

#pragma opt_common_subs reset
#pragma scheduling reset

extern int lbl_803DCD84;
extern f32 bootThisDol_803DEAE8;
extern f32 lbl_803DEAEC;
extern f32 lbl_803DEAF0;

#pragma scheduling off
#pragma opt_common_subs off
void fn_8004CE0C(void* viewMtx)
{
    f32 mtx40[3][4];
    f32 mtx70[3][4];
    f32 sx;
    f32 sy;
    u8* obj7c;
    u8* obj80;

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, 0x3c, GX_FALSE, 0x7d);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    mtx40[0][0] = lbl_803DEAE4;
    mtx40[0][1] = lbl_803DEACC;
    mtx40[0][2] = lbl_803DEACC;
    mtx40[0][3] = lbl_803DEACC;
    mtx40[1][0] = lbl_803DEACC;
    mtx40[1][1] = lbl_803DEACC;
    mtx40[1][2] = lbl_803DEAE4;
    mtx40[1][3] = lbl_803DEACC;
    GXLoadTexMtxImm(mtx40, 0x1e, 1);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_POS, 0x1e, GX_FALSE, 0x7d);
    getTextureFn_8006c5e4(&obj7c);
    if (obj7c != NULL)
    {
        void* obj = obj7c + 0x20;
        if (obj7c[0x48] != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(obj7c + 0x40), 2);
        }
        else
        {
            GXLoadTexObj(obj, 2);
        }
    }
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtx70, lbl_803DEAE0 * sx, lbl_803DEAE0 * sy, lbl_803DEACC);
    mtx70[0][0] = bootThisDol_803DEAE8;
    mtx70[1][1] = bootThisDol_803DEAE8;
    GXLoadTexMtxImm(mtx70, 0x21, 1);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_POS, 0x21, GX_FALSE, 0x7d);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD2, GX_TEXMAP2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_1_2);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    fn_8006C5B8(&obj80);
    if (obj80 != NULL)
    {
        void* obj = obj80 + 0x20;
        if (obj80[0x48] != 0)
        {
            GXLoadTexObjPreLoaded(obj, *(void**)(obj80 + 0x40), 3);
        }
        else
        {
            GXLoadTexObj(obj, 3);
        }
    }
    mtx40[0][0] = lbl_803DEACC;
    mtx40[0][1] = lbl_803DEACC;
    mtx40[0][2] = lbl_803DEAEC;
    mtx40[0][3] = lbl_803DEAF0;
    mtx40[1][0] = lbl_803DEACC;
    mtx40[1][1] = lbl_803DEACC;
    mtx40[1][2] = lbl_803DEACC;
    mtx40[1][3] = lbl_803DEACC;
    PSMTXConcat(mtx40, viewMtx, mtx40);
    GXLoadTexMtxImm(mtx40, 0x24, 1);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_POS, 0x24, GX_FALSE, 0x7d);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD3, GX_TEXMAP3, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD90 = 3;
    lbl_803DCD88 = 4;
    lbl_803DCD8C = 4;
    lbl_803DCD7C = 1;
    lbl_803DCD84 = 0x27;
    lbl_803DCD6A = 3;
    lbl_803DCD69 = 4;
    lbl_803DCD68 = 1;
}

#pragma opt_common_subs reset
#pragma scheduling reset

extern void printHeapStats(int a);
extern void defragMemory(int mode);
extern void debugPrintSetColor(int r, int g, int b, int a);
extern void fn_80137948(char* fmt, ...);
extern char sAssetHaltFormat[];
extern int lbl_8035EF48[];
extern s16 lbl_803DCC78;
extern void loadTableFiles(void);

void loadDataFiles(int arg)
{
    int i;
    if (getButtonsJustPressed(2) & 0x100)
    {
        {
            volatile int vi;
            for (vi = 0x50; vi < 0x57; vi++)
            {
            }
        }
        printHeapStats(1);
    }
    if (getButtonsJustPressed(2) & 0x200)
    {
        defragMemory(0);
    }
    if (lbl_803DCC78 != 0)
    {
        if (lbl_803DCC78 == 1)
        {
            defragMemory(0);
        }
        lbl_803DCC78--;
    }
    i = 0;
    do
    {
        if (lbl_8035EF48[i] != -1)
        {
            debugPrintSetColor(0, 0xff, 0, 0xff);
            fn_80137948(sAssetHaltFormat, sResourceFileNameTable[i]);
            debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
            lbl_803DCC70 = 1;
            if (mapLoadDataFile(lbl_8035EF48[i], i) != 0)
            {
                lbl_8035EF48[i] = -1;
                printHeapStats(1);
            }
            lbl_803DCC70 = 0;
        }
        i++;
    }
    while (i <= 0x57);
    loadTableFiles();
}

extern void VIConfigure(void* mode);
#pragma peephole on
void tvInit(void)
{
    gRenderModeObj->viWidth = 0x294;
    gRenderModeObj->viXOrigin = gRenderModeObj->viXOrigin - 0xa;
    VIConfigure(gRenderModeObj);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
}

void mapsBinGetRomlistSize(int idx, int* out1, int* out2, int* out3, int p5)
{
    char* base = (char*)lbl_8035F3E8;
    char* e;
    if (*(void**)(base + 0x74) == NULL) return;
    if (*(void**)(base + 0x78) == NULL) return;
    e = *(char**)(base + 0x74) + idx;
    *out1 = *(s16*)(e + 0x1c);
    *out2 = *(s16*)(e + 0x1e);
    *out3 = *(int*)(*(char**)(base + 0x74) +
        *(int*)(*(char**)(base + 0x78) + p5 * 4 + 0x18) + 4);
}

void trickyVoxAllocFn_8004b5d4(int* out)
{
    out[0] = (int)mmAlloc(0x1960, 0x10, 0);
    out[1] = out[0] + 0xfe0;
    out[2] = out[1] + 0x7f0;
}

void* fileLoad(int id)
{
    u8 fileInfo[0x3c];
    if (lbl_8035F3E8[id] != 0)
    {
        return (void*)lbl_8035F3E8[id];
    }
    DVDOpen(sResourceFileNameTable[id], fileInfo);
    lbl_8035F0A8[id] = *(s32*)(fileInfo + 0x34);
    lbl_8035F3E8[id] = (u32)mmAlloc(lbl_8035F0A8[id] + 0x20, 0x7d7d7d7d, 0);
    DCInvalidateRange((void*)lbl_8035F3E8[id], lbl_8035F0A8[id]);
    DVDRead(fileInfo, (void*)lbl_8035F3E8[id], lbl_8035F0A8[id], 0);
    DVDClose(fileInfo);
    return (void*)lbl_8035F3E8[id];
}

int fileLoadToBuffer(int id, void* buffer)
{
    u8 fileInfo[0x3c];
    if (lbl_8035F3E8[id] != 0)
    {
        memcpy(buffer, (void*)lbl_8035F3E8[id], lbl_8035F0A8[id]);
        DCStoreRange(buffer, lbl_8035F0A8[id]);
        return lbl_8035F0A8[id];
    }
    DVDOpen(sResourceFileNameTable[id], fileInfo);
    DCInvalidateRange(buffer, *(s32*)(fileInfo + 0x34));
    DVDRead(fileInfo, buffer, *(s32*)(fileInfo + 0x34), 0);
    DVDClose(fileInfo);
    return *(s32*)(fileInfo + 0x34);
}
#pragma peephole off
int fileLoadToBufferOffset(int id, void* buffer, int offset, int size)
{
    u8 fileInfo[0x3c];
    int asize;
    void* tmp;
    if (size == 0) return 0;
    if (lbl_8035F3E8[id] != 0)
    {
        {
            int base = lbl_8035F3E8[id];
            memcpy(buffer, (void*)(base + offset), size);
        }
        DCStoreRange(buffer, size);
        return size;
    }
    DVDOpen(sResourceFileNameTable[id], fileInfo);
    if (((int)buffer & 0x1fu) != 0 || (size & 0x1f) != 0)
    {
        asize = (size + 0x1f) & ~0x1f;
        tmp = mmAlloc(asize, 0x7d7d7d7d, 0);
        DCInvalidateRange(tmp, asize);
        DVDRead(fileInfo, tmp, asize, offset);
        memcpy(buffer, tmp, size);
        mm_free(tmp);
    }
    else
    {
        DCInvalidateRange(buffer, size);
        DVDRead(fileInfo, buffer, size, offset);
    }
    DVDClose(fileInfo);
    DCStoreRange(buffer, size);
    return size;
}
#pragma peephole on
void fn_8004EECC(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevColorIn(lbl_803DCD90, 0, 0xf, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

void fn_8004F080(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevOrder(lbl_803DCD90 + 1, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90 + 1, 4, 0xf, 0xf, 0);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevOrder(lbl_803DCD90 + 2, 0xff, 0xff, 4);
    GXSetTevColorIn(lbl_803DCD90 + 2, 0, 6, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 2, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 3;
    lbl_803DCD6A = lbl_803DCD6A + 3;
}

extern void textureFn_8006c75c(int a);

void fn_8004D928(void)
{
    textureFn_8006c75c(lbl_803DCD8C);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0x24, 0, 0x7d);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevKColorSel(lbl_803DCD90, 6);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD88++;
    lbl_803DCD90++;
    lbl_803DCD8C++;
    lbl_803DCD84 = 0x27;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_8004FDA0(u8* texSrc, void* texMtx)
{
    GXSetTevDirect(lbl_803DCD90);
    GXLoadTexMtxImm(texMtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevKColorSel(lbl_803DCD90, 4);
    GXSetTevColorIn(lbl_803DCD90, 0xe, 9, 0, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 1, 1, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    {
        int id = lbl_803DCD8C;
        if (texSrc != NULL)
        {
            void* obj = texSrc + 0x20;
            if (texSrc[0x48] != 0)
            {
                GXLoadTexObjPreLoaded(obj, *(void**)(texSrc + 0x40), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    lbl_803DCD88++;
    lbl_803DCD90++;
    lbl_803DCD8C++;
    lbl_803DCD80 += 3;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_80050A28(int scale)
{
    f32 m[3][4];
    PSMTXScale(m, scale, scale, lbl_803DEACC);
    m[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 1, 4, 0x3c, 0, lbl_803DCD80);
    lbl_803DCD80 += 3;
    lbl_803DCD88++;
    lbl_803DCD69++;
}

void fn_8004F2B0(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern void GXSetTevColor(int id, void* color);

void fn_8004EF9C(int* param)
{
    int color = param[0];
    GXSetTevColor(2, &color);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern u8 lbl_802CC6A0[];
extern char lbl_8035F680[];
extern void OSStopStopwatch(void* sw);
extern u64 OSCheckStopwatch(void* sw);
extern void OSResetStopwatch(void* sw);
extern void OSStartStopwatch(void* sw);
extern int OSGetCurrentThread(void);
extern int Queue_GetCount(void* q);
extern void OSSleepThread(void* q);

extern void GXInvalidateVtxCache(void);

extern void OSReport(const char* msg, ...);
extern int GXReadDrawSync(void);
extern void VISetNextFrameBuffer(void* fb);
extern void GXReadXfRasMetric(int* a, int* b, int* c, int* d);
extern void GXGetGPStatus(u8 * a, u8 * b, u8 * c, u8 * d, u8 * e);

extern void modelFn_800292e0(void);
extern void GXInitFifoBase(void* fifo, void* base, u32 size);
extern void GXSetCPUFifo(void* fifo);
extern void GXSetGPFifo(void* fifo);
extern int GXInit(void* base, u32 size);
extern void OSWakeupThread(void* q);
extern int Queue_Peek(void* q, void* out);
extern void Queue_Pop(void* q, void* out);
extern void GXDisableBreakPt(void);
extern void GXPeekZ(int x, int y, void* out);
extern f32 lbl_803DCCC0;
extern f32 lbl_803DEA9C;
extern f32 lbl_803DEAA0;
extern f32 lbl_803DEA74;
extern f32 lbl_803DEA7C;
extern f32 lbl_803DCCB4;
extern u8 lbl_803DB411;
extern int lbl_803DCCDC;
extern int lbl_803DCCAC;
extern char lbl_803DCCC4;
extern int lbl_803DCCA0;
extern u16 lbl_803DCCAA;
extern u8 lbl_803DCCA9;
extern int lbl_803DB5C8;
extern int gAttractMovieState;
extern u16 gDepthReadPendingQueue[];
extern u16 gDepthReadResults[];
extern u16 gDepthReadPendingCount;
extern u16 gDepthReadResultCount;
extern u8 lbl_803DCCA8;
extern int stackCreate(int n, int stride);
extern int testAndSet_onlyUseHeap3(int v);
extern void dvdReadCb_80041d30();
extern u8 lbl_803DCC90;
extern int lbl_803DCC88;
extern int lbl_803DCC98;
extern int lbl_803DCC84;
#pragma peephole off
int initLoadFiles(void)
{
    struct MldfTables* t = (struct MldfTables*)lbl_80345E10;
    int i;
    int* rom;
    u32* ptrs;
    s16* owners;
    int* ids;
    char** names;
    int* sizes;
    u8* flags;
    u8* himem;
    if (lbl_803DCC90 == 0)
    {
        lbl_803DCC90 = 1;
        lbl_803DCC88 = 0;
        lbl_803DCC8C = stackCreate(0x5e, 0x40);
        rom = t->romList;
        for (i = 0; i < 0x75; i++)
        {
            *rom = 0;
            if (i >= 0x50 || i == 0x49 || ((i == 0x43) | (i == 5)))
            {
                piRomLoadSection(0, i, 0);
            }
            rom++;
        }
        lbl_803DCC98 = 0;
        himem = (u8*)t + 0x20000;
        ptrs = (u32*)(himem - 27176);
        owners = (s16*)(himem - 26824);
        ids = (int*)(himem - 28360);
        names = sResourceFileNameTable;
        sizes = (int*)(himem - 28008);
        flags = himem - 28448;
        for (i = 0; i <= 0x57; i++)
        {
            switch (i)
            {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 13:
            case 14:
            case 17:
            case 18:
            case 24:
            case 26:
            case 27:
            case 32:
            case 33:
            case 35:
            case 36:
            case 37:
            case 38:
            case 42:
            case 43:
            case 47:
            case 48:
            case 54:
            case 66:
            case 67:
            case 68:
            case 69:
            case 70:
            case 71:
            case 72:
            case 73:
            case 74:
            case 75:
            case 76:
            case 77:
            case 78:
            case 83:
            case 84:
            case 85:
            case 86:
                *ptrs = 0;
                *owners = -1;
                *ids = -1;
                break;
            default:
                if (*ptrs == 0)
                {
                    int fi = AtomicSList_Pop(lbl_803DCC8C);
                    DVDOpen(*names, (void*)fi);
                    *sizes = *(int*)(fi + 0x34);
                    *ptrs = (u32)mmAlloc(*sizes + 0x20, 0x7d7d7d7d, 0);
                    lbl_803DCC88 = lbl_803DCC88 + 1;
                    DVDReadAsyncPrio((void*)fi, (void*)*ptrs, *sizes, 0, dvdReadCb_80041d30, 2);
                }
                *owners = -1;
                *ids = -1;
                break;
            }
            *flags = 0;
            ptrs++;
            owners++;
            ids++;
            names++;
            sizes++;
            flags++;
        }
    }
    if (lbl_803DCC88 == 0)
    {
        if (((*(volatile int*)&lbl_803DCC80 & 0x100) == 0 || (*(volatile int*)&lbl_803DCC80 & 0x400) == 0) &&
            ((*(volatile int*)&lbl_803DCC84 & 0x100) == 0 || (*(volatile int*)&lbl_803DCC84 & 0x400) == 0))
        {
            int saved = testAndSet_onlyUseHeap3(0);
            mapLoadDataFile(5, 0x23);
            mapLoadDataFile(5, 0x24);
            testAndSet_onlyUseHeap3(saved);
        }
        else if ((*(volatile int*)&lbl_803DCC84 & 0x100) != 0 && (*(volatile int*)&lbl_803DCC84 & 0x400) != 0)
        {
            mergeTableFiles(t->mergeModels, 0x2a, 0x45, 0x800);
            mergeTableFiles(t->mergeAnim, 0x2f, 0x49, 3000);
            mergeTableFiles(t->mergeTex0, 0x24, 0x4e, 0x1000);
            mergeTableFiles(t->mergeTex1, 0x21, 0x4c, 0x1000);
            mergeTableFiles(t->mergeBlocks, 0x26, 0x48, 0x800);
            lbl_803DCC84 = 0;
            lbl_803DCC80 = 0;
            return 1;
        }
    }
    return 0;
}
#pragma optimize_for_size reset

extern char sThreadStateAttrSuspendFormat[];

void waitNextFrame(void)
{
    int lvl;
    u32 frames;

    OSStopStopwatch(lbl_8035F680);
    lbl_803DCCC0 = OSCheckStopwatch(lbl_8035F680) /
        (f32)(u32)((*(u32*)0x800000f8 >> 2) / 1000);
    OSResetStopwatch(lbl_8035F680);
    OSStartStopwatch(lbl_8035F680);
    timeDelta = lbl_803DEA9C * lbl_803DEAA0 * lbl_803DCCC0;
    if (gDvdErrorPauseActive != 0)
    {
        timeDelta = lbl_803DEA70;
    }
    if (timeDelta > lbl_803DEA74)
    {
        timeDelta = *(f32*)&lbl_803DEA74;
    }
    if (timeDelta > lbl_803DEA7C)
    {
        oneOverTimeDelta = lbl_803DEA78 / timeDelta;
    }
    else
    {
        oneOverTimeDelta = lbl_803DEA78;
    }
    frames = (int)(timeDelta + lbl_803DCCB4) & 0xff;
    lbl_803DB411 = frames;
    lbl_803DCCB4 = (timeDelta + lbl_803DCCB4) - (f32)(u32)
    lbl_803DB411;
    framesThisStep = frames;
    if (lbl_803DB411 < 1)
    {
        framesThisStep = 1;
    }
    lvl = OSDisableInterrupts();
    lbl_803DCCDC = OSGetCurrentThread();
    if (*(u16*)(lbl_803DCCDC + 0x2c8) != 2)
    {
        OSReport(sThreadStateAttrSuspendFormat, *(u16*)(lbl_803DCCDC + 0x2c8),
                 *(u16*)(lbl_803DCCDC + 0x2ca), *(int*)(lbl_803DCCDC + 0x2cc));
    }
    if ((u32)Queue_GetCount(lbl_8035F730) > 1)
    {
        lbl_803DCCAC = 0;
        OSSleepThread(&lbl_803DCCC4);
    }
    OSRestoreInterrupts(lvl);
    Camera_ApplyFullViewport();
    GXInvalidateVtxCache();
    GXInvalidateTexAll();
}

void logGpuHang(void);
extern void* lbl_803DCCD8;
extern void* lbl_803DCCE4;
extern void* displayFrameBuffer;
#pragma peephole on
void videoSwapFrameBuffers(void)
{
    int sync;
    int tok[3];
    char fifo[140];

    lbl_803DCCA0 = lbl_803DCCA0 + 1;
    sync = GXReadDrawSync();
    if ((u16)sync == (u16)(lbl_803DCCAA + 1))
    {
        lbl_803DCCAA = sync;
        if (displayFrameBuffer == externalFrameBuffer0)
        {
            displayFrameBuffer = externalFrameBuffer1;
        }
        else
        {
            displayFrameBuffer = externalFrameBuffer0;
        }
        VISetNextFrameBuffer(displayFrameBuffer);
        VIFlush();
        lbl_803DCCA9 = 1;
        lbl_803DB5C8 = lbl_803DCCA0;
        lbl_803DCCA0 = 0;
    }
    lbl_803DCCAC = lbl_803DCCAC + 1;
    if (lbl_803DCCB0 != 0 && (u32) * (volatile int*)&lbl_803DCCAC > 18000)
    {
        logGpuHang();
        gxErrorFn_80060b40();
        modelFn_800292e0();
        __GXAbortWaitPECopyDone();
        GXInitFifoBase(fifo, renderFrameBuffer, 0x10000);
        GXSetCPUFifo(fifo);
        GXSetGPFifo(fifo);
        lbl_803DCCD4 = (void*)GXInit(lbl_803DCCD8, (u32)lbl_803DCCE4);
        if (Queue_IsEmpty(lbl_8035F730) == 0)
        {
            Queue_Pop(lbl_8035F730, tok);
        }
        OSWakeupThread(&lbl_803DCCC4);
        if (Queue_IsEmpty(lbl_8035F730) != 0)
        {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
        else
        {
            Queue_Peek(lbl_8035F730, tok);
            GXEnableBreakPt((void*)tok[0]);
        }
        gxPerfFn_8004a77c(1);
    }
}

#pragma scheduling off
#pragma peephole off
void videoFn_800499e8(void)
{
    char peek[12];
    int tok[3];
    u16* src;
    u16* dst;
    int i;

    if (gAttractMovieState == 2 || gAttractMovieState == 3)
    {
        THPPlayerPostDrawDone();
    }
    Queue_Peek(lbl_8035F730, &peek);
    i = 0;
    src = gDepthReadPendingQueue;
    dst = gDepthReadResults;
    for (; i < (int)(u32)gDepthReadPendingCount; i++)
    {
        dst[i * 6] = src[i * 6];
        dst[i * 6 + 1] = src[i * 6 + 1];
        *(int*)(dst + i * 6 + 4) = *(int*)(src + i * 6 + 4);
        GXPeekZ(dst[i * 6], dst[i * 6 + 1], dst + i * 6 + 2);
    }
    gDepthReadResultCount = gDepthReadPendingCount;
    gDepthReadPendingCount = 0;
    if (*(void**)(peek + 8) == displayFrameBuffer)
    {
        lbl_803DCCA8 = 1;
        lbl_803DCCA9 = 0;
    }
    else
    {
        Queue_Pop(lbl_8035F730, tok);
        lbl_803DCCAC = 0;
        OSWakeupThread(&lbl_803DCCC4);
        if (Queue_IsEmpty(lbl_8035F730) != 0)
        {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
        else
        {
            Queue_Peek(lbl_8035F730, tok);
            GXEnableBreakPt((void*)tok[0]);
            lbl_803DCCA7 = 1;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void logGpuHang(void)
{
    char* strs = (char*)lbl_802CC6A0;
    int topClks, topPerf0, topClks2, topPerf1;
    int botClks, botPerf0, botClks2, botPerf1;
    u32 xfStuck;
    u32 cmdStuck;
    u32 rdIdle;
    u32 cmdIdle;
    u8 cmdRdy;
    u8 readIdle;
    u8 fifoErr;

    GXReadXfRasMetric(&topPerf0, &topClks, &topPerf1, &topClks2);
    GXReadXfRasMetric(&botPerf0, &botClks, &botPerf1, &botClks2);
    xfStuck = (botClks - topClks) == 0;
    cmdStuck = (botPerf0 - topPerf0) == 0;
    rdIdle = (botClks2 - topClks2) != 0;
    cmdIdle = (botPerf1 - topPerf1) != 0;
    GXGetGPStatus(&fifoErr, &fifoErr, &cmdRdy, &readIdle, &fifoErr);
    OSReport(strs + 0x4002c, cmdRdy, readIdle, xfStuck, cmdStuck, rdIdle, cmdIdle);
    if (cmdStuck == 0 && rdIdle != 0)
    {
        OSReport(strs + 0x400fc);
    }
    else if (xfStuck == 0 && cmdStuck != 0 && rdIdle != 0)
    {
        OSReport(strs + 0x4011c);
    }
    else if (readIdle == 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0)
    {
        OSReport(strs + 0x40144);
    }
    else if (cmdRdy != 0 && readIdle != 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0 &&
        cmdIdle != 0)
    {
        OSReport(strs + 0x4016c);
    }
    else
    {
        OSReport(strs + 0x4019c);
    }
}

extern void setShouldResetNextFrame(int v);
extern u8 lbl_803DCCA5;
extern u8 lbl_803DCCA6;
extern u8 lbl_803DCCA4;
extern u8 lbl_803DDA28;
extern char lbl_803DB5DC;

void gpuErrorHandler(void)
{
    char* strs = (char*)lbl_802CC6A0;
    int tok[3];
    u32 botClks;
    int botPerf0;
    u32 botClks2;
    int botPerf1;
    u32 topClks;
    int topPerf0;
    u32 topClks2;
    int topPerf1;
    u8 cmdRdy;
    u8 readIdle;
    u8 fifoErr;
    u32 xfStuck;
    u32 cmdStuck;
    u32 rdIdle;
    u32 cmdIdle;

    if (lbl_803DCCA8 != 0 && lbl_803DCCA9 != 0)
    {
        Queue_Pop(lbl_8035F730, tok);
        lbl_803DCCAC = 0;
        OSWakeupThread(&lbl_803DCCC4);
        if (Queue_IsEmpty(lbl_8035F730) != 0)
        {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
        else
        {
            Queue_Peek(lbl_8035F730, tok);
            GXEnableBreakPt((void*)tok[0]);
            lbl_803DCCA7 = 1;
        }
        lbl_803DCCA8 = 0;
        lbl_803DCCA9 = 0;
    }
    lbl_803DCCA5 = 1;
    lbl_803DCCA6 = 1;
    switch (lbl_803DCCA4)
    {
    case 0:
        if (OSGetResetButtonState() != 0)
        {
            lbl_803DCCA4++;
        }
        break;
    case 1:
        if (OSGetResetButtonState() == 0)
        {
            lbl_803DCCA4++;
            setShouldResetNextFrame(1);
        }
        break;
    }
    if (lbl_803DDA28 != 0 && (void*)lbl_803DCCDC != NULL && (u32)lbl_803DCCAC > 600)
    {
        debugPrintfxy(0x32, 100, strs + 0x40000);
        GXReadXfRasMetric(&botPerf0, (int*)&botClks, &botPerf1, (int*)&botClks2);
        GXReadXfRasMetric(&topPerf0, (int*)&topClks, &topPerf1, (int*)&topClks2);
        xfStuck = (topClks - botClks) == 0;
        cmdStuck = (topPerf0 - botPerf0) == 0;
        rdIdle = (topClks2 - botClks2) != 0;
        cmdIdle = (topPerf1 - botPerf1) != 0;
        GXGetGPStatus(&fifoErr, &fifoErr, &cmdRdy, &readIdle, &fifoErr);
        debugPrintfxy(0x32, 0x78, strs + 0x4002c, cmdRdy, readIdle, xfStuck, cmdStuck, rdIdle, cmdIdle);
        if (cmdStuck == 0 && rdIdle != 0)
        {
            debugPrintfxy(0x32, 0x8c, strs + 0x40048);
        }
        else if (xfStuck == 0 && cmdStuck != 0 && rdIdle != 0)
        {
            debugPrintfxy(0x32, 0x8c, strs + 0x40068);
        }
        else if (readIdle == 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0)
        {
            debugPrintfxy(0x32, 0x8c, strs + 0x40090);
        }
        else if (cmdRdy != 0 && readIdle != 0 && xfStuck != 0 && cmdStuck != 0 &&
            rdIdle != 0 && cmdIdle != 0)
        {
            debugPrintfxy(0x32, 0x8c, strs + 0x400b4);
        }
        else
        {
            debugPrintfxy(0x32, 0x8c, strs + 0x400e4);
        }
        debugPrintfxy(0x32, 0xa0, &lbl_803DB5DC, *(int*)(lbl_803DCCDC + 0x198));
    }
}




extern void* OSInitAlloc(void* lo, void* hi, int numHeaps);
extern int OSCreateHeap(void* start, void* end);
extern void OSSetCurrentHeap(int heap);
extern void GXInitFifoLimits(void* fifo, u32 hi, u32 lo);
extern void Queue_Init(void* q, void* buf, int n, int stride);
extern void OSInitThreadQueue(char* q);
extern void VISetPreRetraceCallback(void (*cb)());
extern void VISetPostRetraceCallback(void (*cb)());
extern void GXSetBreakPtCallback(void (*cb)());
extern void GXSetViewport(f32 left, f32 top, f32 wd, f32 ht, f32 nearz, f32 farz);
extern void GXSetFieldMode(int field_mode, int half_aspect_ratio);
extern void GXSetDispCopySrc(int left, int top, int wd, int ht);
extern u32 GXSetDispCopyYScale(f32 vscale);
extern void GXSetDispCopyDst(int wd, int ht);
extern void GXSetPixelFmt(int pix_fmt, int z_fmt);
extern void GXSetDither(int dither);
extern void GXSetDispCopyGamma(int gamma);
extern int VIWaitForRetrace();

extern void GXSetVtxDesc(GXAttr attr, GXAttrType type);
extern void GXSetVtxAttrFmt(int fmt, int attr, int cnt, int type, int frac);
extern void GXSetCopyClear(void* clear_clr, u32 clear_z);


extern void GXEnableTexOffsets(int coord, int line_enable, int point_enable);
extern void GXLoadPosMtxImm(void* mtx, int id);
extern void GXSetCurrentMtx(u32 id);
extern void GXSetMisc(GXMiscToken token, u32 val);
extern char lbl_8035F6B8[];
extern char* lbl_803DCCE0;
extern int lbl_803DCCB8;
extern int lbl_803DCCF4;
extern u8 lbl_803DCD00;
extern int lbl_803DCCFC;
extern u8 lbl_803DCCF8;
extern f32 lbl_803DEA94;
extern f32 lbl_803DEA98;

void videoInit(void)
{
    u8 fifo[0x80];
    f32 mtx[3][4];
    int cc;
    u32 lo;
    u32 hi;
    u32 next;
    int fbSize;
    u32 x;
    lo = (u32)OSGetArenaLo();
    hi = (u32)OSGetArenaHi();
    memcpy((void*)(hi - 0x40000), lbl_802CC6A0, 0x40000);
    DCStoreRange((void*)(hi - 0x40000), 0x40000);
    lbl_803DCCE4 = (void*)0x40000;
    lbl_803DCCD8 = lbl_802CC6A0;
    DCInvalidateRange((char*)lbl_802CC6A0, 0x40000);
    lbl_803DCCD4 = (void*)GXInit(lbl_803DCCD8, (u32)lbl_803DCCE4);
    lbl_803DCCE0 = lbl_803DCCD8;
    GXSetDispCopySrc(0, 0, gRenderModeObj->fbWidth, gRenderModeObj->efbHeight);
    lbl_803DCCB8 = GXSetDispCopyYScale((f32) gRenderModeObj->xfbHeight /  gRenderModeObj->efbHeight);
    fbSize = (u16)((gRenderModeObj->fbWidth + 0xf) & ~0xf) * lbl_803DCCB8 * 2 + 0x1f;
    externalFrameBuffer0 = (void*)((lo + 0x1f) & ~0x1f);
    externalFrameBuffer1 = (void*)(((u32)externalFrameBuffer0 + fbSize) & ~0x1f);
    next = ((u32)externalFrameBuffer1 + fbSize) & ~0x1f;
    OSSetArenaLo((void*)next);
    OSSetArenaLo((void*)(x = (u32)OSInitAlloc((void*)next, (void*)hi, 1)));
    OSSetCurrentHeap(OSCreateHeap((void*)((x + 0x1f) & ~0x1f), (void*)(hi & ~0x1f)));
    VIConfigure(gRenderModeObj);
    GXInitFifoBase(fifo, externalFrameBuffer0, 0x10000);
    GXSetCPUFifo(fifo);
    GXSetGPFifo(fifo);
    GXInitFifoLimits(lbl_803DCCD4, (u32)lbl_803DCCE4 - 0x4000, (u32)((u32)lbl_803DCCE4 * 3) >> 2);
    GXSetCPUFifo(lbl_803DCCD4);
    GXSetGPFifo(lbl_803DCCD4);
    Queue_Init(lbl_8035F730, lbl_8035F6B8, 10, 0xc);
    OSInitThreadQueue(&lbl_803DCCC4);
    VISetPreRetraceCallback(videoSwapFrameBuffers);
    VISetPostRetraceCallback(gpuErrorHandler);
    GXSetBreakPtCallback(videoFn_800499e8);
    GXSetViewport(lbl_803DEA70, lbl_803DEA70,  gRenderModeObj->fbWidth,  gRenderModeObj->xfbHeight,
                  lbl_803DEA70, lbl_803DEA78);
    GXSetFieldMode(gRenderModeObj->field_rendering, (u32)(gRenderModeObj->xfbHeight - gRenderModeObj->viHeight) >> 31);
    GXSetScissor(0, 0, gRenderModeObj->fbWidth, gRenderModeObj->efbHeight);
    GXSetDispCopyDst(gRenderModeObj->fbWidth, (u16)lbl_803DCCB8);
    if (gRenderModeObj->aa != 0)
    {
        GXSetPixelFmt(GX_PF_RGB565_Z16, GX_ZC_LINEAR);
        GXSetDither(GX_TRUE);
    }
    else
    {
        GXSetPixelFmt(GX_PF_RGB8_Z24, GX_ZC_LINEAR);
        GXSetDither(GX_FALSE);
    }
    displayFrameBuffer = externalFrameBuffer0;
    renderFrameBuffer = externalFrameBuffer1;
    VISetNextFrameBuffer(displayFrameBuffer);
    GXSetDispCopyGamma(0);
    VISetBlack(1);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    GXClearVtxDesc();
    GXSetVtxDesc(0, 1);
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xb, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetVtxAttrFmt(0, 9, 1, 3, 0);
    GXSetVtxAttrFmt(0, 0xb, 1, 5, 0);
    GXSetVtxAttrFmt(0, 0xd, 1, 3, 7);
    GXSetVtxAttrFmt(1, 9, 1, 3, 2);
    GXSetVtxAttrFmt(1, 0xb, 1, 5, 0);
    GXSetVtxAttrFmt(1, 0xd, 1, 4, 0);
    GXSetVtxAttrFmt(2, 9, 1, 4, 0);
    GXSetVtxAttrFmt(2, 10, 0, 4, 0);
    GXSetVtxAttrFmt(2, 0xb, 1, 5, 0);
    GXSetVtxAttrFmt(2, 0xd, 1, 4, 0);
    GXSetVtxAttrFmt(2, 0xe, 1, 4, 0);
    GXSetVtxAttrFmt(3, 9, 1, 3, 8);
    GXSetVtxAttrFmt(3, 0x19, 1, 1, 0);
    GXSetVtxAttrFmt(3, 0xb, 1, 3, 0);
    GXSetVtxAttrFmt(3, 0xd, 1, 3, 10);
    GXSetVtxAttrFmt(3, 0xe, 1, 3, 10);
    GXSetVtxAttrFmt(3, 0xf, 1, 3, 10);
    GXSetVtxAttrFmt(3, 0x10, 1, 3, 10);
    GXSetVtxAttrFmt(4, 9, 1, 4, 0);
    GXSetVtxAttrFmt(4, 0xb, 1, 5, 0);
    GXSetVtxAttrFmt(4, 0xd, 1, 3, 7);
    GXSetVtxAttrFmt(4, 10, 0, 4, 0);
    GXSetVtxAttrFmt(5, 9, 1, 3, 3);
    GXSetVtxAttrFmt(5, 10, 0, 1, 0);
    GXSetVtxAttrFmt(5, 0xb, 1, 3, 0);
    GXSetVtxAttrFmt(5, 0xd, 1, 3, 8);
    GXSetVtxAttrFmt(5, 0xe, 1, 3, 8);
    GXSetVtxAttrFmt(5, 0xf, 1, 3, 8);
    GXSetVtxAttrFmt(5, 0x10, 1, 3, 8);
    GXSetVtxAttrFmt(6, 9, 1, 3, 8);
    GXSetVtxAttrFmt(6, 10, 0, 1, 0);
    GXSetVtxAttrFmt(6, 0xb, 1, 3, 0);
    GXSetVtxAttrFmt(6, 0xd, 1, 3, 10);
    GXSetVtxAttrFmt(6, 0xe, 1, 3, 10);
    GXSetVtxAttrFmt(6, 0xf, 1, 3, 10);
    GXSetVtxAttrFmt(6, 0x10, 1, 3, 10);
    GXSetVtxAttrFmt(7, 9, 1, 3, 0);
    GXSetVtxAttrFmt(7, 10, 0, 1, 0);
    GXSetVtxAttrFmt(7, 0xb, 1, 3, 0);
    GXSetVtxAttrFmt(7, 0xd, 1, 3, 10);
    GXSetVtxAttrFmt(7, 0xe, 1, 3, 10);
    GXSetVtxAttrFmt(7, 0xf, 1, 3, 10);
    GXSetVtxAttrFmt(7, 0x10, 1, 3, 10);
    lbl_803DCCF4 = 0;
    GXSetCullMode(GX_CULL_NONE);
    cc = *(int*)&lbl_803DB5D0;
    GXSetCopyClear(&cc, 0xffffff);
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    GXSetNumChans(1);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    lbl_803DCD00 = 1;
    lbl_803DCCFC = 3;
    lbl_803DCCF8 = 1;
    gxSetZMode_(1, 3, 1);
    gxSetPeControl_ZCompLoc_(1);
    GXEnableTexOffsets(0, 1, 1);
    PSMTXIdentity(mtx);
    GXLoadPosMtxImm(mtx, 0);
    GXLoadTexMtxImm(mtx, 0x1e, 0);
    GXLoadTexMtxImm(mtx, 0x21, 0);
    GXSetCurrentMtx(0);
    C_MTXOrtho(hudMatrix, lbl_803DEA94, lbl_803DEA98, lbl_803DEA70, lbl_803DEA8C, lbl_803DEA78, lbl_803DEA90);
    GXSetMisc(GX_MT_XF_FLUSH, 8);
    PPCMtmsr(PPCMfmsr() | MSR_PM);
    PPCMthid0(PPCMfhid0() | HID0_SPD);
}

#pragma optimize_for_size on
extern int __rlwnm(int, int, int, int);
extern u8 lbl_8030C880[];
extern u16 lbl_8030C9A0[];
extern u8 lbl_8030CDA0[];
extern u8 lbl_8030CDC0[];
extern u8 lbl_8030CDE0[];
extern u8 gInflateCodeLengthOrder[];
typedef struct {
    u16 base;
    u16 extra;
} InflateBaseExtra;
extern InflateBaseExtra gInflateLengthCodes[29];
extern InflateBaseExtra gInflateDistCodes[30];
extern u8 lbl_803DCD20[];
extern u8 lbl_803DCD18[];
extern u8 lbl_80377880[];
extern u16 lbl_80377894[];
extern u16 lbl_80377954[];
extern u16 lbl_803778B4[];
extern u16 lbl_80377974[];
extern u8 lbl_803778D4[];
extern u8 lbl_8035F740[];
extern u16 lbl_8035F860[];
extern u8 lbl_8036F860[];
extern u8 lbl_8036F880[];

#define ZROT1(b) ((u32)__rlwnm((b), sh, 31, 31))
#define ZROT8(b) ((u32)__rlwnm((b), sh, 24, 31))
#define ZGB8() (ZROT8(src[0]) | src[1] << (8 - pos))
#define ZGB16() (ZROT8(src[0]) | src[1] << (8 - pos) | src[2] << (0x10 - pos))
#define ZADV(n) (pos += (n), src += pos >> 3, pos &= 7, sh = 0x20 - pos)

/* zlbDecompress is a foreign-compiler (GCC / SN ProDG family) object, not MWCC. */
int zlbDecompress(void* srcv, int size, int dstv, void* outp)
{
    u8* src;
    u8* dst;
    int pos;
    int sh;
    u8* lenBitsP;
    u16* lenTblP;
    int lenMax;
    u8* distBitsP;
    u8* distTblP;
    int distMax;
    int hlit;
    int hdist;
    int hclen;
    u32 final;
    u32 type;
    u32 sym;
    u32 code;
    u32 val;
    int i;
    int j;
    int k;
    int n;
    u8* p8;
    u16* p16;
    u8* curLens;
    u16* curCnt;
    dst = (u8*)dstv - 1;
    pos = 0;
    sh = 0x20;
    src = (u8*)srcv + 2;
    do
    {
        final = ZROT1(src[0]);
        ZADV(1);
        type = ZGB8() & 3;
        ZADV(2);
        if (type == 0)
        {
            u32 len;
            if (pos != 0)
            {
                src += 1;
                pos = 0;
            }
            len = *(u16*)src;
            src += 1;
            len |= (u32) * (u16*)src << 8;
            src += 3;
            do
            {
                u8 v = *src;
                src += 1;
                *++dst = v;
            }
            while (len-- != 0);
        }
        else
        {
            if (type == 1)
            {
                lenBitsP = lbl_8030C880;
                lenTblP = lbl_8030C9A0;
                lenMax = 9;
                distBitsP = lbl_8030CDA0;
                distTblP = lbl_8030CDC0;
                distMax = 5;
            }
            else
            {
                lenBitsP = lbl_8035F740;
                lenTblP = lbl_8035F860;
                distBitsP = lbl_8036F860;
                distTblP = lbl_8036F880;
                val = 0;
                p8 = lbl_803DCD20;
                for (i = 8; i != 0; i--)
                {
                    *p8 = val;
                    p8++;
                }
                p8 = lbl_80377880;
                for (i = 0x13; i != 0; i--)
                {
                    *p8 = val;
                    p8++;
                }
                p16 = lbl_80377894;
                for (i = 0x10; i != 0; i--)
                {
                    *p16 = val;
                    p16++;
                }
                p8 = lenBitsP;
                for (i = 0x120; i != 0; i--)
                {
                    *p8 = val;
                    p8++;
                }
                p16 = lbl_803778B4;
                for (i = 0x10; i != 0; i--)
                {
                    *p16 = val;
                    p16++;
                }
                p8 = distBitsP;
                for (i = 0x20; i != 0; i--)
                {
                    *p8 = val;
                    p8++;
                }
                hlit = (ZGB8() & 0x1f) + 0x101;
                ZADV(5);
                hdist = (ZGB8() & 0x1f) + 1;
                ZADV(5);
                hclen = (ZGB8() & 0xf) + 4;
                ZADV(4);
                for (i = 0; i != hclen; i++)
                {
                    u32 v = ZGB8() & 7;
                    lbl_80377880[gInflateCodeLengthOrder[i]] = v;
                    lbl_803DCD20[v] += 1;
                    ZADV(3);
                }
                lenMax = 7;
                while (lbl_803DCD20[lenMax] == 0)
                {
                    lenMax--;
                }
                code = 0;
                for (j = 1; j <= lenMax; j++)
                {
                    if (lbl_803DCD20[j] != 0)
                    {
                        lbl_803DCD18[j] = code;
                        code += lbl_803DCD20[j] << (lenMax - j);
                    }
                }
                for (i = 0; i < 0x13; i++)
                {
                    u32 len = lbl_80377880[i];
                    if (len != 0)
                    {
                        for (k = 0; k < 1 << (lenMax - len); k++)
                        {
                            u8 c = lbl_803DCD18[len] + 1;
                            lbl_803DCD18[len] = c;
                            (lbl_803778D4 - 1)[c] = i;
                        }
                    }
                }
                curLens = lenBitsP;
                curCnt = lbl_80377894;
                n = 0;
                do
                {
                    u32 extra;
                    u32 v;
                    u32 rep;
                    extra = 0;
                    if (pos > 8 - lenMax)
                    {
                        extra = src[1] << (8 - pos);
                    }
                    v = (ZROT8(src[0]) | extra) & ((1 << lenMax) - 1);
                    sym = lbl_803778D4[__rlwnm(lbl_8030CDE0[v], lenMax + 0x18, 24, 31)];
                    ZADV(lbl_80377880[sym]);
                    if (sym == 0x10)
                    {
                        rep = (ZGB8() & 3) + 3;
                        ZADV(2);
                    }
                    else if (sym == 0x11)
                    {
                        val = 0;
                        rep = (ZGB8() & 7) + 3;
                        ZADV(3);
                    }
                    else if (sym == 0x12)
                    {
                        val = 0;
                        rep = (ZGB8() & 0x7f) + 0xb;
                        ZADV(7);
                    }
                    else
                    {
                        val = sym;
                        rep = 1;
                    }
                    do
                    {
                        curLens[n] = val;
                        n += 1;
                        curCnt[val] += 1;
                        if (curLens == lbl_8035F740 && n == hlit)
                        {
                            curCnt = lbl_803778B4;
                            n = 0;
                            curLens = distBitsP;
                        }
                    }
                    while (rep-- != 1);
                }
                while (curLens == lbl_8035F740 || n < hdist);
                lenMax = 0xf;
                while (lbl_80377894[lenMax] == 0)
                {
                    lenMax--;
                }
                code = 0;
                for (j = 1; j <= lenMax; j++)
                {
                    if (lbl_80377894[j] != 0)
                    {
                        lbl_80377954[j] = code;
                        code += lbl_80377894[j] << (lenMax - j);
                    }
                }
                for (i = 0; i < hlit; i++)
                {
                    u32 len = lenBitsP[i];
                    if (len != 0)
                    {
                        for (k = 0; k < 1 << (lenMax - len); k++)
                        {
                            u16 c = lbl_80377954[len] + 1;
                            lbl_80377954[len] = c;
                            lenTblP[c - 1] = i;
                        }
                    }
                }
                distMax = 0xf;
                while (lbl_803778B4[distMax] == 0)
                {
                    distMax--;
                }
                code = 0;
                for (j = 1; j <= distMax; j++)
                {
                    if (lbl_803778B4[j] != 0)
                    {
                        lbl_80377974[j] = code;
                        code += lbl_803778B4[j] << (distMax - j);
                    }
                }
                for (i = 0; i < hdist; i++)
                {
                    u32 len = distBitsP[i];
                    if (len != 0)
                    {
                        for (k = 0; k < 1 << (distMax - len); k++)
                        {
                            u16 c = lbl_80377974[len] + 1;
                            lbl_80377974[len] = c;
                            distTblP[c - 1] = i;
                        }
                    }
                }
            }
            do
            {
                u32 t;
                u32 code2;
                t = ZGB16() & ((1 << lenMax) - 1);
                code2 = __rlwnm(lbl_8030CDE0[t & 0xff], lenMax - 8, 16, 31) |
                    __rlwnm(lbl_8030CDE0[t >> 8], lenMax + 0x10, 24, 31);
                sym = lenTblP[code2];
                ZADV(lenBitsP[sym]);
                if ((int)sym < 0x100)
                {
                    *++dst = sym;
                }
                else if (sym != 0x100)
                {
                    u32 len2;
                    u32 eb;
                    u32 dt;
                    u32 dcode;
                    u32 dsym;
                    u32 dist;
                    int io = sym - 0x101;
                    len2 = gInflateLengthCodes[io].base;
                    eb = gInflateLengthCodes[io].extra;
                    if (eb != 0)
                    {
                        len2 += ZGB8() & ((1 << eb) - 1);
                        ZADV(eb);
                    }
                    dt = ZGB16() & ((1 << distMax) - 1);
                    dcode = __rlwnm(lbl_8030CDE0[dt & 0xff], distMax - 8, 16, 31) |
                        __rlwnm(lbl_8030CDE0[dt >> 8], distMax + 0x10, 24, 31);
                    dsym = distTblP[dcode];
                    ZADV(distBitsP[dsym]);
                    dist = gInflateDistCodes[dsym].base;
                    eb = gInflateDistCodes[dsym].extra;
                    if (eb != 0)
                    {
                        dist += ZGB16() & ((1 << eb) - 1);
                        ZADV(eb);
                    }
                    {
                        u8* from = dst - dist;
                        do
                        {
                            *++dst = *++from;
                        }
                        while (--len2 != 0);
                    }
                }
            }
            while (sym != 0x100);
        }
    }
    while (final == 0);
    return 0;
}
#pragma optimize_for_size reset
