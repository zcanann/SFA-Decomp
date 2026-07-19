#include "dolphin/os/OSReport.h"
#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "dolphin/gx/GXMisc.h"
#include "main/pi_dolphin.h"
#include "main/pi_dolphin_ext.h"
#include "main/newshadows.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSStopwatch.h"
#include "string.h"
#include "main/pad.h"
#include "main/pi_data_file_api.h"
#include "main/pi_flush_api.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/pi_dolphin_fileload_api.h"
#include "main/dll/FRONT/n_options.h"
#include "dolphin/os/OSResetSW.h"
#include "dolphin/gx/GXCull.h"
#include "main/track_dolphin_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/os/OSArena.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "dolphin/gx/GXCpu2Efb.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXPerf.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/os/OSTime.h"
#include "dolphin/vi.h"
#include "main/camera.h"
#include "main/debug.h"
#include "main/fileio.h"
#include "main/gameloop_api.h"
#include "main/map_load.h"
#include "main/map_texscroll.h"
#include "main/table_file.h"
#include "main/rcp_dolphin.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "main/vecmath_distance_api.h"
#include "main/zlb.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_depth_read_api.h"

static u32 sPiUnused3;
void* lbl_803DCD10;
static u32 sPiUnused2;
char* lbl_803DCD08;
static u32 sPiUnused1;
u8 lbl_803DCD00;
int lbl_803DCCFC;
u8 lbl_803DCCF8;
int lbl_803DCCF4;
GXRenderModeObj* gRenderModeObj;
void* externalFrameBuffer0;
void* externalFrameBuffer1;
void* lbl_803DCCE4;
char* lbl_803DCCE0;
OSThread* lbl_803DCCDC;
void* lbl_803DCCD8;
GXFifoObj* lbl_803DCCD4;
void* renderFrameBuffer;
void* displayFrameBuffer;
static u32 sPiUnused4;
char lbl_803DCCC4;
f32 lbl_803DCCC0;
u32 lbl_803DCCBC;
int lbl_803DCCB8;
f32 lbl_803DCCB4;
u8 lbl_803DCCB0;
volatile int lbl_803DCCAC;
u16 lbl_803DCCAA;
u8 lbl_803DCCA9;
u8 lbl_803DCCA8;
u8 lbl_803DCCA7;
u8 lbl_803DCCA6;
u8 lbl_803DCCA5;
u8 lbl_803DCCA4;
int lbl_803DCCA0;
static u32 sPiUnused0;
int lbl_803DCC98;

char sResourceFileNameSfxTab[] = "SFX.tab";
char sResourceFileNameSfxBin[] = "SFX.bin";
char sResourceFileNameNull[] = "NULL";
char sMapFileNameTemple[] = "temple";
char sMapFileNameHightop[] = "hightop";
char sMapFileNameHollow[] = "hollow";
char sMapFileNameHollow2[] = "hollow2";
char sMapFileNameWastes[] = "wastes";
char sMapFileNameWarlock[] = "warlock";
char sMapFileNameWillow[] = "willow";
char sMapFileNameArwing[] = "arwing";
char sMapFileNameDfptop[] = "dfptop";
char sMapFileNameDragbot[] = "dragbot";
char sMapFileNameKamdrag[] = "kamdrag";
char sMapFileNameDuster[] = "duster";
char sMapFileNameLinkb[] = "linkb";
char sMapFileNameLinka[] = "linka";
char sMapFileNameLinkc[] = "linkc";
char sMapFileNameLinkd[] = "linkd";
char sMapFileNameLinke[] = "linke";
char sMapFileNameLinkf[] = "linkf";
char sMapFileNameLinkg[] = "linkg";
char sMapFileNameLinkh[] = "linkh";
char sMapFileNameLinkj[] = "linkj";
char sMapFileNameLinki[] = "linki";
char sMapFileNameVolcano[] = "volcano";
char sMapFileNameDfalls[] = "dfalls";
char sMapFileNameSwaphol[] = "swaphol";
char sMapFileNameNwastes[] = "nwastes";
char sMapFileNameShop[] = "shop";
char sMapFileNameCrfort[] = "crfort";
char sMapFileNameMmpass[] = "mmpass";
char sMapFileNameDesert[] = "desert";
char sMapFileNameDbay[] = "dbay";
s32 gObjLevelLockSlots[2] = {-2, -2};
char sArchivePathFormat[] = "%s/%s";
char sZlbBlockTag[] = "ZLB";
char sDirBlockTag[] = "DIR";
int lbl_803DB5C8 = 1;
u8 lbl_803DB5CC = 5;
u16 lbl_803DB5CE = 1;
u8 lbl_803DB5D0[4] = {0, 0, 0, 0xFF};
u8 lbl_803DB5D4[8] = {7, 7, 0xC, 0xC, 0xC, 7, 7, 0};
char sProgramCounterFormat[] = "PC: %x";
int lbl_803DB5E4 = 0;

#define GX_CULL_NONE  0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK  2
#define GX_LEQUAL     3
#define PAD_BUTTON_A  0x100
#define PAD_BUTTON_B  0x200
extern int lbl_803DCD6C;
extern int lbl_803DCD70;
extern int lbl_803DCD74;
extern char sResourceFileNameAudioTab[];
extern u8 lbl_80345E10[]; /* resource file table -- see struct MldfTables */
extern s16 lbl_803DCC92;
extern int lbl_803DCC70;
extern int lbl_803DCC7C;
extern volatile int lbl_803DCC80;

#include "main/objprint_load_api.h"
#include "dolphin/os/OSAlloc.h"
#include "main/objmodel.h"
#include "main/mm_ext.h"
#include "main/newshadows_texture_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "dolphin/gx/GXBump.h"

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

/* Resource file table at lbl_80345E10 (0x80345E10, 0x20000 bytes). File slots are
   indexed by resource fileId (0..0x57); map-owned resources use paired slots (e.g.
   ANIMCURV 0xd/0x55) so two maps can be resident at once. Several arrays are also
   addressed directly through their own symbols elsewhere in this file:
   ids   == lbl_8035EF48 (pending mapId per slot, -1 = none; retried by loadDataFiles)
   sizes == lbl_8035F0A8, romList == lbl_8035F208, ptrs == lbl_8035F3E8. */
struct MldfTables
{
    u8 pad0[0x160];
    DVDFileInfo* fileInfo[0x58]; /* async read in flight */
    u8 mergeAnimCurv[0x7f40]; /* merged 2-slot TAB, 0x1fd0 entries */
    u8 mergeVoxMap[0x2000];   /* 0x800 entries */
    u8 mergeBlocks[0x2000];   /* 0x800 entries */
    u8 mergeTex1[0x4000];     /* 0x1000 entries */
    u8 mergeTex0[0x4000];     /* 0x1000 entries */
    u8 mergeAnim[0x2ee0];     /* 3000 entries */
    u8 mergeModels[0x2000];   /* 0x800 entries */
    u8 loadedFlags[0x58];     /* cleared by initLoadFiles */
    int ids[0x58];            /* mapId whose load must be retried, -1 = none */
    int sizes[0x58];          /* byte size of the loaded file */
    int romList[0x78];        /* per-MAP romlist buffer (indexed by mapIndex) */
    u32 ptrs[0x58];           /* loaded file buffer, 0 = not resident */
    s16 owners[0x60];         /* mapId owning the slot, -1 = free */
};

typedef u8 MldfArenaBlock[0x20000];
enum
{
    MLDF_ROM_LIST_WORDS_FROM_ARENA_END =
        (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, romList)) / sizeof(int)
};

struct MldfIterators
{
    void** ptrs;
    s16* owners;
    int* ids;
    char** names;
    int* sizes;
    u8* flags;
};

#define MLDF_MAP_NAME(i)  (nm->mapNames[i])
#define MLDF_FILE_NAME(i) (nm->fileNames[i])
#define MLDF_ADJ(i)       (nm->adjacency[i])
#define MLDF_REMAP        (nm->remapGroups)
/* Constant-index accessors (typed member form). */
#define MLDF_ID(s)    (tbl->ids[s])
#define MLDF_SIZE(s)  (tbl->sizes[s])
#define MLDF_PTR(s)   (tbl->ptrs[s])
#define MLDF_OWNER(s) (tbl->owners[s])
/* Runtime-index accessors. One-shot accesses use the idx-left flat spelling
   (slwi; addis tbl; add) or plain member form; the hot ptr/size slots go through
   per-block biased locals (see slotPtrAddr/slotSizeAddr) so the CSE web keeps the
   ha-sum (tbl + 0x20000 + slot*4) and each access folds the lo displacement. */
#define MLDF_ID_RT(s)    (*(int*)(((s) << 2) + ((u32) & tbl->ids[0])))
#define MLDF_OWNER_RT(s) (*(s16*)(((s) << 1) + ((u32) & tbl->owners[0])))
#define MLDF_FINFO4(s4)  (tbl->fileInfo[slot])
#define MLDF_SP_ID(p)    (tbl->ids[slot])
#define MLDF_SP_SIZE(p)  (*(int*)(slotSizeAddr - 0x6D68))
/* first store of the block also establishes the biased size base; embedding the
   assignment in the lvalue makes MWCC evaluate the RHS (file length) first, as target */
#define MLDF_SP_SIZE_INIT(p) (*(int*)((slotSizeAddr = (slot << 2) + ((u32) & tbl->sizes[0] + 0x6D68)) - 0x6D68))
#define MLDF_SP_PTR(p)       (*(u32*)(slotPtrAddr - 0x6A28))
/* re-deref through the biased local `slotPtrAddr` on every use; the -0x6A28 displacement
   (== &tbl->ptrs[0] relative to tbl + 0x20000) matches target addressing */
#define MLDF_QPTR (*(u32*)(slotPtrAddr - 0x6A28))

/* 16-byte header of a "ZLB"-tagged compressed stream; the deflate payload
   follows at +0x10. "DIR"-tagged data is stored raw. */
struct ZlbHeader
{
    char tag[4]; /* "ZLB" (sZlbBlockTag) / "DIR" (sDirBlockTag) */
    u32 unk4;
    u32 decompressedSize; /* +0x08 */
    int compressedSize;   /* +0x0c */
};
#define ZLB_HDR(buf) ((struct ZlbHeader*)(buf))

/* DVDFileInfo.length: byte length of the opened file. */
#define DVD_FI_LENGTH(fi) ((fi)->length)

/* header of a packed rom section (romlist blocks, MAPS.BIN sections) */
struct PackHeader
{
    u32 magic;            /* 0xFACEFEED = zlb-packed, 0xE0E0E0E0 = stored raw */
    int decompressedSize; /* +0x04 (decompressed in place: also the zlb size out-slot) */
    int auxSize;          /* +0x08: extra bytes between header and payload */
    int compressedSize;   /* +0x0c */
};

extern char sResourceFileNameAudioBin[];
extern char sResourceFileNameAmbientTab[];
extern char sResourceFileNameAmbientBin[];
extern char sResourceFileNameMusicTab[];
extern char sResourceFileNameMusicBin[];
extern char sResourceFileNameMpegTab[];
extern char sResourceFileNameMpegBin[];
extern char sResourceFileNameMusicactBin[];
extern char sResourceFileNameCamactioBin[];
extern char sResourceFileNameLactionsBin[];
extern char sResourceFileNameAnimcurvBin[];
extern char sResourceFileNameAnimcurvTab[];
extern char sResourceFileNameObjseq2cTab[];
extern char sResourceFileNameFontsBin[];
extern char sResourceFileNameCachefonBin[];
extern char sResourceFileNameGametextBin[];
extern char sResourceFileNameGametextTab[];
extern char sResourceFileNameGlobalmaBin[];
extern char sResourceFileNameTablesBin[];
extern char sResourceFileNameTablesTab[];
extern char sResourceFileNameScreensBin[];
extern char sResourceFileNameScreensTab[];
extern char sResourceFileNameVoxmapTab[];
extern char sResourceFileNameVoxmapBin[];
extern char sResourceFileNameWarptabBin[];
extern char sResourceFileNameMapsBin[];
extern char sResourceFileNameMapsTab[];
extern char sResourceFileNameMapinfoBin[];
extern char sResourceFileNameTex1Bin[];
extern char sResourceFileNameTex1Tab[];
extern char sResourceFileNameTextableBin[];
extern char sResourceFileNameTex0Bin[];
extern char sResourceFileNameTex0Tab[];
extern char sResourceFileNameBlocksBin[];
extern char sResourceFileNameBlocksTab[];
extern char sResourceFileNameTrkblkTab[];
extern char sResourceFileNameHitsBin[];
extern char sResourceFileNameHitsTab[];
extern char sResourceFileNameModelsTab[];
extern char sResourceFileNameModelsBin[];
extern char sResourceFileNameModelindBin[];
extern char sResourceFileNameModanimTab[];
extern char sResourceFileNameModanimBin[];
extern char sResourceFileNameAnimTab[];
extern char sResourceFileNameAnimBin[];
extern char sResourceFileNameAmapTab[];
extern char sResourceFileNameAmapBin[];
extern char sResourceFileNameBittableBin[];
extern char sResourceFileNameWeapondaBin[];
extern char sResourceFileNameVoxobjTab[];
extern char sResourceFileNameVoxobjBin[];
extern char sResourceFileNameModlinesBin[];
extern char sResourceFileNameModlinesTab[];
extern char sResourceFileNameSavegameBin[];
extern char sResourceFileNameSavegameTab[];
extern char sResourceFileNameObjseqBin[];
extern char sResourceFileNameObjseqTab[];
extern char sResourceFileNameObjectsTab[];
extern char sResourceFileNameObjectsBin[];
extern char sResourceFileNameObjindexBin[];
extern char sResourceFileNameObjeventBin[];
extern char sResourceFileNameObjhitsBin[];
extern char sResourceFileNameDllsBin[];
extern char sResourceFileNameDllsTab[];
extern char sResourceFileNameDllsimpoBin[];
extern char sResourceFileNameTexpreBin[];
extern char sResourceFileNameTexpreTab[];
extern char sResourceFileNamePreanimBin[];
extern char sResourceFileNamePreanimTab[];
extern char sResourceFileNameEnvfxactBin[];

char* sResourceFileNameTable[90] = {
    sResourceFileNameAudioTab,    sResourceFileNameAudioBin,    sResourceFileNameSfxTab,
    sResourceFileNameSfxBin,      sResourceFileNameAmbientTab,  sResourceFileNameAmbientBin,
    sResourceFileNameMusicTab,    sResourceFileNameMusicBin,    sResourceFileNameMpegTab,
    sResourceFileNameMpegBin,     sResourceFileNameMusicactBin, sResourceFileNameCamactioBin,
    sResourceFileNameLactionsBin, sResourceFileNameAnimcurvBin, sResourceFileNameAnimcurvTab,
    sResourceFileNameObjseq2cTab, sResourceFileNameFontsBin,    sResourceFileNameCachefonBin,
    sResourceFileNameCachefonBin, sResourceFileNameGametextBin, sResourceFileNameGametextTab,
    sResourceFileNameGlobalmaBin, sResourceFileNameTablesBin,   sResourceFileNameTablesTab,
    sResourceFileNameScreensBin,  sResourceFileNameScreensTab,  sResourceFileNameVoxmapTab,
    sResourceFileNameVoxmapBin,   sResourceFileNameWarptabBin,  sResourceFileNameMapsBin,
    sResourceFileNameMapsTab,     sResourceFileNameMapinfoBin,  sResourceFileNameTex1Bin,
    sResourceFileNameTex1Tab,     sResourceFileNameTextableBin, sResourceFileNameTex0Bin,
    sResourceFileNameTex0Tab,     sResourceFileNameBlocksBin,   sResourceFileNameBlocksTab,
    sResourceFileNameTrkblkTab,   sResourceFileNameHitsBin,     sResourceFileNameHitsTab,
    sResourceFileNameModelsTab,   sResourceFileNameModelsBin,   sResourceFileNameModelindBin,
    sResourceFileNameModanimTab,  sResourceFileNameModanimBin,  sResourceFileNameAnimTab,
    sResourceFileNameAnimBin,     sResourceFileNameAmapTab,     sResourceFileNameAmapBin,
    sResourceFileNameBittableBin, sResourceFileNameWeapondaBin, sResourceFileNameVoxobjTab,
    sResourceFileNameVoxobjBin,   sResourceFileNameModlinesBin, sResourceFileNameModlinesTab,
    sResourceFileNameSavegameBin, sResourceFileNameSavegameTab, sResourceFileNameObjseqBin,
    sResourceFileNameObjseqTab,   sResourceFileNameObjectsTab,  sResourceFileNameObjectsBin,
    sResourceFileNameObjindexBin, sResourceFileNameObjeventBin, sResourceFileNameObjhitsBin,
    sResourceFileNameDllsBin,     sResourceFileNameDllsTab,     sResourceFileNameDllsimpoBin,
    sResourceFileNameModelsTab,   sResourceFileNameModelsBin,   sResourceFileNameBlocksBin,
    sResourceFileNameBlocksTab,   sResourceFileNameAnimTab,     sResourceFileNameAnimBin,
    sResourceFileNameTex1Bin,     sResourceFileNameTex1Tab,     sResourceFileNameTex0Bin,
    sResourceFileNameTex0Tab,     sResourceFileNameTexpreBin,   sResourceFileNameTexpreTab,
    sResourceFileNamePreanimBin,  sResourceFileNamePreanimTab,  sResourceFileNameVoxmapTab,
    sResourceFileNameVoxmapBin,   sResourceFileNameAnimcurvBin, sResourceFileNameAnimcurvTab,
    sResourceFileNameEnvfxactBin, sResourceFileNameNull,        sResourceFileNameNull,
};

extern char sMapFileNameFrontend[];
extern char sMapFileNameFrontend2[];
extern char sMapFileNameDragrock[];
extern char sMapFileNameKrazoapalace[];
extern char sMapFileNameDiscovery[];
extern char sMapFileNameMazecave[];
extern char sMapFileNameFortress[];
extern char sMapFileNameWallcity[];
extern char sMapFileNameSwapcircle[];
extern char sMapFileNameCloudtreasure[];
extern char sMapFileNameClouddungeon[];
extern char sMapFileNameCloudtrap[];
extern char sMapFileNameMoonpass[];
extern char sMapFileNameSnowmines[];
extern char sMapFileNameKrashrin2[];
extern char sMapFileNameKraztest[];
extern char sMapFileNameKrazchamber[];
extern char sMapFileNameNewicemount[];
extern char sMapFileNameNewicemount2[];
extern char sMapFileNameNewicemount3[];
extern char sMapFileNameAnimtest[];
extern char sMapFileNameSnowmines2[];
extern char sMapFileNameSnowmines3[];
extern char sMapFileNameCapeclaw[];
extern char sMapFileNameInsidegal[];
extern char sMapFileNameDfshrine[];
extern char sMapFileNameMmshrine[];
extern char sMapFileNameEcshrine[];
extern char sMapFileNameGpshrine[];
extern char sMapFileNameDiamondbay[];
extern char sMapFileNameEarthwalker[];
extern char sMapFileNameDbshrine[];
extern char sMapFileNameNwshrine[];
extern char sMapFileNameCcshrine[];
extern char sMapFileNameWgshrine[];
extern char sMapFileNameCloudrace[];
extern char sMapFileNameFinalboss[];
extern char sMapFileNameWminsert[];
extern char sMapFileNameSnowmines4[];
extern char sMapFileNameSnowmines5[];
extern char sMapFileNameTrexboss[];
extern char sMapFileNameMikelava[];
extern char sMapFileNameSwapstore[];
extern char sMapFileNameMagicave[];
extern char sMapFileNameCloudjoin[];
extern char sMapFileNameArwingtoplanet[];
extern char sMapFileNameArwingdarkice[];
extern char sMapFileNameArwingcloud[];
extern char sMapFileNameArwingcity[];
extern char sMapFileNameArwingdragon[];
extern char sMapFileNameGamefront[];
extern char sMapFileNameLinklevel[];
extern char sMapFileNameGreatfox[];
extern char sMapFileNameDfpodium[];
extern char sMapFileNameDfcradle[];
extern char sMapFileNameDfcavehatch1[];
extern char sMapFileNameDfcavehatch2[];
extern char sMapFileNameScstatue[];
extern char sMapFileNameGalleonship[];
extern char sMapFileNameCfgalleon[];
extern char sMapFileNameCfgangplank[];
extern char sMapFileNameNwtreebridge[];
extern char sMapFileNameCfdungeonblock[];
extern char sMapFileNameCloudrunnermap[];
extern char sMapFileNameCcbridge[];
extern char sMapFileNameCfcolumn[];
extern char sMapFileNameNwboulder[];
extern char sMapFileNameCfprisondoor[];
extern char sMapFileNameCfprisoncage[];
extern char sMapFileNameNwtreebridge2[];
extern char sMapFileNameDim2iceblock1[];
extern char sMapFileNameDimpushblock[];
extern char sMapFileNameDim2iceblock2[];
extern char sMapFileNameDimhornplinth[];
extern char sMapFileNameNwshcolpush[];
extern char sMapFileNameDim2lift[];
extern char sMapFileNameDim2icefloe[];
extern char sMapFileNameDim2icefloe1[];
extern char sMapFileNameDim2icefloe2[];
extern char sMapFileNameCfliftplat[];
extern char sMapFileNameImspacecraft[];
extern char sMapFileNameDimbossgut[];
extern char sMapFileNameWmcolrise[];
extern char sMapFileNameVfpslide1[];
extern char sMapFileNameVfpslide2[];
extern char sMapFileNameDrpushcart[];
extern char sMapFileNameDrliftplat[];
extern char sMapFileNameDim2stonepillar[];
extern char sMapFileNameBossdrakorflatr[];
extern char sMapFileNameWcbouncycrate[];
extern char sMapFileNameWcpushblock[];
extern char sMapFileNameWctemplelift[];
extern char sMapFileNameKamColumn[];
extern char sMapFileNameDbstepstone[];
extern char sMapFileNameVfppushblock[];

char* sMapFileNameTable[117] = {
    sMapFileNameFrontend,       sMapFileNameFrontend2,       sMapFileNameDragrock,        sMapFileNameKrazoapalace,
    sMapFileNameTemple,         sMapFileNameHightop,         sMapFileNameDiscovery,       sMapFileNameHollow,
    sMapFileNameHollow2,        sMapFileNameMazecave,        sMapFileNameWastes,          sMapFileNameWarlock,
    sMapFileNameFortress,       sMapFileNameWallcity,        sMapFileNameSwapcircle,      sMapFileNameCloudtreasure,
    sMapFileNameClouddungeon,   sMapFileNameCloudtrap,       sMapFileNameMoonpass,        sMapFileNameSnowmines,
    sMapFileNameKrashrin2,      sMapFileNameKraztest,        sMapFileNameKrazchamber,     sMapFileNameNewicemount,
    sMapFileNameNewicemount2,   sMapFileNameNewicemount3,    sMapFileNameAnimtest,        sMapFileNameSnowmines2,
    sMapFileNameSnowmines3,     sMapFileNameCapeclaw,        sMapFileNameInsidegal,       sMapFileNameDfshrine,
    sMapFileNameMmshrine,       sMapFileNameEcshrine,        sMapFileNameGpshrine,        sMapFileNameDiamondbay,
    sMapFileNameEarthwalker,    sMapFileNameWillow,          sMapFileNameArwing,          sMapFileNameDbshrine,
    sMapFileNameNwshrine,       sMapFileNameCcshrine,        sMapFileNameWgshrine,        sMapFileNameCloudrace,
    sMapFileNameFinalboss,      sMapFileNameWminsert,        sMapFileNameSnowmines4,      sMapFileNameSnowmines5,
    sMapFileNameTrexboss,       sMapFileNameMikelava,        sMapFileNameDfptop,          sMapFileNameSwapstore,
    sMapFileNameDragbot,        sMapFileNameKamdrag,         sMapFileNameMagicave,        sMapFileNameDuster,
    sMapFileNameLinkb,          sMapFileNameCloudjoin,       sMapFileNameArwingtoplanet,  sMapFileNameArwingdarkice,
    sMapFileNameArwingcloud,    sMapFileNameArwingcity,      sMapFileNameArwingdragon,    sMapFileNameGamefront,
    sMapFileNameLinklevel,      sMapFileNameGreatfox,        sMapFileNameLinka,           sMapFileNameLinkc,
    sMapFileNameLinkd,          sMapFileNameLinke,           sMapFileNameLinkf,           sMapFileNameLinkg,
    sMapFileNameLinkh,          sMapFileNameLinkj,           sMapFileNameLinki,           sMapFileNameDfpodium,
    sMapFileNameDfcradle,       sMapFileNameDfcavehatch1,    sMapFileNameDfcavehatch2,    sMapFileNameScstatue,
    sMapFileNameGalleonship,    sMapFileNameCfgalleon,       sMapFileNameCfgangplank,     sMapFileNameNwtreebridge,
    sMapFileNameCfdungeonblock, sMapFileNameCloudrunnermap,  sMapFileNameCcbridge,        sMapFileNameCfcolumn,
    sMapFileNameNwboulder,      sMapFileNameCfprisondoor,    sMapFileNameCfprisoncage,    sMapFileNameNwtreebridge2,
    sMapFileNameDim2iceblock1,  sMapFileNameDimpushblock,    sMapFileNameDim2iceblock2,   sMapFileNameDimhornplinth,
    sMapFileNameNwshcolpush,    sMapFileNameDim2lift,        sMapFileNameDim2icefloe,     sMapFileNameDim2icefloe1,
    sMapFileNameDim2icefloe2,   sMapFileNameCfliftplat,      sMapFileNameImspacecraft,    sMapFileNameDimbossgut,
    sMapFileNameWmcolrise,      sMapFileNameVfpslide1,       sMapFileNameVfpslide2,       sMapFileNameDrpushcart,
    sMapFileNameDrliftplat,     sMapFileNameDim2stonepillar, sMapFileNameBossdrakorflatr, sMapFileNameWcbouncycrate,
    sMapFileNameWcpushblock,    sMapFileNameWctemplelift,    sMapFileNameKamColumn,       sMapFileNameDbstepstone,
    sMapFileNameVfppushblock,
};

char sMapFileNameFrontend[] = "frontend";
char sMapFileNameFrontend2[] = "frontend2";
char sMapFileNameDragrock[] = "dragrock";
char sMapFileNameKrazoapalace[] = "krazoapalace";
char sMapFileNameDiscovery[] = "discovery";
char sMapFileNameMazecave[] = "mazecave";
char sMapFileNameFortress[] = "fortress";
char sMapFileNameWallcity[] = "wallcity";
char sMapFileNameSwapcircle[] = "swapcircle";
char sMapFileNameCloudtreasure[] = "cloudtreasure";
char sMapFileNameClouddungeon[] = "clouddungeon";
char sMapFileNameCloudtrap[] = "cloudtrap";
char sMapFileNameMoonpass[] = "moonpass";
char sMapFileNameSnowmines[] = "snowmines";
char sMapFileNameKrashrin2[] = "krashrin2";
char sMapFileNameKraztest[] = "kraztest";
char sMapFileNameKrazchamber[] = "krazchamber";
char sMapFileNameNewicemount[] = "newicemount";
char sMapFileNameNewicemount2[] = "newicemount2";
char sMapFileNameNewicemount3[] = "newicemount3";
char sMapFileNameAnimtest[] = "animtest";
char sMapFileNameSnowmines2[] = "snowmines2";
char sMapFileNameSnowmines3[] = "snowmines3";
char sMapFileNameCapeclaw[] = "capeclaw";
char sMapFileNameInsidegal[] = "insidegal";
char sMapFileNameDfshrine[] = "dfshrine";
char sMapFileNameMmshrine[] = "mmshrine";
char sMapFileNameEcshrine[] = "ecshrine";
char sMapFileNameGpshrine[] = "gpshrine";
char sMapFileNameDiamondbay[] = "diamondbay";
char sMapFileNameEarthwalker[] = "earthwalker";
char sMapFileNameDbshrine[] = "dbshrine";
char sMapFileNameNwshrine[] = "nwshrine";
char sMapFileNameCcshrine[] = "ccshrine";
char sMapFileNameWgshrine[] = "wgshrine";
char sMapFileNameCloudrace[] = "cloudrace";
char sMapFileNameFinalboss[] = "finalboss";
char sMapFileNameWminsert[] = "wminsert";
char sMapFileNameSnowmines4[] = "snowmines4";
char sMapFileNameSnowmines5[] = "snowmines5";
char sMapFileNameTrexboss[] = "trexboss";
char sMapFileNameMikelava[] = "mikelava";
char sMapFileNameSwapstore[] = "swapstore";
char sMapFileNameMagicave[] = "magicave";
char sMapFileNameCloudjoin[] = "cloudjoin";
char sMapFileNameArwingtoplanet[] = "arwingtoplanet";
char sMapFileNameArwingdarkice[] = "arwingdarkice";
char sMapFileNameArwingcloud[] = "arwingcloud";
char sMapFileNameArwingcity[] = "arwingcity";
char sMapFileNameArwingdragon[] = "arwingdragon";
char sMapFileNameGamefront[] = "gamefront";
char sMapFileNameLinklevel[] = "linklevel";
char sMapFileNameGreatfox[] = "greatfox";
char sMapFileNameDfpodium[] = "dfpodium";
char sMapFileNameDfcradle[] = "dfcradle";
char sMapFileNameDfcavehatch1[] = "dfcavehatch1";
char sMapFileNameDfcavehatch2[] = "dfcavehatch2";
char sMapFileNameScstatue[] = "scstatue";
char sMapFileNameGalleonship[] = "galleonship";
char sMapFileNameCfgalleon[] = "cfgalleon";
char sMapFileNameCfgangplank[] = "cfgangplank";
char sMapFileNameNwtreebridge[] = "nwtreebridge";
char sMapFileNameCfdungeonblock[] = "cfdungeonblock";
char sMapFileNameCloudrunnermap[] = "cloudrunnermap";
char sMapFileNameCcbridge[] = "ccbridge";
char sMapFileNameCfcolumn[] = "cfcolumn";
char sMapFileNameNwboulder[] = "nwboulder";
char sMapFileNameCfprisondoor[] = "cfprisondoor";
char sMapFileNameCfprisoncage[] = "cfprisoncage";
char sMapFileNameNwtreebridge2[] = "nwtreebridge2";
char sMapFileNameDim2iceblock1[] = "dim2iceblock1";
char sMapFileNameDimpushblock[] = "dimpushblock";
char sMapFileNameDim2iceblock2[] = "dim2iceblock2";
char sMapFileNameDimhornplinth[] = "dimhornplinth";
char sMapFileNameNwshcolpush[] = "nwshcolpush";
char sMapFileNameDim2lift[] = "dim2lift";
char sMapFileNameDim2icefloe[] = "dim2icefloe";
char sMapFileNameDim2icefloe1[] = "dim2icefloe1";
char sMapFileNameDim2icefloe2[] = "dim2icefloe2";
char sMapFileNameCfliftplat[] = "cfliftplat";
char sMapFileNameImspacecraft[] = "imspacecraft";
char sMapFileNameDimbossgut[] = "dimbossgut";
char sMapFileNameWmcolrise[] = "wmcolrise";
char sMapFileNameVfpslide1[] = "vfpslide1";
char sMapFileNameVfpslide2[] = "vfpslide2";
char sMapFileNameDrpushcart[] = "drpushcart";
char sMapFileNameDrliftplat[] = "drliftplat";
char sMapFileNameDim2stonepillar[] = "dim2stonepillar";
char sMapFileNameBossdrakorflatr[] = "bossdrakorflatr";
char sMapFileNameWcbouncycrate[] = "wcbouncycrate";
char sMapFileNameWcpushblock[] = "wcpushblock";
char sMapFileNameWctemplelift[] = "wctemplelift";
char sMapFileNameKamColumn[] = "KamColumn";
char sMapFileNameDbstepstone[] = "dbstepstone";
char sMapFileNameVfppushblock[] = "vfppushblock";

/* Resource archive file-name strings (indexed by sResourceFileNameTable). */
char sResourceFileNameAudioTab[] = "AUDIO.tab";
char sResourceFileNameAudioBin[] = "AUDIO.bin";
char sResourceFileNameAmbientTab[] = "AMBIENT.tab";
char sResourceFileNameAmbientBin[] = "AMBIENT.bin";
char sResourceFileNameMusicTab[] = "MUSIC.tab";
char sResourceFileNameMusicBin[] = "MUSIC.bin";
char sResourceFileNameMpegTab[] = "MPEG.tab";
char sResourceFileNameMpegBin[] = "MPEG.bin";
char sResourceFileNameMusicactBin[] = "MUSICACT.bin";
char sResourceFileNameCamactioBin[] = "CAMACTIO.bin";
char sResourceFileNameLactionsBin[] = "LACTIONS.bin";
char sResourceFileNameAnimcurvBin[] = "ANIMCURV.bin";
char sResourceFileNameAnimcurvTab[] = "ANIMCURV.tab";
char sResourceFileNameObjseq2cTab[] = "OBJSEQ2C.tab";
char sResourceFileNameFontsBin[] = "FONTS.bin";
char sResourceFileNameCachefonBin[] = "CACHEFON.bin";
char sResourceFileNameGametextBin[] = "GAMETEXT.bin";
char sResourceFileNameGametextTab[] = "GAMETEXT.tab";
char sResourceFileNameGlobalmaBin[] = "globalma.bin";
char sResourceFileNameTablesBin[] = "TABLES.bin";
char sResourceFileNameTablesTab[] = "TABLES.tab";
char sResourceFileNameScreensBin[] = "SCREENS.bin";
char sResourceFileNameScreensTab[] = "SCREENS.tab";
char sResourceFileNameVoxmapTab[] = "VOXMAP.tab";
char sResourceFileNameVoxmapBin[] = "VOXMAP.bin";
char sResourceFileNameWarptabBin[] = "WARPTAB.bin";
char sResourceFileNameMapsBin[] = "MAPS.bin";
char sResourceFileNameMapsTab[] = "MAPS.tab";
char sResourceFileNameMapinfoBin[] = "MAPINFO.bin";
char sResourceFileNameTex1Bin[] = "TEX1.bin";
char sResourceFileNameTex1Tab[] = "TEX1.tab";
char sResourceFileNameTextableBin[] = "TEXTABLE.bin";
char sResourceFileNameTex0Bin[] = "TEX0.bin";
char sResourceFileNameTex0Tab[] = "TEX0.tab";
char sResourceFileNameBlocksBin[] = "BLOCKS.bin";
char sResourceFileNameBlocksTab[] = "BLOCKS.tab";
char sResourceFileNameTrkblkTab[] = "TRKBLK.tab";
char sResourceFileNameHitsBin[] = "HITS.bin";
char sResourceFileNameHitsTab[] = "HITS.tab";
char sResourceFileNameModelsTab[] = "MODELS.tab";
char sResourceFileNameModelsBin[] = "MODELS.bin";
char sResourceFileNameModelindBin[] = "MODELIND.bin";
char sResourceFileNameModanimTab[] = "MODANIM.TAB";
char sResourceFileNameModanimBin[] = "MODANIM.BIN";
char sResourceFileNameAnimTab[] = "ANIM.TAB";
char sResourceFileNameAnimBin[] = "ANIM.BIN";
char sResourceFileNameAmapTab[] = "AMAP.TAB";
char sResourceFileNameAmapBin[] = "AMAP.BIN";
char sResourceFileNameBittableBin[] = "BITTABLE.bin";
char sResourceFileNameWeapondaBin[] = "WEAPONDA.bin";
char sResourceFileNameVoxobjTab[] = "VOXOBJ.tab";
char sResourceFileNameVoxobjBin[] = "VOXOBJ.bin";
char sResourceFileNameModlinesBin[] = "MODLINES.bin";
char sResourceFileNameModlinesTab[] = "MODLINES.tab";
char sResourceFileNameSavegameBin[] = "SAVEGAME.bin";
char sResourceFileNameSavegameTab[] = "SAVEGAME.tab";
char sResourceFileNameObjseqBin[] = "OBJSEQ.bin";
char sResourceFileNameObjseqTab[] = "OBJSEQ.tab";
char sResourceFileNameObjectsTab[] = "OBJECTS.tab";
char sResourceFileNameObjectsBin[] = "OBJECTS.bin";
char sResourceFileNameObjindexBin[] = "OBJINDEX.bin";
char sResourceFileNameObjeventBin[] = "OBJEVENT.bin";
char sResourceFileNameObjhitsBin[] = "OBJHITS.bin";
char sResourceFileNameDllsBin[] = "DLLS.bin";
char sResourceFileNameDllsTab[] = "DLLS.tab";
char sResourceFileNameDllsimpoBin[] = "DLLSIMPO.bin";
char sResourceFileNameTexpreBin[] = "TEXPRE.bin";
char sResourceFileNameTexpreTab[] = "TEXPRE.tab";
char sResourceFileNamePreanimBin[] = "PREANIM.bin";
char sResourceFileNamePreanimTab[] = "PREANIM.tab";
char sResourceFileNameEnvfxactBin[] = "ENVFXACT.bin";


char sMapFileNameDragrockbot[] = "dragrockbot";
char sMapFileNameShipbattle[] = "shipbattle";
char sMapFileNameSwapholbot[] = "swapholbot";
char sMapFileNameLightfoot[] = "lightfoot";
char sMapFileNameDarkicemines[] = "darkicemines";
char sMapFileNameIcemountain[] = "icemountain";
char sMapFileNameDarkicemines2[] = "darkicemines2";
char sMapFileNameBossgaldon[] = "bossgaldon";
char sMapFileNameMagiccave[] = "magiccave";
char sMapFileNameWorldmap[] = "worldmap";
char sMapFileNameBossdrakor[] = "bossdrakor";
char sMapFileNameBosstrex[] = "bosstrex";

char* sMapFileNameByMapIdTable[] = {
    sMapFileNameAnimtest,       sMapFileNameAnimtest,      sMapFileNameAnimtest,      sMapFileNameArwing,
    sMapFileNameDragrock,       sMapFileNameAnimtest,      sMapFileNameDfptop,        sMapFileNameVolcano,
    sMapFileNameAnimtest,       sMapFileNameMazecave,      sMapFileNameDragrockbot,   sMapFileNameDfalls,
    sMapFileNameSwaphol,        sMapFileNameShipbattle,    sMapFileNameNwastes,       sMapFileNameWarlock,
    sMapFileNameShop,           sMapFileNameAnimtest,      sMapFileNameCrfort,        sMapFileNameSwapholbot,
    sMapFileNameWallcity,       sMapFileNameLightfoot,     sMapFileNameCloudtreasure, sMapFileNameAnimtest,
    sMapFileNameClouddungeon,   sMapFileNameMmpass,        sMapFileNameDarkicemines,  sMapFileNameAnimtest,
    sMapFileNameDesert,         sMapFileNameAnimtest,      sMapFileNameIcemountain,   sMapFileNameAnimtest,
    sMapFileNameAnimtest,       sMapFileNameAnimtest,      sMapFileNameDarkicemines2, sMapFileNameBossgaldon,
    sMapFileNameAnimtest,       sMapFileNameInsidegal,     sMapFileNameMagiccave,     sMapFileNameDfshrine,
    sMapFileNameMmshrine,       sMapFileNameEcshrine,      sMapFileNameGpshrine,      sMapFileNameDbshrine,
    sMapFileNameNwshrine,       sMapFileNameWorldmap,      sMapFileNameAnimtest,      sMapFileNameCapeclaw,
    sMapFileNameDbay,           sMapFileNameAnimtest,      sMapFileNameCloudrace,     sMapFileNameBossdrakor,
    sMapFileNameAnimtest,       sMapFileNameBosstrex,      sMapFileNameLinkb,         sMapFileNameCloudjoin,
    sMapFileNameArwingtoplanet, sMapFileNameArwingdarkice, sMapFileNameArwingcloud,   sMapFileNameArwingcity,
    sMapFileNameArwingdragon,   sMapFileNameGamefront,     sMapFileNameLinklevel,     sMapFileNameGreatfox,
    sMapFileNameLinka,          sMapFileNameLinkc,         sMapFileNameLinkd,         sMapFileNameLinke,
    sMapFileNameLinkf,          sMapFileNameLinkg,         sMapFileNameLinkh,         sMapFileNameLinkj,
    sMapFileNameLinki,
};

u32 sMapFileNameIndexRemapTable[] = {
    13, 5,  4,  5,  7,  5,  5,  12, 19, 9,  14, 15, 18, 20, 21, 22, 24, 5,  25, 26, 5,  28, 5,  30, 31,
    32, 5,  34, 35, 47, 37, 39, 40, 41, 42, 48, 5,  5,  3,  43, 44, 45, 5,  50, 51, 5,  5,  5,  53, 5,
    6,  16, 10, 5,  38, 55, 54, 5,  56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
};

s16 sMapFileNameAdjacencyTable[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 12, -1, -1, -1, 15, -1, -1, 12, -1, -1, 12, -1, -1, -1, -1, 18, -1,
    -1, -1, 6,  -1, -1, -1, -1, -1, -1, 34, -1, -1, -1, 25, 21, 15, 20, 14, 15, -1, -1, -1, 5,  -1, -1, -1,
    -1, 20, 30, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 14, -1, 12, 7,  12, 21, 47, -1, -1, -1, 0,
};



void* jumptable_802CBE94[13] = {
    (void*)((u8*)fn_80041D98 + 0x44), (void*)((u8*)fn_80041D98 + 0x48),
    (void*)((u8*)fn_80041D98 + 0x4C), (void*)((u8*)fn_80041D98 + 0x50),
    (void*)((u8*)fn_80041D98 + 0x54), (void*)((u8*)fn_80041D98 + 0x58),
    (void*)((u8*)fn_80041D98 + 0x5C), (void*)((u8*)fn_80041D98 + 0x60),
    (void*)((u8*)fn_80041D98 + 0x64), (void*)((u8*)fn_80041D98 + 0x68),
    (void*)((u8*)fn_80041D98 + 0x6C), (void*)((u8*)fn_80041D98 + 0x70),
    (void*)((u8*)fn_80041D98 + 0x74),
};

void* jumptable_802CBEC8[73] = {
    (void*)((u8*)defragMemory + 0x1CC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x1CC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x1CC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x1CC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x1CC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x1CC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x1CC),
    (void*)((u8*)defragMemory + 0x1CC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x1CC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x1CC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x3AC),
    (void*)((u8*)defragMemory + 0x3AC), (void*)((u8*)defragMemory + 0x1CC),
    (void*)((u8*)defragMemory + 0x1CC),
};

void* jumptable_802CBFEC[73] = {
    (void*)((u8*)defragMemory + 0xB8), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0xB8), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0xB8), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0xB8), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0xB8), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0xB8),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0xB8),
    (void*)((u8*)defragMemory + 0xB8), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0xB8),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0xB8), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0x15C),
    (void*)((u8*)defragMemory + 0x15C), (void*)((u8*)defragMemory + 0xB8),
    (void*)((u8*)defragMemory + 0xB8),
};

char sAssetIndexOverflowError[0x1D] = "ERROR: asset index overflow ";

void* jumptable_802CC130[73] = {
    (void*)((u8*)mapUnload + 0x4EC), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x4D0), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x498),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x47C), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x4B4), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x444), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x460),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x444),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x4B4), (void*)((u8*)mapUnload + 0x460),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x498), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x47C), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x4D0),
    (void*)((u8*)mapUnload + 0x500), (void*)((u8*)mapUnload + 0x500),
    (void*)((u8*)mapUnload + 0x4EC),
};

void* jumptable_802CC254[73] = {
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x2F4), (void*)((u8*)mapUnload + 0x2E8),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x2F4),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x300), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x2E8),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x2E8),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x2E8),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x300), (void*)((u8*)mapUnload + 0x2E8),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x2F4),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x2F4),
    (void*)((u8*)mapUnload + 0x2E8), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x2E8),
    (void*)((u8*)mapUnload + 0x3D4), (void*)((u8*)mapUnload + 0x3D4),
    (void*)((u8*)mapUnload + 0x2E8),
};

char sMapAssetPathFormats[0x78] =
    "%s/animcurv.bin\0%s/animcurv.tab\0%s/voxmap.bin\0\0\0warlock/voxmap.bin\0\0%s/voxmap.tab\0\0"
    "\0%s/mod%d.zlb.bin\0\0\0\0%s/mod%d.tab";
extern u8 lbl_803DCD28;
extern f32 lbl_803DCD44;
extern f32 lbl_803DCD40;
extern u8 lbl_803DCD31;
extern f32 lbl_803DCD34;
extern f32 lbl_803DCD38;
extern f32 lbl_803DCD3C;
extern u8 lbl_803DCCB0;
void gxPerfFn_8004a77c(int);
extern void* lbl_803DCD10;
extern char* lbl_803DCD08;
extern void* renderFrameBuffer;
extern void* externalFrameBuffer0;
extern void* externalFrameBuffer1;
extern u8 lbl_803DCCA7;
extern u8 lbl_803DCD30;
extern u8 lbl_803DCD68;
extern int lbl_803DCD80;
extern u8 lbl_803DCD69;
extern f32 lbl_803DEACC;
extern f32 lbl_803DEADC;
extern int lbl_803DCD78;
extern u8* lbl_803DCD2C;
extern f32 lbl_803DEAE4;
extern u8 lbl_803DCD6B;
extern f32 lbl_803DEAF4;
extern f32 lbl_803DEAF8;
extern f32 lbl_803DEAFC;
extern f32 lbl_803DEB00;
extern int lbl_803DCD84;
extern f32 lbl_803DEAE8;
extern f32 lbl_803DEAEC;
extern f32 lbl_803DEAF0;
extern u8 gLoadingScreenTextures[];
extern OSStopwatch lbl_8035F680;
extern f32 lbl_803DCCC0;
extern f32 physicsTimeScale;
extern f32 lbl_803DEAA0;
extern f32 lbl_803DEA74;
extern f32 lbl_803DEA7C;
extern f32 lbl_803DCCB4;
extern u8 lbl_803DB411;
extern volatile int lbl_803DCCAC;
extern int lbl_803DCCA0;
extern u16 lbl_803DCCAA;
extern u8 lbl_803DCCA9;
extern u8 lbl_803DCCA8;
extern u8 lbl_803DCC90;
extern int lbl_803DCC88;
extern int lbl_803DCC98;
extern volatile int lbl_803DCC84;
extern void* lbl_803DCCD8;
extern void* lbl_803DCCE4;
extern void* displayFrameBuffer;
extern u8 lbl_803DCCA6;
extern u8 lbl_803DCCA4;
extern char lbl_8035F6B8[0x78];
extern RingBufferQueue lbl_8035F730;
extern char* lbl_803DCCE0;
extern int lbl_803DCCB8;
extern int lbl_803DCCF4;
extern u8 lbl_803DCD00;
extern int lbl_803DCCFC;
extern u8 lbl_803DCCF8;
extern f32 lbl_803DEA94;
extern f32 lbl_803DEA98;
extern u8 lbl_803DCD20[];
extern u8 lbl_803DCD18[];

void piRomLoadSection(int romOffset, int mapIndex, int destBuf);
int GXFlush_(u8 visible, int unused);
void waitNextFrame(void);


u32 mapLoadDataFile(int mapId, int fileId)
{
    struct MldfNames* nm = (struct MldfNames*)sResourceFileNameAudioTab;
    struct MldfTables* tbl = (struct MldfTables*)lbl_80345E10;
    DVDFileInfo* fi;
    int sync = 0;
    u32 result;
    int adj;
    int slot;
    u32 slotPtrAddr;  /* &tbl->ptrs[slot] + 0x6A28 (ha-sum biased base) */
    u32 slotSizeAddr; /* &tbl->sizes[slot] + 0x6D68 */
    int ok;
    u32 tmp;
    int cls[1];
    char buf[56];

    if (lbl_803DCC92 != 0)
    {
        lbl_803DCC92 = 0;
        sync = 1;
    }
    adj = MLDF_ADJ(mapId);
    if (adj != -1)
    {
        int nOwned = 0;
        s16 o25 = MLDF_OWNER(0x25);
        s16 o47;
        if (o25 != -1)
        {
            nOwned = 1;
        }
        o47 = MLDF_OWNER(0x47);
        if (o47 != -1)
        {
            nOwned = nOwned + 1;
        }
        if (nOwned == 0)
        {
            lbl_803DCC92 = 1;
            if (o25 == adj)
            {
                cls[0] = 0;
            }
            else if (o47 == adj)
            {
                cls[0] = 1;
            }
            else
            {
                cls[0] = -1;
            }
            if (cls[0] == -1)
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtAnimCurvBin, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
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
                        if (MLDF_ID_RT(fileId) == -1)
                        {
                            texRestructRefs(1);
                        }
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        MLDF_SP_SIZE(x) = 0;
                        MLDF_SP_ID(x) = mapId;
                        return 0;
                    }
                    else
                    {
                        if (sync != 0)
                        {
                            DVDRead(fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                            DVDClose(fi);
                            AtomicSList_Push(lbl_803DCC8C, fi);
                            if (((lbl_803DCC80 & 0x20000000) == 0) && ((lbl_803DCC80 & 0x80000000) == 0))
                            {
                                mergeTableFiles(tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
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
                            DVDReadAsyncPrio(fi, (void*)tmp, MLDF_SP_SIZE(x), 0, animCurvReadCb, 2);
                            MLDF_FINFO4(x) = fi;
                        }
                        MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtAnimCurvTab, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
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
                        DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x20000000) == 0) && ((lbl_803DCC80 & 0x80000000) == 0))
                        {
                            mergeTableFiles(tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
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
                        DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animCurvTabReadCb, 2);
                        MLDF_FINFO4(x) = fi;
                    }
                    MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtVoxmapBin, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                sprintf(buf, nm->fmtWarlockVoxmap);
                ok = DVDOpen(buf, fi);
                if (ok == 0)
                {
                    return 0;
                    break;
                }
            }
            MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
            if (MLDF_SP_SIZE(x) == 0)
            {
                sprintf(buf, nm->fmtWarlockVoxmap);
                ok = DVDOpen(buf, fi);
                if (ok == 0)
                {
                    return 0;
                    break;
                }
                MLDF_SP_SIZE(x) = DVD_FI_LENGTH(fi);
            }
            MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
            DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
            if (sync != 0)
            {
                DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                DVDClose(fi);
                AtomicSList_Push(lbl_803DCC8C, fi);
                if (((lbl_803DCC80 & 0x2000000) == 0) && ((lbl_803DCC80 & 0x8000000) == 0))
                {
                    mergeTableFiles(tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
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
                DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapReadCb, 2);
            }
            MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtVoxmapTab, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
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
                        DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x2000000) == 0) && ((lbl_803DCC80 & 0x8000000) == 0))
                        {
                            mergeTableFiles(tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
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
                        DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapTabReadCb, 2);
                    }
                    MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
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
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x20000) == 0) && ((lbl_803DCC80 & 0x80000) == 0))
                        {
                            mergeTableFiles(tbl->mergeBlocks, 0x26, 0x48, 0x800);
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
                        DVDReadAsyncPrio(fi, (void*)tmp, MLDF_SP_SIZE(x), 0, blocksReadCb, 2);
                    }
                    MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            grp = MLDF_REMAP;
            for (idx = 0; idx < 0x4b; idx++)
            {
                if (mapId == grp[idx])
                    break;
            }
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
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 0x20000) == 0) && ((lbl_803DCC80 & 0x80000) == 0))
                    {
                        mergeTableFiles(tbl->mergeBlocks, 0x26, 0x48, 0x800);
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
                    DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, blocksTabReadCb, 2);
                }
                MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 4) == 0) && ((lbl_803DCC80 & 8) == 0))
                        {
                            mergeTableFiles(tbl->mergeModels, 0x2a, 0x45, 0x800);
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
                        DVDReadAsyncPrio(fi, (void*)tmp, MLDF_SP_SIZE(x), 0, modelsReadCb, 2);
                    }
                    MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 4) == 0) && ((lbl_803DCC80 & 8) == 0))
                    {
                        mergeTableFiles(tbl->mergeModels, 0x2a, 0x45, 0x800);
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
                    DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, modelsTabReadCb, 2);
                }
                MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x40) == 0) && ((lbl_803DCC80 & 0x80) == 0))
                        {
                            mergeTableFiles(tbl->mergeAnim, 0x2f, 0x49, 3000);
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
                        DVDReadAsyncPrio(fi, (void*)tmp, MLDF_SP_SIZE(x), 0, animReadCb, 2);
                    }
                    MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 0x40) == 0) && ((lbl_803DCC80 & 0x80) == 0))
                    {
                        mergeTableFiles(tbl->mergeAnim, 0x2f, 0x49, 3000);
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
                    DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animTabReadCb, 2);
                }
                MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x400) == 0) && ((lbl_803DCC80 & 0x800) == 0))
                        {
                            mergeTableFiles(tbl->mergeTex0, 0x24, 0x4e, 0x1000);
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
                        DVDReadAsyncPrio(fi, (void*)tmp, MLDF_SP_SIZE(x), 0, tex0readCb, 2);
                    }
                    MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 0x400) == 0) && ((lbl_803DCC80 & 0x800) == 0))
                    {
                        mergeTableFiles(tbl->mergeTex0, 0x24, 0x4e, 0x1000);
                    }
                }
                else
                {
                    if (slot == 0x24)
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x400;
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex0tab1readCb, 2);
                    }
                    else
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x800;
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex0tab2readCb, 2);
                    }
                }
                MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                tmp = MLDF_SP_PTR(x);
                if (tmp == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, (void*)tmp, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(lbl_803DCC8C, fi);
                        if (((lbl_803DCC80 & 0x4000) == 0) && ((lbl_803DCC80 & 0x8000) == 0))
                        {
                            mergeTableFiles(tbl->mergeTex1, 0x21, 0x4c, 0x1000);
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
                        DVDReadAsyncPrio(fi, (void*)tmp, MLDF_SP_SIZE(x), 0, tex1ReadCb, 2);
                    }
                    MLDF_OWNER_RT(slot) = mapId;
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
            slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
            if (MLDF_SP_PTR(x) != 0)
            {
                mm_free((void*)MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange((void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(lbl_803DCC8C, fi);
                    if (((lbl_803DCC80 & 0x4000) == 0) && ((lbl_803DCC80 & 0x8000) == 0))
                    {
                        mergeTableFiles(tbl->mergeTex1, 0x21, 0x4c, 0x1000);
                    }
                }
                else
                {
                    MLDF_FINFO4(x) = fi;
                    if (slot == 0x21)
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x4000;
                        DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex1tab1readCb, 2);
                    }
                    else
                    {
                        lbl_803DCC80 = lbl_803DCC80 | 0x8000;
                        DVDReadAsyncPrio(fi, (void*)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex1tab2readCb, 2);
                    }
                }
                MLDF_OWNER_RT(slot) = mapId;
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

char sAssetHaltFormat[] = "HALT\t%s\n";
char sRomlistZlbPathFormat[] = "%s.romlist.zlb";

int loadAndDecompressDataFile(int fileId, int destBuf, int offsetFlags, u32 length, u32* sizeOut, int entryIndex,
                              u32 flagBits)
{
    struct MldfTables* tbl = (struct MldfTables*)lbl_80345E10;
    u32 tab0 = 0; /* TAB ptr of the primary slot of the pair, 0 = not ready */
    u32 tab1 = 0; /* TAB ptr of the alternate slot of the pair */
    u8 frame = 0; /* run a full frame per wait iteration once dvd error UI is up */
    u32 hiSel;    /* caller's slot-select bit; cases 0x51/0x4f reuse it as the TAB ptr */
    int entryOff;
    int flags;
    int intr;
    int i;
    int prev;
    u32 slotPtrAddr; /* &tbl->ptrs[fileId], biased +0x6A28 for MLDF_QPTR */
    u32 fileBuf;
    u32 alignedSize;
    int tmp;
    u32 decompSize;
    int entryByteOff;
    u32 qptr;       /* MLDF_QPTR from the guard, reused for the first use of each branch */
    DVDFileInfo buf;

    switch (fileId)
    {
    case 0xd:
        intr = OSDisableInterrupts();
        entryIndex = lbl_803DCC80;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0)
        {
            tab0 = MLDF_PTR(0xe);
        }
        if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0)
        {
            tab1 = MLDF_PTR(0x56);
        }
        hiSel = offsetFlags & 0x80000000;
        if (hiSel != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(intr), entryIndex != 0)
            {
                if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0)
                {
                    tab0 = *(u32*)((char*)&MLDF_PTR(0) + 0x80000000);
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
        else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0)
        {
            while (intr = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(intr), entryIndex != 0)
            {
                if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0)
                {
                    tab1 = MLDF_PTR(0);
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
        if ((offsetFlags & 0x20000000) != 0 && tab1 != 0)
        {
            fileId = 0x55;
        }
        else if (hiSel != 0 && tab0 != 0)
        {
            fileId = 0xd;
        }
        else if (tab0 != 0)
        {
            fileId = 0xd;
        }
        else if (tab1 != 0)
        {
            fileId = 0x55;
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x1b:
        intr = OSDisableInterrupts();
        entryIndex = lbl_803DCC80;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x2000000) == 0 && (entryIndex & 0x1000000) == 0)
        {
            tab0 = MLDF_PTR(0x1a);
        }
        if ((entryIndex & 0x8000000) == 0 && (entryIndex & 0x4000000) == 0)
        {
            tab1 = MLDF_PTR(0x53);
        }
        hiSel = offsetFlags & 0x80000000;
        if (hiSel != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(intr), entryIndex != 0)
            {
                if ((entryIndex & 0x2000000) == 0 && (entryIndex & 0x1000000) == 0)
                {
                    tab0 = MLDF_PTR(0x1a);
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
        else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0)
        {
            while (intr = OSDisableInterrupts(), entryIndex = lbl_803DCC80, OSRestoreInterrupts(intr), entryIndex != 0)
            {
                if ((entryIndex & 0x8000000) == 0 && (entryIndex & 0x4000000) == 0)
                {
                    tab1 = MLDF_PTR(0x53);
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
        if ((offsetFlags & 0x20000000) != 0 && tab1 != 0)
        {
            fileId = 0x54;
        }
        else if (hiSel != 0 && tab0 != 0)
        {
            fileId = 0x1b;
        }
        else if (tab0 != 0)
        {
            fileId = 0x1b;
        }
        else if (tab1 != 0)
        {
            fileId = 0x54;
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x25:
        intr = OSDisableInterrupts();
        entryIndex = lbl_803DCC80;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x20000) == 0 && (entryIndex & 0x10000) == 0)
        {
            tab0 = MLDF_PTR(0x26);
        }
        if ((entryIndex & 0x80000) == 0 && (entryIndex & 0x40000) == 0)
        {
            tab1 = MLDF_PTR(0x48);
        }
        if ((offsetFlags & 0x20000000) != 0 && tab1 != 0)
        {
            fileId = 0x47;
        }
        else if ((offsetFlags & 0x10000000) != 0 && tab0 != 0)
        {
            fileId = 0x25;
        }
        else if (tab0 != 0)
        {
            fileId = 0x25;
        }
        else if (tab1 != 0)
        {
            fileId = 0x47;
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x2b:
        intr = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(intr);
        if ((flags & 4) == 0 && (flags & 1) == 0)
        {
            tab0 = MLDF_PTR(0x2a);
        }
        if ((flags & 8) == 0 && (flags & 2) == 0)
        {
            tab1 = MLDF_PTR(0x45);
        }
        entryOff = offsetFlags & 0x10000000;
        if (entryOff != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(intr), flags != 0)
            {
                if ((flags & 4) == 0 && (flags & 1) == 0)
                {
                    tab0 = MLDF_PTR(0x2a);
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
        else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0)
        {
            while (intr = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(intr), flags != 0)
            {
                if ((flags & 8) == 0 && (flags & 2) == 0)
                {
                    tab1 = MLDF_PTR(0x45);
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
        if (tab1 != 0 && (offsetFlags & 0x20000000) != 0)
        {
            fileId = 0x46;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)tab1)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0)
                {
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
                else if (entryOff < (((int*)(tab1 - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while (entryOff != (((int*)tab1)[prev] & 0xffffff));
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (tab0 != 0 && entryOff != 0)
        {
            fileId = 0x2b;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)tab0)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0)
                {
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
                else if (entryOff < (((int*)(tab0 - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while (entryOff != (((int*)tab0)[prev] & 0xffffff));
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (tab0 != 0)
        {
            fileId = 0x2b;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)tab0)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0)
                {
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
                else if (entryOff < (((int*)(tab0 - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while (entryOff != (((int*)tab0)[prev] & 0xffffff));
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        else if (tab1 != 0)
        {
            fileId = 0x46;
            if (sizeOut != NULL)
            {
                entryOff = ((int*)tab1)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0)
                {
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
                else if (entryOff < (((int*)(tab1 - 4))[entryIndex] & 0xffffff))
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while (entryOff != (((int*)tab1)[prev] & 0xffffff));
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x30:
        intr = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(intr);
        if ((flags & 0x40) == 0 && (flags & 0x10) == 0)
        {
            tab0 = MLDF_PTR(0x2f);
        }
        if ((flags & 0x80) == 0 && (flags & 0x20) == 0)
        {
            tab1 = MLDF_PTR(0x49);
        }
        if ((offsetFlags & 0x10000000) != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(intr), flags != 0)
            {
                if ((flags & 0x40) == 0 && (flags & 0x10) == 0)
                {
                    tab0 = MLDF_PTR(0x2f);
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
        else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0)
        {
            while (intr = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(intr), flags != 0)
            {
                if ((flags & 0x80) == 0 && (flags & 0x20) == 0)
                {
                    tab1 = MLDF_PTR(0x49);
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
                *sizeOut = (((u32*)(tab1 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab1)[entryIndex] & 0xfffffff);
            }
        }
        else if ((offsetFlags & 0x10000000) != 0)
        {
            fileId = 0x30;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(tab0 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab0)[entryIndex] & 0xfffffff);
            }
        }
        else if (tab0 != 0)
        {
            fileId = 0x30;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(tab0 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab0)[entryIndex] & 0xfffffff);
            }
        }
        else if (tab1 != 0)
        {
            fileId = 0x4a;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(tab1 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab1)[entryIndex] & 0xfffffff);
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        if (((u8)flagBits & 1) != 0)
        {
            fileBuf = *(u32*)((fileId << 2) + (u32)&tbl->ptrs[0]) + offsetFlags;
            tmp = return0_8002A5B8(fileBuf);
            if (tmp != 0)
            {
                *sizeOut = ObjModel_GetUnpackedResourceSize((u8*)fileBuf, *sizeOut);
            }
        }
        break;
    case 0x51:
        hiSel = MLDF_PTR(0x52);
        if (hiSel != 0)
        {
            fileId = 0x51;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(hiSel + 4))[entryIndex] & 0xfffffff) - (((u32*)hiSel)[entryIndex] & 0xfffffff);
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        if (((u8)flagBits & 1) != 0)
        {
            fileBuf = *(u32*)((fileId << 2) + (u32)&tbl->ptrs[0]) + offsetFlags;
            tmp = return0_8002A5B8(fileBuf);
            if (tmp != 0)
            {
                *sizeOut = ObjModel_GetUnpackedResourceSize((u8*)fileBuf, *sizeOut);
            }
        }
        break;
    case 0x23:
        intr = OSDisableInterrupts();
        i = lbl_803DCC80;
        OSRestoreInterrupts(intr);
        if ((i & 0x100) == 0 && (i & 0x100) == 0)
        {
            tab0 = MLDF_PTR(0x24);
        }
        if ((i & 0x800) == 0 && (i & 0x200) == 0)
        {
            tab1 = MLDF_PTR(0x4e);
        }
        if ((offsetFlags & 0x40000000) != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), i = lbl_803DCC80, OSRestoreInterrupts(intr), i != 0)
            {
                if ((i & 0x100) == 0 && (i & 0x100) == 0)
                {
                    tab0 = MLDF_PTR(0x24);
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
        else if ((offsetFlags & 0x80000000) != 0 && tab1 == 0)
        {
            while (intr = OSDisableInterrupts(), i = lbl_803DCC80, OSRestoreInterrupts(intr), i != 0)
            {
                if ((i & 0x800) == 0 && (i & 0x200) == 0)
                {
                    tab1 = MLDF_PTR(0x4e);
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
        if (tab1 != 0 &&
            (entryByteOff = entryIndex << 2, (*(u32*)((u8*)tbl->mergeTex0 + entryByteOff) & 0x80000000) != 0))
        {
            fileId = 0x4d;
            if (sizeOut != NULL)
            {
                offsetFlags = *(int*)((u8*)tab1 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        else if (tab0 != 0 &&
                 (entryByteOff = entryIndex << 2, (*(int*)((u8*)tbl->mergeTex0 + entryByteOff) & 0x40000000) != 0))
        {
            fileId = 0x23;
            if (sizeOut != NULL)
            {
                offsetFlags = *(int*)((u8*)tab0 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        else if (tab1 != 0)
        {
            fileId = 0x4d;
            if (sizeOut != NULL)
            {
                offsetFlags = ((int*)tab1)[entryIndex] & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        else if (tab0 != 0)
        {
            fileId = 0x23;
            if (sizeOut != NULL)
            {
                offsetFlags = ((int*)tab0)[entryIndex] & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x20:
        intr = OSDisableInterrupts();
        i = lbl_803DCC80;
        OSRestoreInterrupts(intr);
        if ((i & 0x4000) == 0 && (i & 0x1000) == 0)
        {
            tab0 = MLDF_PTR(0x21);
        }
        if ((i & 0x8000) == 0 && (i & 0x2000) == 0)
        {
            tab1 = MLDF_PTR(0x4c);
        }
        if ((offsetFlags & 0x40000000) != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), i = lbl_803DCC80, OSRestoreInterrupts(intr), i != 0)
            {
                if ((i & 0x1000) == 0 && (i & 0x1000) == 0)
                {
                    tab0 = MLDF_PTR(0x21);
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
        else if ((offsetFlags & 0x80000000) != 0 && tab1 == 0)
        {
            while (intr = OSDisableInterrupts(), i = lbl_803DCC80, OSRestoreInterrupts(intr), i != 0)
            {
                if ((i & 0x8000) == 0 && (i & 0x2000) == 0)
                {
                    tab1 = MLDF_PTR(0x4c);
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
        if (tab1 != 0 &&
            (entryByteOff = entryIndex << 2, (*(u32*)((u8*)tbl->mergeTex1 + entryByteOff) & 0x80000000) != 0))
        {
            fileId = 0x4b;
            if (sizeOut != NULL)
            {
                offsetFlags = *(int*)((u8*)tab1 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        else if (tab0 != 0 &&
                 (entryByteOff = entryIndex << 2, (*(int*)((u8*)tbl->mergeTex1 + entryByteOff) & 0x40000000) != 0))
        {
            fileId = 0x20;
            if (sizeOut != NULL)
            {
                offsetFlags = *(int*)((u8*)tab0 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        else if (tab1 != 0)
        {
            fileId = 0x4b;
            if (sizeOut != NULL)
            {
                offsetFlags = ((int*)tab1)[entryIndex] & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        else if (tab0 != 0)
        {
            fileId = 0x20;
            if (sizeOut != NULL)
            {
                offsetFlags = ((int*)tab0)[entryIndex] & 0xffffff;
                if (offsetFlags == 0)
                {
                    i = 0;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    case 0x4f:
        hiSel = MLDF_PTR(0x50);
        if (hiSel != 0)
        {
            fileId = 0x4f;
            if (sizeOut != NULL)
            {
                offsetFlags = ((int*)hiSel)[entryIndex] & 0xffffff;
                if (offsetFlags == 0)
                {
                    do
                    {
                        prev = tab0;
                        tab0 = tab0 + 1;
                    } while ((((int*)hiSel)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(hiSel - 4))[tab0] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)hiSel)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(hiSel - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    }
    if (((u8)flagBits & 1) != 0)
    {
        return 0;
    }
    slotPtrAddr = (fileId << 2) + ((u32)&tbl->ptrs[0] + 0x6A28);
    qptr = MLDF_QPTR;
    if (qptr != 0)
    {
        if (fileId == 0xd || fileId == 0x55)
        {
            if (qptr == 0)
            {
                return 0;
            }
            memcpy((void*)destBuf, (void*)(qptr + offsetFlags), length);
        }
        else if (fileId == 0x1b || fileId == 0x54)
        {
            if (qptr == 0)
            {
                return 0;
            }
            fileBuf = qptr + offsetFlags;
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0)
            {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + (offsetFlags + 0x10)), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange((void*)destBuf, decompSize);
            }
            else
            {
                return 0;
            }
        }
        else if (fileId == 0x25 || fileId == 0x47)
        {
            if (qptr == 0)
            {
                return 0;
            }
            fileBuf = qptr + offsetFlags;
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0)
            {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + (offsetFlags + 0x10)), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange((void*)destBuf, decompSize);
            }
            else
            {
                return 0;
            }
        }
        else if (fileId == 0x2b || fileId == 0x46)
        {
            struct PackHeader* hdr = (struct PackHeader*)(qptr + offsetFlags);
            if (hdr->magic == 0xe0e0e0e0)
            {
                memcpy((void*)destBuf, (void*)(qptr + (hdr->auxSize + (int)hdr - qptr + 0x18)), hdr->decompressedSize);
            }
            else if (hdr->magic == 0xfacefeed)
            {
                zlbDecompress((u8*)(qptr + (hdr->auxSize + (int)hdr - qptr + 0x28)), hdr->compressedSize - 0x10,
                              (u8*)destBuf, &hdr->decompressedSize);
                DCStoreRange((void*)destBuf, hdr->decompressedSize);
            }
        }
        else if (fileId == 0x23 || fileId == 0x4d)
        {
            fileBuf = qptr + (offsetFlags & 0xffffff);
            decompSize = ZLB_HDR(fileBuf)->decompressedSize;
            zlbDecompress((u8*)(fileBuf + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf, &decompSize);
            DCStoreRange((void*)destBuf, decompSize);
        }
        else if (fileId == 0x20 || fileId == 0x4b)
        {
            entryIndex = offsetFlags & 0xffffff;
            fileBuf = qptr + entryIndex;
            if (strncmp(sDirBlockTag, (char*)fileBuf, 3) == 0)
            {
                return MLDF_QPTR + (entryIndex + 0x20);
            }
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0)
            {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + (entryIndex + 0x10)), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange((void*)destBuf, decompSize);
            }
        }
        else if (fileId == 0x4f)
        {
            entryIndex = offsetFlags & 0xffffff;
            fileBuf = qptr + entryIndex;
            if (strncmp(sDirBlockTag, (char*)fileBuf, 3) == 0)
            {
                return MLDF_QPTR + (entryIndex + 0x20);
            }
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0)
            {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + (entryIndex + 0x10)), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange((void*)destBuf, decompSize);
            }
        }
        else if (fileId == 0x30 || fileId == 0x51 || fileId == 0x4a)
        {
            fileBuf = qptr + offsetFlags;
            tmp = return0_8002A5B8(fileBuf);
            if (tmp != 0)
            {
                ObjModel_UnpackResourcePayload((u8*)fileBuf, *sizeOut, (u8*)destBuf,
                                               ObjModel_GetUnpackedResourceSize((u8*)fileBuf, *sizeOut));
            }
            else
            {
                memcpy((void*)destBuf, (void*)(MLDF_QPTR + offsetFlags), length);
            }
        }
        else
        {
            memcpy((void*)destBuf, (void*)(qptr + offsetFlags), length);
        }
    }
    else if (fileId == 0x20 || fileId == 0x4b)
    {
        DVDOpen(sResourceFileNameTable[fileId], &buf);
        alignedSize = (length + 0x1f) & 0xffffffe0;
        fileBuf = (u32)mmAlloc(alignedSize, 0x7f7f7fff, 0);
        DVDRead(&buf, (void*)fileBuf, alignedSize, offsetFlags & 0xffffff);
        DVDClose(&buf);
        DCStoreRange((void*)fileBuf, length);
        if (strncmp(sDirBlockTag, (char*)fileBuf, 3) == 0)
        {
            for (;;)
            {
            }
        }
        if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0)
        {
            decompSize = ZLB_HDR(fileBuf)->decompressedSize;
            zlbDecompress((u8*)(fileBuf + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf, &decompSize);
        }
        mm_free((void*)fileBuf);
    }
    else
    {
        DVDOpen(sResourceFileNameTable[fileId], &buf);
        if (((u32)destBuf & 0x1f) != 0 || ((int)length & 0x1f) != 0)
        {
            alignedSize = (length + 0x1f) & 0xffffffe0;
            tmp = (int)mmAlloc(alignedSize, 0x7f7f7fff, 0);
            DVDRead(&buf, (void*)tmp, alignedSize, offsetFlags);
            memcpy((void*)destBuf, (void*)tmp, length);
            mm_free((void*)tmp);
        }
        else
        {
            DVDRead(&buf, (void*)destBuf, length, offsetFlags);
        }
        DCStoreRange((void*)destBuf, length);
        DVDClose(&buf);
    }
    return 0;
}

extern int lbl_8035F208[];
extern u32 lbl_8035F3E8[];
extern int lbl_803DCC74;


int mapGetDirIdx(int idx)
{
    if (idx >= 0x4b)
        return 5;
    return sMapFileNameIndexRemapTable[idx];
}


extern int lbl_8035EF48[];
extern s16 lbl_803DCC78;

void loadDataFiles()
{
    int i;
    if (getButtonsJustPressed(2) & PAD_BUTTON_A)
    {
        int vi = 0x4F;
        vi++;
        for (; vi < 0x57; vi++)
        {
        }
        printHeapStats(1);
    }
    if (getButtonsJustPressed(2) & PAD_BUTTON_B)
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
    for (i = 0; i <= 0x57; i++)
    {
        if (lbl_8035EF48[i] != -1)
        {
            debugPrintSetColor(0, 0xff, 0, 0xff);
            logPrintf(sAssetHaltFormat, sResourceFileNameTable[i]);
            debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
            lbl_803DCC70 = 1;
            if (mapLoadDataFile(lbl_8035EF48[i], i) != 0)
            {
                lbl_8035EF48[i] = -1;
                printHeapStats(1);
            }
            lbl_803DCC70 = 0;
        }
    }
    loadTableFiles();
}
void piRomLoadSection(int romOffset, int mapIndex, int destBuf)
{
    char buf[1024];
    DVDFileInfo* fi;
    int ok;
    struct PackHeader* hdr;

    if (((void*)destBuf == NULL) && ((void*)lbl_8035F208[mapIndex] == NULL))
    {
        sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
        fi = AtomicSList_Pop(lbl_803DCC8C);
        ok = DVDOpen(buf, fi);
        if (ok != 0)
        {
            lbl_8035F208[mapIndex] = (int)mmAlloc(DVD_FI_LENGTH(fi), 0x7d7d7d7d, 0);
            lbl_803DCC74 = 1;
            DVDReadAsyncPrio(fi, (void*)lbl_8035F208[mapIndex], DVD_FI_LENGTH(fi), 0, romListReadCb, 2);
        }
    }
    else
    {
        if ((void*)lbl_8035F208[mapIndex] == NULL)
        {
            sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
            fi = AtomicSList_Pop(lbl_803DCC8C);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return;
            }
            lbl_8035F208[mapIndex] = (int)mmAlloc(DVD_FI_LENGTH(fi), 0x7d7d7d7d, 0);
            DVDRead(fi, (void*)lbl_8035F208[mapIndex], DVD_FI_LENGTH(fi), 0);
            DVDClose(fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
        }
        hdr = (struct PackHeader*)(lbl_8035F3E8[0x1d] + romOffset);
        if (hdr->magic == 0xfacefeed)
        {
            zlbDecompress((u8*)(lbl_8035F208[mapIndex] + 0x10), hdr->compressedSize, (u8*)destBuf, &hdr->decompressedSize);
            DCStoreRange((void*)destBuf, hdr->decompressedSize);
        }
    }
}

void tex1GetFrame(int texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode)
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
                    if (strncmp(sDirBlockTag, (char*)e, 3) == 0)
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
                DVDFileInfo fileInfo;
                int v;
                char* buf;
                DVDOpen(sResourceFileNameTable[idx], &fileInfo);
                buf = mmAlloc(0x400, 0x7f7f7fff, 0);
                DVDRead(&fileInfo, buf, 0x400, (texId & 0xffffff) * 2);
                DVDClose(&fileInfo);
                DCStoreRange(buf, 0x400);
                if (queryMode == 1 && frameTable != 0)
                {
                    int e = *(int*)(frameTable + count * 4);
                    int v;
                    e = (int)buf + e + 4;
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
                    if (strncmp(sDirBlockTag, buf, 3) == 0)
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

extern f32 lbl_803DEAC8;

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


void texPreGetMipmap(int texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode)
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
            if (strncmp(sDirBlockTag, (char*)e, 3) == 0)
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

void loadModelsBin(int offsetFlags, int* p1c, int* p20, int* p18, int* p4, int wpad0)
{
    u32 tab0 = 0;
    u32 tab1 = 0;
    int idx = -1;
    int flags;
    int saved;
    char* entry;
    if (lbl_8035F3E8[0x2b] != 0 || lbl_8035F3E8[0x46] != 0)
    {
        saved = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(saved);
        if ((flags & 4) == 0 && (flags & 1) == 0)
        {
            tab0 = lbl_8035F3E8[0x2a];
        }
        if ((flags & 8) == 0 && (flags & 2) == 0)
        {
            tab1 = lbl_8035F3E8[0x45];
        }
        if (tab1 != 0 && (offsetFlags & 0x20000000) != 0)
        {
            idx = 0x46;
        }
        else if (tab0 != 0 && (offsetFlags & 0x10000000) != 0)
        {
            idx = 0x2b;
        }
        else if (tab0 != 0)
        {
            idx = 0x2b;
        }
        else if (tab1 != 0)
        {
            idx = 0x46;
        }
        entry = (char*)lbl_8035F3E8[idx] + (offsetFlags & 0x0fffffff);
        *p18 = *(int*)(entry + 0x18);
        *p1c = *(int*)(entry + 0x1c);
        *p20 = *(int*)(entry + 0x20);
        *p4 = *(int*)(entry + 0x4);
    }
}


/* base+0x74 / base+0x78 are lbl_8035F3E8[0x1d]/[0x1e] (MldfTables.ptrs: maps info
   bin/tab); the byte-offset spelling is codegen-load-bearing */
void mapsBinGetRomlistSize(int idx, int* out1, int* out2, int* out3, int p5)
{
    char* base = (char*)lbl_8035F3E8;
    char* e;
    if (*(void**)(base + 0x74) == NULL)
        return;
    if (*(void**)(base + 0x78) == NULL)
        return;
    e = *(char**)(base + 0x74) + idx;
    *out1 = *(s16*)(e + 0x1c);
    *out2 = *(s16*)(e + 0x1e);
    *out3 = *(int*)(*(char**)(base + 0x74) + *(int*)(*(char**)(base + 0x78) + p5 * 4 + 0x18) + 4);
}

void checkLoadBlock(int a, int* pc, int* p8)
{
    int idx = -1;
    int flags;
    int saved;
    char* blk;
    u32 t25, t47;
    if ((lbl_8035F3E8[0x26] != 0 && lbl_8035F3E8[0x25] != 0) || (lbl_8035F3E8[0x48] != 0 && lbl_8035F3E8[0x47] != 0))
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
        if (strncmp(blk, sZlbBlockTag, 3) != 0)
        {
            *p8 = 0;
            *pc = 0;
        }
        else
        {
            {
                int vc = ZLB_HDR(blk)->compressedSize;
                *p8 = ZLB_HDR(blk)->decompressedSize;
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
    if ((lbl_8035F3E8[0x1a] != 0 && lbl_8035F3E8[0x1b] != 0) || (lbl_8035F3E8[0x53] != 0 && lbl_8035F3E8[0x54] != 0))
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
            if (strncmp(blk, sZlbBlockTag, 3) != 0)
            {
                *p8 = 0;
                *pc = 0;
            }
            else
            {
                {
                    int vc = ZLB_HDR(blk)->compressedSize;
                    *p8 = ZLB_HDR(blk)->decompressedSize;
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

extern u32 lbl_8035F0A8[];

s32 getDataFileSize(int idx)
{
    if (lbl_8035F3E8[idx] != 0)
    {
        return lbl_8035F0A8[idx];
    }
    *(u8*)0 = 0;
    return 0;
}
int fileLoadToBufferOffset(int id, void* buffer, int offset, int size)
{
    DVDFileInfo fileInfo;
    int asize;
    void* tmp;
    if (size == 0)
        return 0;
    if (lbl_8035F3E8[id] != 0)
    {
        {
            int base = lbl_8035F3E8[id];
            memcpy(buffer, (void*)(base + offset), size);
        }
        DCStoreRange(buffer, size);
        return size;
    }
    DVDOpen(sResourceFileNameTable[id], &fileInfo);
    if (((int)buffer & 0x1fu) != 0 || (size & 0x1f) != 0)
    {
        asize = (size + 0x1f) & ~0x1f;
        tmp = mmAlloc(asize, 0x7d7d7d7d, 0);
        DCInvalidateRange(tmp, asize);
        DVDRead(&fileInfo, tmp, asize, offset);
        memcpy(buffer, tmp, size);
        mm_free(tmp);
    }
    else
    {
        DCInvalidateRange(buffer, size);
        DVDRead(&fileInfo, buffer, size, offset);
    }
    DVDClose(&fileInfo);
    DCStoreRange(buffer, size);
    return size;
}

int fileLoadToBuffer(int id, void* buffer)
{
    DVDFileInfo fileInfo;
    if (lbl_8035F3E8[id] != 0)
    {
        memcpy(buffer, (void*)lbl_8035F3E8[id], lbl_8035F0A8[id]);
        DCStoreRange(buffer, lbl_8035F0A8[id]);
        return lbl_8035F0A8[id];
    }
    DVDOpen(sResourceFileNameTable[id], &fileInfo);
    DCInvalidateRange(buffer, fileInfo.length);
    DVDRead(&fileInfo, buffer, fileInfo.length, 0);
    DVDClose(&fileInfo);
    return fileInfo.length;
}

void* fileLoad(int id, int wpad0)
{
    DVDFileInfo fileInfo;
    if (lbl_8035F3E8[id] != 0)
    {
        return (void*)lbl_8035F3E8[id];
    }
    DVDOpen(sResourceFileNameTable[id], &fileInfo);
    lbl_8035F0A8[id] = fileInfo.length;
    lbl_8035F3E8[id] = (u32)mmAlloc(lbl_8035F0A8[id] + 0x20, 0x7d7d7d7d, 0);
    DCInvalidateRange((void*)lbl_8035F3E8[id], lbl_8035F0A8[id]);
    DVDRead(&fileInfo, (void*)lbl_8035F3E8[id], lbl_8035F0A8[id], 0);
    DVDClose(&fileInfo);
    return (void*)lbl_8035F3E8[id];
}

u8 initLoadFiles(void)
{
    int i;
    DVDFileInfo* fileInfo;
    int* rom;
    struct MldfIterators it;
    u8* himem;
    struct MldfTables* tbl = (struct MldfTables*)lbl_80345E10;
    if (lbl_803DCC90 == 0)
    {
        lbl_803DCC90 = 1;
        lbl_803DCC88 = 0;
        lbl_803DCC8C = stackCreate(0x5e, 0x40);
        i = 0;
        rom = (int*)((MldfArenaBlock*)tbl + 1) - MLDF_ROM_LIST_WORDS_FROM_ARENA_END;
        for (; i < 0x75; rom++, i++)
        {
            *rom = 0;
            if (i >= 0x50 || i == 0x49 || ((i == 0x43) | (i == 5)))
            {
                piRomLoadSection(0, i, 0);
            }
        }
        lbl_803DCC98 = 0;
        for (i = 0,
             himem = (u8*)tbl + 0x20000,
             it.ptrs = (void**)(himem - 27176),
             it.owners = (s16*)(himem - 26824),
             it.ids = (int*)(himem - 28360),
             it.names = sResourceFileNameTable,
             it.sizes = (int*)(himem - 28008),
             it.flags = himem - 28448;
             i <= 0x57;
             it.ptrs++, it.owners++, it.ids++, it.names++, it.sizes++, it.flags++, i++)
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
                *it.ptrs = 0;
                *it.owners = -1;
                *it.ids = -1;
                break;
            default:
                if (*it.ptrs == 0)
                {
                    fileInfo = AtomicSList_Pop(lbl_803DCC8C);
                    DVDOpen(*it.names, fileInfo);
                    *it.sizes = fileInfo->length;
                    *it.ptrs = mmAlloc(*it.sizes + 0x20, 0x7d7d7d7d, 0);
                    lbl_803DCC88 = lbl_803DCC88 + 1;
                    DVDReadAsyncPrio(fileInfo, *it.ptrs, *it.sizes, 0, dvdReadCb_80041d30, 2);
                }
                *it.owners = -1;
                *it.ids = -1;
                break;
            }
            *it.flags = 0;
        }
    }
    if (lbl_803DCC88 == 0)
    {
        if (((lbl_803DCC80 & 0x100) == 0 || (lbl_803DCC80 & 0x400) == 0) &&
            ((lbl_803DCC84 & 0x100) == 0 || (lbl_803DCC84 & 0x400) == 0))
        {
            int saved = testAndSet_onlyUseHeap3(0);
            mapLoadDataFile(5, MLDF_FILEID_TEX0_BIN_A);
            mapLoadDataFile(5, MLDF_FILEID_TEX0_TAB_A);
            testAndSet_onlyUseHeap3(saved);
        }
        else if ((lbl_803DCC84 & 0x100) != 0 && (lbl_803DCC84 & 0x400) != 0)
        {
            mergeTableFiles(tbl->mergeModels, 0x2a, 0x45, 0x800);
            mergeTableFiles(tbl->mergeAnim, 0x2f, 0x49, 3000);
            mergeTableFiles(tbl->mergeTex0, 0x24, 0x4e, 0x1000);
            mergeTableFiles(tbl->mergeTex1, 0x21, 0x4c, 0x1000);
            mergeTableFiles(tbl->mergeBlocks, 0x26, 0x48, 0x800);
            lbl_803DCC84 = 0;
            lbl_803DCC80 = 0;
            return 1;
        }
    }
    return 0;
}
void tvInit(void)
{
    gRenderModeObj->viWidth = 0x294;
    gRenderModeObj->viXOrigin -= 0xa;
    VIConfigure(gRenderModeObj);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
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

extern u8 enableDebugText;

void gpuErrorHandler(u32 retraceCount)
{
    char* strs = (char*)gLoadingScreenTextures;
    int tok[3];
    u32 botClks;
    u32 botPerf0;
    u32 botClks2;
    u32 botPerf1;
    u32 topClks;
    u32 topPerf0;
    u32 topClks2;
    u32 topPerf1;
    u8 cmdRdy;
    u8 readIdle;
    u8 fifoErr;
    u32 xfStuck;
    u32 cmdStuck;
    u32 rdIdle;
    u32 cmdIdle;

    if (lbl_803DCCA8 != 0 && lbl_803DCCA9 != 0)
    {
        Queue_Pop(&lbl_8035F730, tok);
        lbl_803DCCAC = 0;
        OSWakeupThread((OSThreadQueue*)&lbl_803DCCC4);
        if (Queue_IsEmpty(&lbl_8035F730) != 0)
        {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
        else
        {
            Queue_Peek(&lbl_8035F730, tok);
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
    if (enableDebugText != 0 && lbl_803DCCDC != NULL && (u32)lbl_803DCCAC > 600)
    {
        debugPrintfxy(0x32, 100, strs + 0x40000);
        GXReadXfRasMetric(&botPerf0, &botClks, &botPerf1, &botClks2);
        GXReadXfRasMetric(&topPerf0, &topClks, &topPerf1, &topClks2);
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
        else if (cmdRdy != 0 && readIdle != 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0 && cmdIdle != 0)
        {
            debugPrintfxy(0x32, 0x8c, strs + 0x400b4);
        }
        else
        {
            debugPrintfxy(0x32, 0x8c, strs + 0x400e4);
        }
        debugPrintfxy(0x32, 0xa0, sProgramCounterFormat, lbl_803DCCDC->context.srr0);
    }
}
void logGpuHang(void);

void videoSwapFrameBuffers(u32 retraceCount)
{
    u16 sync;
    int tok[3];
    GXFifoObj fifo;

    lbl_803DCCA0 = lbl_803DCCA0 + 1;
    sync = GXReadDrawSync();
    if (sync == (u16)(lbl_803DCCAA + 1))
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
    if (lbl_803DCCB0 != 0 && (u32)lbl_803DCCAC > 18000)
    {
        logGpuHang();
        gxErrorFn_80060b40();
        modelFn_800292e0();
        __GXAbortWaitPECopyDone();
        GXInitFifoBase(&fifo, renderFrameBuffer, 0x10000);
        GXSetCPUFifo(&fifo);
        GXSetGPFifo(&fifo);
        lbl_803DCCD4 = GXInit(lbl_803DCCD8, (u32)lbl_803DCCE4);
        if (Queue_IsEmpty(&lbl_8035F730) == 0)
        {
            Queue_Pop(&lbl_8035F730, tok);
        }
        OSWakeupThread((OSThreadQueue*)&lbl_803DCCC4);
        if (Queue_IsEmpty(&lbl_8035F730) != 0)
        {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
        else
        {
            Queue_Peek(&lbl_8035F730, tok);
            GXEnableBreakPt((void*)tok[0]);
        }
        gxPerfFn_8004a77c(1);
    }
}

void videoFn_800499e8(void)
{
    char peek[12];
    int tok[3];
    int i;

    if (gAttractMovieState == 2 || gAttractMovieState == 3)
    {
        THPPlayerPostDrawDone();
    }
    Queue_Peek(&lbl_8035F730, &peek);
    for (i = 0; i < (int)(u32)gDepthReadPendingCount; i++)
    {
        gDepthReadResults[i].x = gDepthReadPendingQueue[i].x;
        gDepthReadResults[i].y = gDepthReadPendingQueue[i].y;
        gDepthReadResults[i].key = gDepthReadPendingQueue[i].key;
        GXPeekZ(gDepthReadResults[i].x, gDepthReadResults[i].y, &gDepthReadResults[i].value);
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
        Queue_Pop(&lbl_8035F730, tok);
        lbl_803DCCAC = 0;
        OSWakeupThread((OSThreadQueue*)&lbl_803DCCC4);
        if (Queue_IsEmpty(&lbl_8035F730) != 0)
        {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
        else
        {
            Queue_Peek(&lbl_8035F730, tok);
            GXEnableBreakPt((void*)tok[0]);
            lbl_803DCCA7 = 1;
        }
    }
}

extern f32 lbl_803DEA70;
extern f32 lbl_803DEA78;
extern f32 lbl_803DEA88;
extern f32 lbl_803DEA8C;
extern f32 lbl_803DEA90;
extern Mtx44 hudMatrix;

void initViewport(void)
{
    C_MTXOrtho(hudMatrix, lbl_803DEA70, lbl_803DEA88, *(f32*)&lbl_803DEA70, lbl_803DEA8C, lbl_803DEA78, lbl_803DEA90);
}
void videoInit(void* wpad0, int wpad1)
{
    GXFifoObj fifo;
    f32 mtx[3][4];
    GXColor cc;
    u32 lo;
    u32 hi;
    u32 next;
    int fbSize;
    lo = (u32)OSGetArenaLo();
    hi = (u32)OSGetArenaHi();
    memcpy((void*)(hi - 0x40000), gLoadingScreenTextures, 0x40000);
    DCStoreRange((void*)(hi - 0x40000), 0x40000);
    fbSize = 0x40000;
    lbl_803DCCE4 = (void*)fbSize;
    lbl_803DCCD8 = gLoadingScreenTextures;
    DCInvalidateRange((char*)gLoadingScreenTextures, fbSize);
    lbl_803DCCD4 = GXInit(lbl_803DCCD8, (u32)lbl_803DCCE4);
    lbl_803DCCE0 = lbl_803DCCD8;
    GXSetDispCopySrc(0, 0, gRenderModeObj->fbWidth, gRenderModeObj->efbHeight);
    lbl_803DCCB8 = GXSetDispCopyYScale((f32)gRenderModeObj->xfbHeight / gRenderModeObj->efbHeight);
    fbSize = (u16)((gRenderModeObj->fbWidth + 0xf) & ~0xf) * lbl_803DCCB8 * 2;
    externalFrameBuffer0 = (void*)((lo + 0x1f) & ~0x1f);
    fbSize += 0x1f;
    externalFrameBuffer1 = (void*)(((u32)externalFrameBuffer0 + fbSize) & ~0x1f);
    next = ((u32)externalFrameBuffer1 + fbSize) & ~0x1f;
    OSSetArenaLo((void*)next);
    OSSetArenaLo((void*)(lo = (u32)OSInitAlloc((void*)next, (void*)hi, 1)));
    lo = (lo + 0x1f) & ~0x1f;
    hi = hi & ~0x1f;
    OSSetCurrentHeap(OSCreateHeap((void*)lo, (void*)hi));
    VIConfigure(gRenderModeObj);
    GXInitFifoBase(&fifo, externalFrameBuffer0, 0x10000);
    GXSetCPUFifo(&fifo);
    GXSetGPFifo(&fifo);
    GXInitFifoLimits(lbl_803DCCD4, (u32)lbl_803DCCE4 - 0x4000, (u32)((u32)lbl_803DCCE4 * 3) >> 2);
    GXSetCPUFifo(lbl_803DCCD4);
    GXSetGPFifo(lbl_803DCCD4);
    Queue_Init(&lbl_8035F730, lbl_8035F6B8, 10, 0xc);
    OSInitThreadQueue((OSThreadQueue*)&lbl_803DCCC4);
    VISetPreRetraceCallback(videoSwapFrameBuffers);
    VISetPostRetraceCallback(gpuErrorHandler);
    GXSetBreakPtCallback(videoFn_800499e8);
    GXSetViewport(lbl_803DEA70, lbl_803DEA70, gRenderModeObj->fbWidth, gRenderModeObj->xfbHeight, lbl_803DEA70,
                  lbl_803DEA78);
    GXSetFieldMode(gRenderModeObj->field_rendering, gRenderModeObj->xfbHeight < gRenderModeObj->viHeight);
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
    GXSetDispCopyGamma(GX_GM_1_0);
    VISetBlack(1);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetVtxAttrFmt(GX_VTXFMT0, GX_VA_POS, GX_POS_XYZ, GX_S16, 0);
    GXSetVtxAttrFmt(GX_VTXFMT0, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT0, GX_VA_TEX0, GX_TEX_ST, GX_S16, 7);
    GXSetVtxAttrFmt(GX_VTXFMT1, GX_VA_POS, GX_POS_XYZ, GX_S16, 2);
    GXSetVtxAttrFmt(GX_VTXFMT1, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT1, GX_VA_TEX0, GX_TEX_ST, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_POS, GX_POS_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_NRM, GX_NRM_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_TEX0, GX_TEX_ST, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_TEX1, GX_TEX_ST, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_POS, GX_POS_XYZ, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_NBT, GX_NRM_NBT, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX0, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX1, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX2, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX3, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_POS, GX_POS_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_TEX0, GX_TEX_ST, GX_S16, 7);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_NRM, GX_NRM_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_POS, GX_POS_XYZ, GX_S16, 3);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_NRM, GX_NRM_XYZ, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX0, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX1, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX2, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX3, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_POS, GX_POS_XYZ, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_NRM, GX_NRM_XYZ, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX0, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX1, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX2, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX3, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_POS, GX_POS_XYZ, GX_S16, 0);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_NRM, GX_NRM_XYZ, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX0, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX1, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX2, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX3, GX_TEX_ST, GX_S16, 10);
    lbl_803DCCF4 = 0;
    GXSetCullMode(GX_CULL_NONE);
    cc = *(GXColor*)&lbl_803DB5D0;
    GXSetCopyClear(cc, 0xffffff);
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    GXSetNumChans(1);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    lbl_803DCD00 = 1;
    lbl_803DCCFC = 3;
    lbl_803DCCF8 = 1;
    gxSetZMode_(1, GX_LEQUAL, 1);
    gxSetPeControl_ZCompLoc_(1);
    GXEnableTexOffsets(0, 1, 1);
    PSMTXIdentity(mtx);
    GXLoadPosMtxImm(mtx, GX_PNMTX0);
    GXLoadTexMtxImm(mtx, GX_TEXMTX0, GX_MTX3x4);
    GXLoadTexMtxImm(mtx, GX_TEXMTX1, GX_MTX3x4);
    GXSetCurrentMtx(GX_PNMTX0);
    C_MTXOrtho(hudMatrix, lbl_803DEA94, lbl_803DEA98, lbl_803DEA70, lbl_803DEA8C, lbl_803DEA78, lbl_803DEA90);
    GXSetMisc(GX_MT_XF_FLUSH, 8);
    PPCMtmsr(PPCMfmsr() | MSR_PM);
    PPCMthid0(PPCMfhid0() | HID0_SPD);
}

void setColor_803db5d0(u8 r, u8 g, u8 b)
{
    lbl_803DB5D0[0] = r;
    lbl_803DB5D0[1] = g;
    lbl_803DB5D0[2] = b;
}

extern int lbl_803DCD88;
extern int lbl_803DCD8C;
extern int lbl_803DCD90;
extern u8 lbl_803DCD6A;
void setDisplayCopyFilter(void)
{
    GXRenderModeObj* renderMode = gRenderModeObj;
    if (renderMode == &GXNtsc480Prog || renderMode->field_rendering != 0)
    {
        GXSetCopyFilter(renderMode->aa, renderMode->sample_pattern, GX_FALSE, renderMode->vfilter);
    }
    else
    {
        GXSetCopyFilter(renderMode->aa, renderMode->sample_pattern, GX_TRUE, lbl_803DB5D4);
    }
}


int GXFlush_(u8 visible, int unused)
{
    void* fifo_get;
    void* fifo_put;
    void* item[3];
    int s;
    void* next;
    gxSetZMode_(1, GX_LEQUAL, 1);
    GXSetAlphaUpdate(GX_TRUE);
    GXFlush();
    GXGetFifoPtrs(lbl_803DCCD4, &fifo_get, &fifo_put);
    item[0] = fifo_put;
    item[1] = 0;
    item[2] = renderFrameBuffer;
    s = OSDisableInterrupts();
    Queue_Push(&lbl_8035F730, item);
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



void viFn_8004a56c(int val)
{
    int v = val;
    VISetBlack(1);
    VIFlush();
    lbl_803DB5CC = v;
}
void logGpuHang(void)
{
    char* strs = (char*)gLoadingScreenTextures;
    u32 topClks, topPerf0, topClks2, topPerf1;
    u32 botClks, botPerf0, botClks2, botPerf1;
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
    else if (cmdRdy != 0 && readIdle != 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0 && cmdIdle != 0)
    {
        OSReport(strs + 0x4016c);
    }
    else
    {
        OSReport(strs + 0x4019c);
    }
}
void gxTransformFn_8004a83c(void)
{
    lbl_803DCCB0 = 0;
    gxPerfFn_8004a77c(0);
}

void gxPerfFn_8004a77c(int enabled)
{
    if ((u8)enabled != 0)
    {
        GXSetGPMetric(GX_PERF0_NONE, GX_PERF1_NONE);
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

extern char sThreadStateAttrSuspendFormat[];

void waitNextFrame(void)
{
    int lvl;
    u32 frames;

    OSStopStopwatch(&lbl_8035F680);
    lbl_803DCCC0 = OSCheckStopwatch(&lbl_8035F680) / (f32)(u32)((*(u32*)0x800000f8 >> 2) / 1000);
    OSResetStopwatch(&lbl_8035F680);
    OSStartStopwatch(&lbl_8035F680);
    timeDelta = physicsTimeScale * (lbl_803DEAA0 * lbl_803DCCC0);
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
    framesThisStep = frames;
    lbl_803DCCB4 = (timeDelta + lbl_803DCCB4) - (f32)(u32)framesThisStep;
    lbl_803DB411 = frames;
    if (framesThisStep < 1)
    {
        framesThisStep = 1;
    }
    lvl = OSDisableInterrupts();
    lbl_803DCCDC = OSGetCurrentThread();
    if (lbl_803DCCDC->state != OS_THREAD_STATE_RUNNING)
    {
        OSReport(sThreadStateAttrSuspendFormat, lbl_803DCCDC->state, lbl_803DCCDC->attr,
                 lbl_803DCCDC->suspend);
    }
    if ((u32)Queue_GetCount(&lbl_8035F730) > 1)
    {
        lbl_803DCCAC = 0;
        OSSleepThread((OSThreadQueue*)&lbl_803DCCC4);
    }
    OSRestoreInterrupts(lvl);
    Camera_ApplyFullViewport();
    GXInvalidateVtxCache();
    GXInvalidateTexAll();
}


extern GXTexObj lbl_803779A0;


int pathSearchNodeMatchesTarget(int* ctx, int* ref);
void pathSearchHeapSiftDown(u8* arr, int size, int idx);
static inline int pathSearchFindPointNode(PathSearch* search, PathPoint* point, int count, int* visitedOut)
{
    int index = 0;
    int offset = 0;
    int n;

    for (n = count; n > 0; n--)
    {
        PathSearchNode* scanNode = (PathSearchNode*)((u8*)search->nodes + offset);
        if (scanNode->point == point)
        {
            *visitedOut = scanNode->visited;
            return index;
        }
        offset += 0x10;
        index++;
    }
    return -1;
}

void pathSearchEnqueuePoint(int* q, int* elem, int idx, u32 d, char* obj)
{
    PathSearch* search = (PathSearch*)q;
    PathPoint* point = (PathPoint*)obj;
    int pos;
    u16* hh;
    u16 v;
    int cnt2;
    PathSearchNode* node;
    u32* heap;
    int z[2];
    PathSearchNode* node4;
    int visited;
    int cnt;
    if (pathSearchNodeMatchesTarget(q, elem) != 0)
    {
        cnt = search->nodeCount;
        if (cnt != 0xfe)
        {
            node = &search->nodes[search->nodeCount++];
            node->point = point;
            node->routeDistance = d;
            node->parentIndex = (u16)idx;
            node->distanceToTarget = (u32)vec3f_distanceSquared(node->point->position, search->targetPosition);
        }
        heap = (u32*)search->heap;
        hh = (u16*)search->heap;
        v = cnt;
        hh[++search->heapSize * 4 + 2] = v;
        *(u32*)((int)heap + search->heapSize * 8) = 0xfffffffe;
        {
            int i = search->heapSize;
            u32 pri = *(u32*)((int)heap + i * 8);
            u16 idx16 = hh[i * 4 + 2];
            int parent;
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
    cnt2 = search->nodeCount;
    z[0] = pathSearchFindPointNode(search, point, cnt2, &visited);
    if (z[0] >= 0 && visited == 0)
    {
        PathSearchNode* node3 = &search->nodes[z[0]];
        if (d < node3->routeDistance)
        {
            u32 newpri;
            int s2;
            int j;
            u16 target;
            u32* entry;
            u32 old;
            node3->parentIndex = idx;
            node3->routeDistance = d;
            newpri = node3->distanceToTarget + node3->routeDistance;
            s2 = search->heapSize;
            heap = (u32*)search->heap;
            hh = (u16*)heap;
            j = 0;
            target = z[0];
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
                pathSearchHeapSiftDown((u8*)heap, s2, pos);
            }
            else if (newpri > old)
            {
                u32 pri = *entry;
                u16 idx16 = ((u16*)entry)[2];
                int parent;
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
    else if (z[0] < 0)
    {
        if (cnt2 == 0xfe)
        {
            node4 = NULL;
        }
        else
        {
            node4 = &search->nodes[search->nodeCount++];
            node4->point = point;
            node4->routeDistance = d;
            node4->parentIndex = (u16)idx;
            node4->distanceToTarget = (u32)vec3f_distanceSquared(node4->point->position, search->targetPosition);
        }
        if (node4 != NULL)
        {
            if (node4->distanceToTarget > search->closestDistance)
            {
                u32 newpri = node4->distanceToTarget + node4->routeDistance;
                heap = (u32*)search->heap;
                hh = (u16*)heap;
                v = cnt2;
                hh[++search->heapSize * 4 + 2] = v;
                *(u32*)((int)heap + search->heapSize * 8) = -1 - newpri;
                {
                    int i = search->heapSize;
                    u32 pri = *(u32*)((int)heap + i * 8);
                    u16 idx16 = hh[i * 4 + 2];
                    int parent;
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
            else
            {
                u32 newpri;
                if (node4->distanceToTarget < search->closestDistance)
                {
                    search->closestDistance = node4->distanceToTarget;
                }
                newpri = node4->distanceToTarget + node4->routeDistance;
                heap = (u32*)search->heap;
                hh = (u16*)heap;
                v = cnt2;
                hh[++search->heapSize * 4 + 2] = v;
                *(u32*)((int)heap + search->heapSize * 8) = -1 - newpri;
                {
                    int i = search->heapSize;
                    u32 pri = *(u32*)((int)heap + i * 8);
                    u16 idx16 = hh[i * 4 + 2];
                    int parent;
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
}

void pathSearchExpandNode(int* q, int* elem, int idx)
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
                    mainGetBit(0x4e2);
                    ev1 = *(s16*)(obj + 0x30);
                    if (ev1 == -1 || mainGetBit(ev1) != 0)
                    {
                        ev2 = *(s16*)(obj + 0x32);
                        if (ev2 == -1 || mainGetBit(ev2) == 0)
                        {
                            if (!(*(s8*)(obj + 0x1a) == 8 && *(s8*)(node + 0x1a) == 9))
                            {
                                f32 d = vec3f_distanceSquared((f32*)(node + 8), (f32*)(obj + 8));
                                pathSearchEnqueuePoint(q, elem, idx, (u32)((f32)(u32)elem[2] + d), obj);
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
void* pathSearchGetNextPoint(PathSearch* search)
{
    int* p = (int*)search;
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

int pathSearchBuildPath(PathSearch* search)
{
    int* p = (int*)search;
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

int pathSearchStep(PathSearch* search, u32 n_)
{
    int n;
    int* q = (int*)search;
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
            pathSearchHeapSiftDown((u8*)heap, *(s16*)((char*)q + 0x22), 1);
        }
        if (idx >= 0)
        {
            elem = (int*)(*(int*)((char*)q + 0) + idx * 16);
            *(int*)((char*)q + 0x1c) = idx;
            if (pathSearchNodeMatchesTarget(q, elem) != 0)
            {
                done = 1;
                result = 1;
            }
            else
            {
                *((u8*)elem + 0xe) = 1;
                pathSearchExpandNode(q, elem, idx);
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

int pathSearchNodeMatchesTarget(int* ctx, int* ref)
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

void pathSearchHeapSiftDown(u8* arr, int size, int idx)
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
        if (key >= *(u32*)childptr)
            break;
        *(u32*)(arr + idx * 8) = *(u32*)childptr;
        *(u16*)(arr + idx * 8 + 4) = *(u16*)(childptr + 4);
        idx = child;
    }
    *(u32*)((int)arr + idx * 8) = key;
    h[idx * 4 + 2] = val;
}

int pathSearchBegin(PathSearch* queue, PathPoint* startPoint, f32* targetPosition, int pathId, u32 routeFlags)
{
    int i;
    PathSearchNode* node;
    PathHeapEntry* heap;
    int nodeCount;
    u32 priority;
    int parent;
    u16 nodeIndex;
    u16* heapHalves;
    u16 startNodeIndex;

    queue->heapSize = 0;
    queue->nodeCount = 0;
    for (i = 0; i < 0xfe; i++)
    {
        queue->heap[i].priority = 0;
        queue->nodes[i].visited = 0;
    }
    queue->startPoint = startPoint;
    queue->targetPosition = targetPosition;
    queue->pathId = pathId;
    queue->routeFlags = routeFlags & 1;
    queue->closestDistance = 10000;
    nodeCount = queue->nodeCount;
    if (nodeCount == 0xfe)
    {
        node = NULL;
    }
    else
    {
        node = &queue->nodes[queue->nodeCount++];
        node->point = startPoint;
        node->routeDistance = 0;
        node->parentIndex = 0xff;
        node->distanceToTarget = (u32)vec3f_distanceSquared(node->point->position, queue->targetPosition);
    }
    i = node->distanceToTarget + node->routeDistance;
    heap = queue->heap;
    heapHalves = (u16*)queue->heap;
    startNodeIndex = queue->nodeCount - 1;
    heapHalves[(++queue->heapSize) * 4 + 2] = startNodeIndex;
    heap[queue->heapSize].priority = -1 - i;
    i = queue->heapSize;
    priority = heap[i].priority;
    nodeIndex = heapHalves[i * 4 + 2];
    heap[0].priority = -1;
    while (parent = i >> 1, *(u32*)(heapHalves + parent * 4) < priority)
    {
        *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
        *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
        i = parent;
    }
    heap[i].priority = priority;
    heapHalves[i * 4 + 2] = nodeIndex;
    return 0;
}


void freeAndNull(void** p)
{
    if (*p != NULL)
    {
        mm_free(*p);
        *p = NULL;
    }
}

void trickyVoxAllocFn_8004b5d4(PathSearch* search)
{
    search->nodes = (PathSearchNode*)mmAlloc(0x1960, 0x10, 0);
    search->heap = (PathHeapEntry*)((u8*)search->nodes + 0xfe0);
    search->path = (PathPoint**)((u8*)search->heap + 0x7f0);
}


void allocSomething32bytes(void)
{
    lbl_803DCD10 = mmAlloc(0x20, 0xff, 0);
}

RingBufferQueue lbl_8035F730;
char lbl_8035F6B8[0x78];
OSStopwatch lbl_8035F680;
s16 gObjMapBlockInfo[0x9C];
u32 lbl_8035F3E8[0x58];
int lbl_8035F208[0x78];
u32 lbl_8035F0A8[0x58];
int lbl_8035EF48[0x58];
