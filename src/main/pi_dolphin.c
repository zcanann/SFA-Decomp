#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebits.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "dolphin/gx/GXMisc.h"
#include "main/pi_dolphin.h"
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
#include "dolphin/gx/GXFifo.h"
#include "dolphin/os/OSThread.h"
#include "main/asset_load.h"
#include "main/mapEventTypes.h"
#include "main/objprint_load_api.h"
#include "dolphin/os/OSAlloc.h"
#include "main/objmodel.h"
#include "main/voxmaps.h"
#include "main/newshadows_texture_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "dolphin/gx/GXBump.h"
#include "main/mapEvent.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/dll/ppcwgpipe_struct.h"

u32 sPiUnused3;
void* lbl_803DCD10;
u32 sPiUnused2;
char* lbl_803DCD08;
static u32 sPiUnused1;
u8 lbl_803DCD00;
int lbl_803DCCFC;
u8 lbl_803DCCF8;
int lbl_803DCCF4;
GXRenderModeObj* gRenderModeObj;
void* externalFrameBuffer0;
void* externalFrameBuffer1;
u32 gGxFifoSize;
char* lbl_803DCCE0;
OSThread* gVideoWaitThread;
void* gGxFifoBase;
GXFifoObj* gGxFifoObj;
void* renderFrameBuffer;
void* displayFrameBuffer;
static u32 sPiUnused4;
char gVideoFlipWaitQueue;
f32 gFrameElapsedMs;
u32 gViewportJitterField;
int gDispCopyYScaleLines;
f32 gFrameStepRemainder;
u8 gGpuHangRecoveryEnabled;
volatile int gGpuStallRetraceCount;
u16 gLastDrawSyncToken;
u8 gFrameBufferFlipped;
u8 gFlipTokenHeldForDisplayedFb;
u8 gGxBreakPtEnabled;
u8 gVideoRetracePending;
u8 gPadReadReady;
u8 gResetButtonPressState;
int gRetraceCountSinceFlip;
u32 sPiUnused0;
int lbl_803DCC98;
s32 gObjTableFileRequestFlags;
s16 gForceNextLoadSync;
u8 gLoadFilesInitDone;
void** gDvdFileInfoPool;
int gPendingDvdReadCount;
volatile int gAssetLoadCompletedFlags;
volatile int gAssetLoadInFlightFlags;
int gModelsArchiveLoadCount;
s16 gDefragDelayFrames;
u32 gRomListLoadInFlight;
int gForceLoadImmediately;

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
u8 gVideoBlackScreenFrameCount = 5;
u16 gGxDrawSyncToken = 1;
GXColor gEfbCopyClearColor = {0, 0, 0, 0xFF};
u8 gDispCopyFilterWeights[8] = {7, 7, 0xC, 0xC, 0xC, 7, 7, 0};
char sProgramCounterFormat[] = "PC: %x";
int lbl_803DB5E4 = 0;

#define PAD_BUTTON_A  0x100
#define PAD_BUTTON_B  0x200
extern u8 gResourceFileTable[]; /* resource file table -- see struct MldfTables */
extern u32 gObjBlockStatus[];


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

/* Resource file table at gResourceFileTable (0x80345E10, 0x20000 bytes). File slots are
   indexed by resource fileId (0..0x57); map-owned resources use paired slots (e.g.
   ANIMCURV 0xd/0x55) so two maps can be resident at once. Several arrays are also
   addressed directly through their own symbols elsewhere in this file:
   ids   == gResourcePendingMapIds (pending mapId per slot, -1 = none; retried by loadDataFiles)
   sizes == gResourceFileSizes, romList == gMapRomListBuffers, ptrs == gResourceFileBuffers. */
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
    void* ptrs[0x58];         /* loaded file buffer, NULL = not resident */
    s16 owners[0x60];         /* mapId owning the slot, -1 = free */
};

STATIC_ASSERT(offsetof(struct MldfTables, mergeAnimCurv) == 0x2C0);
STATIC_ASSERT(offsetof(struct MldfTables, mergeVoxMap) == 0x8200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeBlocks) == 0xA200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeTex1) == 0xC200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeTex0) == 0x10200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeAnim) == 0x14200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeModels) == 0x170E0);
STATIC_ASSERT(offsetof(struct MldfTables, ids) == 0x19138);

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
#define MLDF_ID_RT(s)    (*(int*)(((s) << 2) + ((u32) & tbl->ids[0])))
#define MLDF_OWNER_RT(s) (*(s16*)(((s) << 1) + ((u32) & tbl->owners[0])))
#define MLDF_FINFO4(s4)  (tbl->fileInfo[slot])
#define MLDF_SP_ID(p)    (tbl->ids[slot])
#define MLDF_SP_SIZE(p)  (*(int*)(slotSizeAddr - 0x6D68))
#define MLDF_SP_SIZE_INIT(p) (*(int*)((slotSizeAddr = (slot << 2) + ((u32) & tbl->sizes[0] + 0x6D68)) - 0x6D68))
#define MLDF_SP_PTR(p)       (*(void**)(slotPtrAddr - 0x6A28))
/* the -0x6A28 displacement == &tbl->ptrs[0] relative to tbl + 0x20000 */
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

int sMapFileNameIndexRemapTable[] = {
    13, 5,  4,  5,  7,  5,  5,  12, 19, 9,  14, 15, 18, 20, 21, 22, 24, 5,  25, 26, 5,  28, 5,  30, 31,
    32, 5,  34, 35, 47, 37, 39, 40, 41, 42, 48, 5,  5,  3,  43, 44, 45, 5,  50, 51, 5,  5,  5,  53, 5,
    6,  16, 10, 5,  38, 55, 54, 5,  56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
};

s16 sMapFileNameAdjacencyTable[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 12, -1, -1, -1, 15, -1, -1, 12, -1, -1, 12, -1, -1, -1, -1, 18, -1,
    -1, -1, 6,  -1, -1, -1, -1, -1, -1, 34, -1, -1, -1, 25, 21, 15, 20, 14, 15, -1, -1, -1, 5,  -1, -1, -1,
    -1, 20, 30, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 14, -1, 12, 7,  12, 21, 47, -1, -1, -1, 0,
};


void initLoadFileReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        gPendingDvdReadCount--;
    }
}


// DVDGetCommandBlockStatus() command-block states (DVD_STATE_*)

s32 ObjLoad_GetDvdCommandBlockStatus(DVDCommandBlock* block)
{
    s32 status;
    if (block == NULL)
    {
        return -1;
    }
    status = DVDGetCommandBlockStatus(block);
    switch (status)
    {
    case DVD_STATE_FATAL_ERROR:
        return status;
    case DVD_STATE_END:
        return status;
    case DVD_STATE_BUSY:
        return status;
    case DVD_STATE_WAITING:
        return status;
    case DVD_STATE_COVER_CLOSED:
        return status;
    case DVD_STATE_NO_DISK:
        return status;
    case DVD_STATE_COVER_OPEN:
        return status;
    case DVD_STATE_WRONG_DISK:
        return status;
    case DVD_STATE_MOTOR_STOPPED:
        return status;
    case DVD_STATE_PAUSING:
        return status;
    case DVD_STATE_IGNORED:
        return status;
    case DVD_STATE_CANCELED:
        return status;
    case DVD_STATE_RETRY:
        return status;
    }
    return 0;
}


void clearForceLoadImmediately(void)
{
    gForceLoadImmediately = 0x0;
}
void setForceLoadImmediately(void)
{
    gForceLoadImmediately = 0x1;
}
static inline int loadedFileFlags(void)
{
    int s = OSDisableInterrupts();
    u32 v = gAssetLoadInFlightFlags;
    OSRestoreInterrupts(s);
    return v;
}

void defragMemory(int mode)
{
    char* q1;
    char* q2;
    char* q3;
    char* q4;
    int i;
    int pass;
    int done;
    int d;
    u8* base = gResourceFileTable;
    done = 0;
    pass = 0;
    mmSetTextureAllocationState(2);
    if (loadedFileFlags() != 0)
    {
        return;
    }
    if (mode == 0 && gDefragDelayFrames == 0)
    {
        texRestructRefs(0);
        gDefragDelayFrames = 6;
        return;
    }
    if (mode != 0)
    {
        char* p1;
        char* p2;
        char* p3;
        char* p4;
        void* n;
        int i;
        mmSetDelay2(1);
        i = 0;
        {
            char* hi = (char*)base + 0x20000;
            p1 = hi - 0x6a28;
            p2 = hi - 0x68c8;
            p3 = hi - 0x6d68;
            p4 = hi - 0x6f20;
        }
        do
        {
            switch (i)
            {
            case 0xd:
            case 0x1b:
            case 0x23:
            case 0x25:
            case 0x2b:
            case 0x30:
            case 0x46:
            case 0x47:
            case 0x4a:
            case 0x4d:
            case 0x54:
            case 0x55:
            {
                if (*(void**)p1 == NULL)
                {
                    break;
                }
                if (*(s16*)p2 == -1)
                {
                    break;
                }
                if (mmGetRegionForPtr(*(void**)p1) != 0)
                {
                    break;
                }
                if (mode == 2)
                {
                    if (i == 0x20)
                        break;
                    if (i == 0x4b)
                        break;
                    if (i == 0x23)
                        break;
                    if (i == 0x4d)
                        break;
                }
                n = mmAlloc(*(int*)p3 + 0x20, 0x7d7d7d7d, 0);
                if (n == NULL)
                {
                    break;
                }
                memcpy(n, *(void**)p1, *(int*)p3);
                {
                    int d = mmSetFreeDelay(0);
                    mm_free(*(void**)p1);
                    *(int*)p1 = 0;
                    *(void**)p1 = n;
                    mmSetFreeDelay(d);
                }
                break;
            }
            }
            *(u8*)p4 = 0;
            p1 += 4;
            p2 += 2;
            p3 += 4;
            p4 += 1;
            i++;
        } while (i <= 0x57);
        mmSetDelay2(-1);
    }
    base = (u8*)((char*)base + 0x20000);
    while (done == 0 && pass < 10)
    {
        done = 1;
        i = 0;
        q1 = (char*)base - 0x6a28;
        q2 = (char*)base - 0x68c8;
        q3 = (char*)base - 0x6d68;
        q4 = (char*)base - 0x6f20;
        do
        {
            switch (i)
            {
            case 0xd:
            case 0x1b:
            case 0x23:
            case 0x25:
            case 0x2b:
            case 0x30:
            case 0x46:
            case 0x47:
            case 0x4a:
            case 0x4d:
            case 0x54:
            case 0x55:
            {
                void* n;
                if (*(void**)q1 != NULL && *(s16*)q2 != -1 && mmGetRegionForPtr(*(void**)q1) == 0)
                {
                    n = mmAlloc(*(int*)q3 + 0x20, 0x7d7d7d7d, 0);
                    if (n == NULL)
                    {
                        break;
                    }
                    if (*(int*)q3 >= 0x33450 && *(u32*)q1 < (u32)n)
                    {
                        int d = mmSetFreeDelay(0);
                        mm_free(n);
                        mmSetFreeDelay(d);
                    }
                    else if (*(int*)q3 < 0x33450 && *(u32*)q1 > (u32)n)
                    {
                        int d = mmSetFreeDelay(0);
                        mm_free(n);
                        mmSetFreeDelay(d);
                    }
                    else
                    {
                        int d;
                        memcpy(n, *(void**)q1, *(int*)q3);
                        d = mmSetFreeDelay(0);
                        mm_free(*(void**)q1);
                        *(int*)q1 = 0;
                        *(void**)q1 = n;
                        mmSetFreeDelay(d);
                        done = 0;
                    }
                }
                else
                {
                    if (mode == 2)
                        break;
                    if (pass == 0)
                        break;
                    if (*(void**)q1 == NULL)
                        break;
                    if (*(s16*)q2 == -1)
                        break;
                    if (mmGetRegionForPtr(*(void**)q1) != 1 && mmGetRegionForPtr(*(void**)q1) != 2)
                    {
                        break;
                    }
                    if (getHeapItemSize(*(void**)q1) < 0x3000)
                    {
                        break;
                    }
                    n = mmAlloc(*(int*)q3 + 0x20, 0x7d7d7d7d, 0);
                    if (n == NULL)
                    {
                        break;
                    }
                    if (mmGetRegionForPtr(n) != 0)
                    {
                        int d = mmSetFreeDelay(0);
                        mm_free(n);
                        mmSetFreeDelay(d);
                    }
                    else
                    {
                        memcpy(n, *(void**)q1, *(int*)q3);
                        d = mmSetFreeDelay(0);
                        mm_free(*(void**)q1);
                        *(int*)q1 = 0;
                        *(void**)q1 = n;
                        mmSetFreeDelay(d);
                        done = 0;
                    }
                }
                break;
            }
            }
            *(u8*)q4 = 0;
            q1 += 4;
            q2 += 2;
            q3 += 4;
            q4 += 1;
            i++;
        } while (i <= 0x57);
        pass++;
    }
    mmSetTextureAllocationState(0);
}


void animCurvReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x10000000)
        {
            gAssetLoadCompletedFlags |= 0x10000000;
            gObjBlockStatus[0x34 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x40000000)
        {
            gAssetLoadCompletedFlags |= 0x40000000;
            gObjBlockStatus[0x154 / 4] = 0;
        }
    }
}


void animCurvTabReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x20000000)
        {
            gAssetLoadCompletedFlags |= 0x20000000;
            gObjBlockStatus[0x38 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x80000000)
        {
            gAssetLoadCompletedFlags |= 0x80000000;
            gObjBlockStatus[0x158 / 4] = 0;
        }
    }
}


void voxMapReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x1000000)
        {
            gAssetLoadCompletedFlags |= 0x1000000;
            gObjBlockStatus[0x6c / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x4000000)
        {
            gAssetLoadCompletedFlags |= 0x4000000;
            gObjBlockStatus[0x150 / 4] = 0;
        }
    }
}


void voxMapTabReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x2000000)
        {
            gAssetLoadCompletedFlags |= 0x2000000;
            gObjBlockStatus[0x68 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x8000000)
        {
            gAssetLoadCompletedFlags |= 0x8000000;
            gObjBlockStatus[0x14c / 4] = 0;
        }
    }
}


void blocksTabReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x20000)
        {
            gAssetLoadCompletedFlags |= 0x20000;
            gObjBlockStatus[0x98 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x80000)
        {
            gAssetLoadCompletedFlags |= 0x80000;
            gObjBlockStatus[0x120 / 4] = 0;
        }
    }
}

void romListReadCb(s32 result, DVDFileInfo* fileInfo)
{
    gRomListLoadInFlight = 0;
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
}

void blocksReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x10000)
        {
            gAssetLoadCompletedFlags |= 0x10000;
            gObjBlockStatus[0x94 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x40000)
        {
            gAssetLoadCompletedFlags |= 0x40000;
            gObjBlockStatus[0x11c / 4] = 0;
        }
    }
}

void tex1tab2readCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free((void*)gResourceFileBuffers[78]);
        gResourceFileBuffers[78] = 0;
        gObjBlockStatus[78] = 0;
        if (gAssetLoadInFlightFlags & 0x8000)
        {
            gAssetLoadCompletedFlags |= 0x8000;
            gObjBlockStatus[76] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x8000)
        {
            gAssetLoadCompletedFlags |= 0x8000;
            gObjBlockStatus[76] = 0;
        }
    }
}

void tex1tab1readCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free((void*)gResourceFileBuffers[78]);
        gResourceFileBuffers[78] = 0;
        gObjBlockStatus[78] = 0;
        if (gAssetLoadInFlightFlags & 0x4000)
        {
            gAssetLoadCompletedFlags |= 0x4000;
            gObjBlockStatus[33] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x4000)
        {
            gAssetLoadCompletedFlags |= 0x4000;
            gObjBlockStatus[33] = 0;
        }
    }
}

void tex1ReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x1000)
        {
            gAssetLoadCompletedFlags |= 0x1000;
            gObjBlockStatus[0x80 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x2000)
        {
            gAssetLoadCompletedFlags |= 0x2000;
            gObjBlockStatus[0x12c / 4] = 0;
        }
    }
}

void tex0tab2readCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free((void*)gResourceFileBuffers[78]);
        gResourceFileBuffers[78] = 0;
        gObjBlockStatus[78] = 0;
        if (gAssetLoadInFlightFlags & 0x800)
        {
            gAssetLoadCompletedFlags |= 0x800;
            gObjBlockStatus[78] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x800)
        {
            gAssetLoadCompletedFlags |= 0x800;
            gObjBlockStatus[78] = 0;
        }
    }
}
void tex0tab1readCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free((void*)gResourceFileBuffers[36]);
        gResourceFileBuffers[36] = 0;
        gObjBlockStatus[36] = 0;
        if (gAssetLoadInFlightFlags & 0x400)
        {
            gAssetLoadCompletedFlags |= 0x400;
            gObjBlockStatus[36] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x400)
        {
            gAssetLoadCompletedFlags |= 0x400;
            gObjBlockStatus[36] = 0;
        }
    }
}

void tex0readCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x100)
        {
            gAssetLoadCompletedFlags |= 0x100;
            gObjBlockStatus[0x8c / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x200)
        {
            gAssetLoadCompletedFlags |= 0x200;
            gObjBlockStatus[0x134 / 4] = 0;
        }
    }
}

void animReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x10)
        {
            gAssetLoadCompletedFlags |= 0x10;
            gObjBlockStatus[0xc0 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x20)
        {
            gAssetLoadCompletedFlags |= 0x20;
            gObjBlockStatus[0x128 / 4] = 0;
        }
    }
}

void modelsReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x1)
        {
            gAssetLoadCompletedFlags |= 0x1;
            gObjBlockStatus[0xac / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x2)
        {
            gAssetLoadCompletedFlags |= 0x2;
            gObjBlockStatus[0x118 / 4] = 0;
        }
    }
}

void animTabReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x40)
        {
            gAssetLoadCompletedFlags |= 0x40;
            gObjBlockStatus[0xbc / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x80)
        {
            gAssetLoadCompletedFlags |= 0x80;
            gObjBlockStatus[0x124 / 4] = 0;
        }
    }
}

void modelsTabReadCb(s32 result, DVDFileInfo* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x4)
        {
            gAssetLoadCompletedFlags |= 0x4;
            gObjBlockStatus[0xa8 / 4] = 0;
        }
        else if (gAssetLoadInFlightFlags & 0x8)
        {
            gAssetLoadCompletedFlags |= 0x8;
            gObjBlockStatus[0x114 / 4] = 0;
        }
    }
}



static inline s32 mapCheckCurBlocksImpl(int v)
{
    if (gObjMapBlockInfo[0x25] == v)
        return 0;
    if (gObjMapBlockInfo[0x47] == v)
        return 1;
    return -1;
}

void mapLoadDataFiles(int mapIdx)
{
    if (sMapFileNameAdjacencyTable[mapIdx] != -1)
    {
        SaveGameCharacterPosition* r = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
        r->mapDataFileId = mapIdx;
    }
    mapLoadDataFile(mapIdx, MLDF_FILEID_TEX1_BIN_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_TEX1_TAB_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_TEX0_BIN_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_TEX0_TAB_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_ANIM_BIN_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_ANIM_TAB_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_MODELS_BIN_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_MODELS_TAB_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_BLOCKS_TAB_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_BLOCKS_BIN_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_VOXMAP_TAB_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_VOXMAP_BIN_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_ANIMCURV_TAB_A);
    mapLoadDataFile(mapIdx, MLDF_FILEID_ANIMCURV_BIN_A);
}


int loadMapAndParent(int mapId)
{
    int idx;
    int parent;
    if (mapId >= 0x4b)
    {
        idx = 5;
    }
    else
    {
        idx = sMapFileNameIndexRemapTable[mapId];
    }
    parent = sMapFileNameAdjacencyTable[idx];
    if (parent != -1 && mapCheckCurBlocksImpl(parent) == -1)
    {
        mapLoadDataFiles(parent);
        return parent;
    }
    mapLoadDataFiles(idx);
    return idx;
}

void clearLoadedFileFlags_blocks1(void)
{
    int s = OSDisableInterrupts();
    if (gAssetLoadInFlightFlags & 0x100000)
    {
        gAssetLoadInFlightFlags ^= 0x100000;
    }
    OSRestoreInterrupts(s);
}


void setLoadedFileFlags_blocks1(void)
{
    int s = OSDisableInterrupts();
    gAssetLoadInFlightFlags |= 0x100000;
    OSRestoreInterrupts(s);
}
int isRomListLoading(void)
{
    return gRomListLoadInFlight;
}

int getLoadedFileFlags(int slot)
{
    return loadedFileFlags();
}


u32 loadTableFiles(void)
{
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    int s = OSDisableInterrupts();
    int flags = loadedFileFlags();
    int loadedFlags = gAssetLoadInFlightFlags;
    if ((gObjTableFileRequestFlags & 0x4) && !(flags & 0x4) && tbl->ids[0x2b] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeModels, 0x2a, 0x45, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x8) && !(flags & 0x8) && tbl->ids[0x46] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeModels, 0x2a, 0x45, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x40) && !(flags & 0x40) && tbl->ids[0x30] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeAnim, 0x2f, 0x49, 0xbb8);
    }
    if ((gObjTableFileRequestFlags & 0x80) && !(flags & 0x80) && tbl->ids[0x4a] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeAnim, 0x2f, 0x49, 0xbb8);
    }
    if ((gObjTableFileRequestFlags & 0x400) && !(flags & 0x400) && tbl->ids[0x23] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeTex0, 0x24, 0x4e, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x800) && !(flags & 0x800) && tbl->ids[0x4d] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeTex0, 0x24, 0x4e, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x4000) && !(flags & 0x4000) && tbl->ids[0x20] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeTex1, 0x21, 0x4c, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x8000) && !(flags & 0x8000) && tbl->ids[0x4b] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeTex1, 0x21, 0x4c, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x20000) && !(flags & 0x20000) && tbl->ids[0x25] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeBlocks, 0x26, 0x48, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x80000) && !(flags & 0x80000) && tbl->ids[0x47] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeBlocks, 0x26, 0x48, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x2000000) && !(flags & 0x2000000) && tbl->ids[0x1b] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x8000000) && !(flags & 0x8000000) && tbl->ids[0x54] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x20000000) && !(flags & 0x20000000) && tbl->ids[0xd] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
    }
    if ((gObjTableFileRequestFlags & 0x80000000) && !(flags & 0x80000000) && tbl->ids[0x55] == -1)
    {
        mergeTableFiles((u32*)tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
    }
    gObjTableFileRequestFlags = flags;
    gAssetLoadInFlightFlags = gAssetLoadInFlightFlags ^ gAssetLoadCompletedFlags;
    gAssetLoadCompletedFlags = 0;
    OSRestoreInterrupts(s);
    return gAssetLoadInFlightFlags;
}

int unlockLevel(s32 level, int bucket, int flag)
{
    s32 cur;
    if (flag == 1)
    {
        gObjLevelLockSlots[0] = -2;
        gObjLevelLockSlots[1] = -2;
        return -1;
    }
    cur = gObjLevelLockSlots[bucket];
    if (level == cur || cur == -2)
    {
        gObjLevelLockSlots[bucket] = -2;
        return -1;
    }
    return cur;
}


int lockLevel(s32 level, int bucket)
{
    s32 cur = gObjLevelLockSlots[bucket];
    if (cur == -2)
    {
        gObjLevelLockSlots[bucket] = level;
        return -1;
    }
    return cur;
}

char sAssetIndexOverflowError[0x1D] = "ERROR: asset index overflow ";

int getTableFileEntry(int fileId, int index, int* out)
{
    u8* base = gResourceFileTable;
    int count = 0;
    void* table = NULL;
    switch (fileId)
    {
    case 0x2a:
        count = 0x800;
        table = (u8*)(base + 0x10000) + 0x70e0;
        break;
    case 0x2f:
        count = 0xbb8;
        table = (u8*)(base + 0x10000) + 0x4200;
        break;
    case 0x24:
        count = 0x1000;
        table = (u8*)(base + 0x10000) + 0x200;
        break;
    case 0x21:
        count = 0x1000;
        table = (u8*)(base + 0x10000) - 0x3e00;
        break;
    case 0x50:
        table = *(void**)&base[0x19718];
        break;
    case 0x26:
        count = 0x800;
        table = (u8*)(base + 0x10000) - 0x5e00;
        break;
    case 0x1a:
        count = 0x800;
        table = (u8*)(base + 0x10000) - 0x7e00;
        break;
    case 0xe:
        count = 0x1fd0;
        table = &base[0x2c0];
        break;
    }
    if (index < 0 || index >= count)
    {
        debugPrintfxy(0x14, 0x28, sAssetIndexOverflowError);
        return 0;
    }
    if (table != NULL)
    {
        *out = ((int*)table)[index];
        return 1;
    }
    return 0;
}


#define MAPTBLP(idx)    (*(int**)(((idx) << 2) + ((u32)&((struct MldfTables*)base)->ptrs[0])))
#define MAPID_RT(s)    (*(int*)(((s) << 2) + ((u32) & tbl->ids[0])))
#define MAPPTR_RT(s)   (*(u32*)(((s) << 2) + ((u32) & tbl->ptrs[0])))
#define MAPOWNER_RT(s) (*(s16*)(((s) << 1) + ((u32) & tbl->owners[0])))


void* getCurrentDataFile(int id)
{
    u8* base = gResourceFileTable;
    switch (id)
    {
    case 42:
        return &base[0x170e0];
    case 47:
        return &base[0x14200];
    case 36:
        return &base[0x10200];
    case 33:
        return &base[0xc200];
    case 80:
        return *(void**)&base[0x19718];
    case 38:
        return &base[0xa200];
    case 26:
        return &base[0x8200];
    case 14:
        return &base[0x2c0];
    }
    return NULL;
}


int mapUnload(int mapId, int flags)
{
    struct MldfTables* tbl;
    int* e;
    int f20;
    int f10;
    u32 f80;
    int n;
    s32* lockp;
    u8 needWait;
    int i;
    int s;
    int j;
    SaveGameCharacterPosition* st;

    tbl = (struct MldfTables*)gResourceFileTable;
    i = 0;
    needWait = 0;
    st = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
    {
        int pairs[56] = {
            0x2b, 0x1,    0x2a, 0x2,    0x2f, 0x8,    0x30, 0x4,   0x46, 0x1,   0x45, 0x2,   0x49, 0x8,
            0x4a, 0x4,    0x24, 0x20,   0x23, 0x10,   0x4e, 0x20,  0x4d, 0x10,  0x21, 0x80,  0x20, 0x40,
            0x4c, 0x80,   0x4b, 0x40,   0x25, 0x100,  0x26, 0x200, 0x47, 0x100, 0x48, 0x200, 0x1b, 0x1000,
            0x1a, 0x2000, 0x54, 0x1000, 0x53, 0x2000, 0xd,  0x400, 0xe,  0x800, 0x55, 0x400, 0x56, 0x800,
        };

        while (s = OSDisableInterrupts(), n = gAssetLoadInFlightFlags, OSRestoreInterrupts(s), n != 0)
        {
            if (n == 0x100000)
            {
                break;
            }
            padUpdate();
            checkReset();
            if (needWait)
            {
                waitNextFrame();
            }
            loadDataFiles(0);
            dvdCheckError();
            if (needWait)
            {
                mmFreeTick(0);
                gameTextRun();
                GXFlush_(1, 0);
            }
            if (gDvdErrorPauseActive)
            {
                needWait = 1;
            }
        }

        st = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
        {
            int v = st->mapDataFileId;
            if (v != gObjLevelLockSlots[0] && v != gObjLevelLockSlots[1])
            {
                if ((flags & 0x10000000) && mapId != v)
                {
                    st->mapDataFileId = -1;
                }
                if ((flags & 0x20000000) && mapId == st->mapDataFileId)
                {
                    st->mapDataFileId = -1;
                }
                if (flags & 0x80000000)
                {
                    st->mapDataFileId = -1;
                }
            }
        }

        e = pairs;
        f20 = flags & 0x20000000;
        f10 = flags & 0x10000000;
        f80 = flags & 0x80000000;
        lockp = gObjLevelLockSlots;
        for (; i < 0x38; i += 2)
        {
            if ((f20 && mapId == MAPID_RT(e[0])) || (f10 && mapId != MAPID_RT(e[0])) ||
                ((flags & e[1]) && mapId == MAPID_RT(e[0])))
            {
                MAPID_RT(e[0]) = -1;
            }
            {
                int idx = e[0];
                if (((int**)((char*)tbl + 0x20000 + -0x6A28))[idx] != NULL)
                {
                    s16 v;
                    if (f80 || ((flags & e[1]) && mapId == ((s16*)((char*)tbl + 0x20000 + -0x68C8))[idx]) ||
                        (f10 && mapId != MAPOWNER_RT(idx)) || (f20 && mapId == MAPOWNER_RT(idx)))
                    {
                        if (gObjLevelLockSlots[0] != (v = MAPOWNER_RT(idx)) && lockp[1] != v)
                        {
                            switch (idx)
                            {
                            case 0xe:
                            case 0x1a:
                            case 0x21:
                            case 0x24:
                            case 0x2a:
                            case 0x2b:
                            case 0x2f:
                            case 0x30:
                            case 0x45:
                            case 0x46:
                            case 0x49:
                            case 0x4a:
                            case 0x4c:
                            case 0x4e:
                            case 0x53:
                            case 0x56:
                                mmSetFreeDelay(0);
                                break;
                            case 0x20:
                            case 0x23:
                            case 0x4b:
                            case 0x4d:
                                mmSetFreeDelay(0);
                                break;
                            case 0x26:
                            case 0x48:
                                mmSetFreeDelay(0);
                                for (j = 0; j < 75; j++)
                                {
                                    if (sMapFileNameIndexRemapTable[j] == *(s16*)((u32)tbl + 0x20000 + (e[0] << 1) - 0x68C8))
                                    {
                                        break;
                                    }
                                }
                                if (j <= 0x50 && j != 0x49 && j != 0x43 && j != 5)
                                {
                                    u32 slotAddr = (j << 2) + ((u32)&tbl->romList[0] + 0x6C08);
                                    mm_free((void*)*(u32*)(slotAddr - 0x6C08));
                                    *(u32*)(slotAddr - 0x6C08) = 0;
                                }
                                break;
                            }
                            mm_free((void*)MAPPTR_RT(e[0]));
                            mmSetFreeDelay(2);
                            *(u32*)((e[0] << 2) + ((u32)tbl + 0x20000) - 0x6A28) = 0;
                            *(s16*)((e[0] << 1) + ((u32)tbl + 0x20000) - 0x68C8) = -1;
                            *(int*)((e[0] << 2) + ((u32)tbl + 0x20000) - 0x6D68) = 0;
                            switch (e[0])
                            {
                            case 0x2a:
                            case 0x45:
                                mergeTableFiles((u32*)tbl->mergeModels, 0x2a, 0x45, 0x800);
                                break;
                            case 0x2f:
                            case 0x49:
                                mergeTableFiles((u32*)tbl->mergeAnim, 0x2f, 0x49, 0xbb8);
                                break;
                            case 0x24:
                            case 0x4e:
                                mergeTableFiles((u32*)tbl->mergeTex0, 0x24, 0x4e, 0x1000);
                                break;
                            case 0x21:
                            case 0x4c:
                                mergeTableFiles((u32*)tbl->mergeTex1, 0x21, 0x4c, 0x1000);
                                break;
                            case 0x26:
                            case 0x48:
                                mergeTableFiles((u32*)tbl->mergeBlocks, 0x26, 0x48, 0x800);
                                break;
                            case 0x1a:
                            case 0x53:
                                mergeTableFiles((u32*)tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
                                break;
                            case 0xe:
                            case 0x56:
                                mergeTableFiles((u32*)tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
                                break;
                            }
                        }
                    }
                }
            }
            e += 2;
        }
    }
    return 1;
}

int mergeTableFiles(void* table, int id, int idx, int count_)
{
    u32* tbl = table;
    u8* base = gResourceFileTable;
    int i = 0;
    int e1 = 0;
    int e2 = 0;
    int count = 0;
    int* p1;
    int* p2;
    int* src1 = MAPTBLP(id);
    if (src1 == NULL || MAPTBLP(idx) == NULL)
    {
        if (src1 == NULL)
        {
            e1 = 1;
        }
        if (MAPTBLP(idx) == NULL)
        {
            e2 = 1;
        }
    }
    p1 = (int*)(u32)src1;
    p2 = MAPTBLP(idx);
    if (tbl == (u32*)(base + 0x170e0))
    {
        count = 0x800;
    }
    else if (tbl == (u32*)(base + 0x14200))
    {
        count = 0xbb8;
    }
    else if (tbl == (u32*)(base + 0x10200))
    {
        count = 0x1000;
    }
    else if (tbl == (u32*)(base + 0xc200))
    {
        count = 0x1000;
    }
    else if (tbl == (u32*)(base + 0xa200))
    {
        count = 0x800;
    }
    else if (tbl == (u32*)(base + 0x8200))
    {
        count = 0x800;
    }
    else if (tbl == (u32*)(base + 0x2c0))
    {
        count = 0x1fd0;
    }
    if (tbl == (u32*)(base + 0x10200) || tbl == (u32*)(base + 0xc200))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int va;
        int vb;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                e1 = 1;
            }
            if (!e2 && *p2 == -1)
            {
                e2 = 1;
            }
            if (!e1 && (va = *w1, va != -1) && (va & 0x80000000))
            {
                *dst = va & 0x7fffffff;
                *dst = *dst | 0x40000000;
            }
            else if (!e2 && (vb = *p2, vb != -1) && (vb & 0x80000000))
            {
                *dst = vb;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *p2 != 0)
            {
                *dst = *p2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            p2++;
            dst++;
            i++;
        }
    }
    else if (tbl == (u32*)(base + 0xa200))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int* w2 = p2;
        int va;
        int vb;
        for (; count > 0; count--)
        {
            if (!e1 && (va = *w1, va != -1) && (va & 0x10000000))
            {
                *dst = va;
                if (p2 != NULL && *w2 == -1)
                {
                    e2 = 1;
                }
            }
            else if (!e2 && (vb = *w2, vb != -1) && (vb & 0x10000000))
            {
                *dst = (vb & 0xffffff) | 0x20000000;
                if (p1 != NULL && *w1 == -1)
                {
                    e1 = 1;
                }
            }
            else if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *w2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *w2 != 0)
            {
                *dst = *w2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            dst++;
            w2++;
            i++;
        }
    }
    else if (tbl == (u32*)(base + 0x8200))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int va;
        int vb;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *p2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && (va = *w1, va != -1) && (va & 0x80000000))
            {
                *dst = va;
            }
            else if (!e2 && (vb = *p2, vb != -1) && (vb & 0x80000000))
            {
                *dst = (vb & 0x7fffffff) | 0x20000000;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *p2 != 0)
            {
                *dst = *p2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            dst++;
            p2++;
            i++;
        }
    }
    else if (tbl == (u32*)(base + 0x2c0))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int va;
        int vb;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *p2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && (va = *w1, va != -1) && (va & 0x80000000))
            {
                *dst = va;
            }
            else if (!e2 && (vb = *p2, vb != -1) && (vb & 0x80000000))
            {
                *dst = (vb & 0x7fffffff) | 0x20000000;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *p2 != 0)
            {
                *dst = *p2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            dst++;
            p2++;
            i++;
        }
    }
    else
    {
        int* w1 = p1;
        int* w2 = p2;
        int* dst = (int*)tbl;
        int va;
        int vb;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                e1 = 1;
            }
            if (!e2 && *w2 == -1)
            {
                e2 = 1;
            }
            if (!e1 && (va = *w1, va != -1) && (va & 0x10000000))
            {
                *dst = va;
            }
            else if (!e2 && (vb = *w2, vb != -1) && (vb & 0x10000000))
            {
                *dst = (vb & 0xffffff) | 0x20000000;
            }
            else if (!e1 && p1 != NULL)
            {
                *dst = *w1;
            }
            else if (!e2 && p2 != NULL)
            {
                *dst = *w2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            w2++;
            dst++;
            i++;
        }
    }
    {
        int last = i - 1;
        tbl[last] = 0xffffffff;
    }
    return 1;
}
#undef MAPTBLP

s32 mapCheckCurBlocks(int v)
{
    return mapCheckCurBlocksImpl(v);
}

char sMapAssetPathFormats[0x78] =
    "%s/animcurv.bin\0%s/animcurv.tab\0%s/voxmap.bin\0\0\0warlock/voxmap.bin\0\0%s/voxmap.tab\0\0"
    "\0%s/mod%d.zlb.bin\0\0\0\0%s/mod%d.tab";
void gxSetGPMetricsEnabled(int);


void* mapLoadDataFile(int mapId, int fileId)
{
    struct MldfNames* nm = (struct MldfNames*)sResourceFileNameAudioTab;
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    DVDFileInfo* tabFi;
    DVDFileInfo* fi;
    int sync = 0;
    void* result;
    int adj;
    int slot;
    u32 slotPtrAddr;  /* &tbl->ptrs[slot] + 0x6A28 (ha-sum biased base) */
    u32 slotSizeAddr; /* &tbl->sizes[slot] + 0x6D68 */
    int ok;
    void* loadedBuffer;
    int adjacentClass[1];
    char buf[56];

    if (gForceNextLoadSync != 0)
    {
        gForceNextLoadSync = 0;
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
            gForceNextLoadSync = 1;
            if (o25 == adj)
            {
                adjacentClass[0] = 0;
            }
            else if (o47 == adj)
            {
                adjacentClass[0] = 1;
            }
            else
            {
                adjacentClass[0] = -1;
            }
            if (adjacentClass[0] == -1)
            {
                mapLoadDataFile(adj, fileId);
            }
            sync = 1;
        }
    }
    sync = sync | gForceLoadImmediately;
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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtAnimCurvBin, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
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
                    MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                    DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                    loadedBuffer = MLDF_SP_PTR(x);
                    if (loadedBuffer == 0)
                    {
                        if (MLDF_ID_RT(fileId) == -1)
                        {
                            texRestructRefs(1);
                        }
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        MLDF_SP_SIZE(x) = 0;
                        MLDF_SP_ID(x) = mapId;
                        return 0;
                    }
                    else
                    {
                        if (sync != 0)
                        {
                            DVDRead(fi, loadedBuffer, MLDF_SP_SIZE(x), 0);
                            DVDClose(fi);
                            AtomicSList_Push(gDvdFileInfoPool, fi);
                            if (((gAssetLoadInFlightFlags & 0x20000000) == 0) && ((gAssetLoadInFlightFlags & 0x80000000) == 0))
                            {
                                mergeTableFiles(tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
                            }
                        }
                        else
                        {
                            if (slot == 0xd)
                            {
                                gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x10000000;
                            }
                            else
                            {
                                gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x40000000;
                            }
                            DVDReadAsyncPrio(fi, loadedBuffer, MLDF_SP_SIZE(x), 0, animCurvReadCb, 2);
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
            u32 slotSizeAddr;
            int slot;
            DVDFileInfo* fi;
            u32 slotPtrAddr;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtAnimCurvTab, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
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
                    MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                    DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                    if (sync != 0)
                    {
                        DVDRead(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        if (((gAssetLoadInFlightFlags & 0x20000000) == 0) && ((gAssetLoadInFlightFlags & 0x80000000) == 0))
                        {
                            mergeTableFiles(tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
                        }
                    }
                    else
                    {
                        if (slot == 0xe)
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x20000000;
                        }
                        else
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x80000000;
                        }
                        DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animCurvTabReadCb, 2);
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
            int slot;
            DVDFileInfo* fi;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtVoxmapBin, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
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
            MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
            DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
            if (sync != 0)
            {
                DVDRead(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                DVDClose(fi);
                AtomicSList_Push(gDvdFileInfoPool, fi);
                if (((gAssetLoadInFlightFlags & 0x2000000) == 0) && ((gAssetLoadInFlightFlags & 0x8000000) == 0))
                {
                    mergeTableFiles(tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
                }
            }
            else
            {
                if (slot == 0x1b)
                {
                    gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x1000000;
                }
                else
                {
                    gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x4000000;
                }
                MLDF_FINFO4(x) = fi;
                DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapReadCb, 2);
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
            int slot;
            DVDFileInfo* fi;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, nm->fmtVoxmapTab, MLDF_MAP_NAME(mapId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
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
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    return 0;
                }
                else
                {
                    MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                    DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                    if (sync != 0)
                    {
                        DVDRead(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        if (((gAssetLoadInFlightFlags & 0x2000000) == 0) && ((gAssetLoadInFlightFlags & 0x8000000) == 0))
                        {
                            mergeTableFiles(tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
                        }
                    }
                    else
                    {
                        if (slot == 0x1a)
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x2000000;
                        }
                        else
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x8000000;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapTabReadCb, 2);
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
            int slot;
            DVDFileInfo* fi;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
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
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                loadedBuffer = MLDF_SP_PTR(x);
                if (loadedBuffer == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, loadedBuffer, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        if (((gAssetLoadInFlightFlags & 0x20000) == 0) && ((gAssetLoadInFlightFlags & 0x80000) == 0))
                        {
                            mergeTableFiles(tbl->mergeBlocks, 0x26, 0x48, 0x800);
                        }
                    }
                    else
                    {
                        if (slot == 0x25)
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x10000;
                        }
                        else
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x40000;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, loadedBuffer, MLDF_SP_SIZE(x), 0, blocksReadCb, 2);
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
            int slot;
            DVDFileInfo* fi;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
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
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    if (((gAssetLoadInFlightFlags & 0x20000) == 0) && ((gAssetLoadInFlightFlags & 0x80000) == 0))
                    {
                        mergeTableFiles(tbl->mergeBlocks, 0x26, 0x48, 0x800);
                    }
                }
                else
                {
                    if (slot == 0x26)
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x20000;
                    }
                    else
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x80000;
                    }
                    MLDF_FINFO4(x) = fi;
                    DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, blocksTabReadCb, 2);
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
            int slot;
            DVDFileInfo* fi;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                loadedBuffer = MLDF_SP_PTR(x);
                if (loadedBuffer == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, loadedBuffer, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        if (((gAssetLoadInFlightFlags & 4) == 0) && ((gAssetLoadInFlightFlags & 8) == 0))
                        {
                            mergeTableFiles(tbl->mergeModels, 0x2a, 0x45, 0x800);
                        }
                        gModelsArchiveLoadCount = gModelsArchiveLoadCount + 1;
                    }
                    else
                    {
                        gModelsArchiveLoadCount = gModelsArchiveLoadCount + 1;
                        if (slot == 0x2b)
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 1;
                        }
                        else
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 2;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, loadedBuffer, MLDF_SP_SIZE(x), 0, modelsReadCb, 2);
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
            int slot;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            DVDFileInfo* fi;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    if (((gAssetLoadInFlightFlags & 4) == 0) && ((gAssetLoadInFlightFlags & 8) == 0))
                    {
                        mergeTableFiles(tbl->mergeModels, 0x2a, 0x45, 0x800);
                    }
                }
                else
                {
                    if (slot == 0x2a)
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 4;
                    }
                    else
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 8;
                    }
                    MLDF_FINFO4(x) = fi;
                    DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, modelsTabReadCb, 2);
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
            int slot;
            DVDFileInfo* fi;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                loadedBuffer = MLDF_SP_PTR(x);
                if (loadedBuffer == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, loadedBuffer, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        if (((gAssetLoadInFlightFlags & 0x40) == 0) && ((gAssetLoadInFlightFlags & 0x80) == 0))
                        {
                            mergeTableFiles(tbl->mergeAnim, 0x2f, 0x49, 3000);
                        }
                    }
                    else
                    {
                        if (slot == 0x30)
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x10;
                        }
                        else
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x20;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, loadedBuffer, MLDF_SP_SIZE(x), 0, animReadCb, 2);
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
            int slot;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            DVDFileInfo* fi;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    if (((gAssetLoadInFlightFlags & 0x40) == 0) && ((gAssetLoadInFlightFlags & 0x80) == 0))
                    {
                        mergeTableFiles(tbl->mergeAnim, 0x2f, 0x49, 3000);
                    }
                }
                else
                {
                    if (slot == 0x2f)
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x40;
                    }
                    else
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x80;
                    }
                    MLDF_FINFO4(x) = fi;
                    DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animTabReadCb, 2);
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
            int slot;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            DVDFileInfo* fi;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                loadedBuffer = MLDF_SP_PTR(x);
                if (loadedBuffer == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, loadedBuffer, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        if (((gAssetLoadInFlightFlags & 0x400) == 0) && ((gAssetLoadInFlightFlags & 0x800) == 0))
                        {
                            mergeTableFiles(tbl->mergeTex0, 0x24, 0x4e, 0x1000);
                        }
                    }
                    else
                    {
                        if (slot == 0x23)
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x100;
                        }
                        else
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x200;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, loadedBuffer, MLDF_SP_SIZE(x), 0, tex0readCb, 2);
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
            int slot;
            u32 slotPtrAddr;
            u32 slotSizeAddr;
            DVDFileInfo* fi;
            int ok;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    if (((gAssetLoadInFlightFlags & 0x400) == 0) && ((gAssetLoadInFlightFlags & 0x800) == 0))
                    {
                        mergeTableFiles(tbl->mergeTex0, 0x24, 0x4e, 0x1000);
                    }
                }
                else
                {
                    if (slot == 0x24)
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x400;
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex0tab1readCb, 2);
                    }
                    else
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x800;
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex0tab2readCb, 2);
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
            DVDFileInfo* fi;

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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(fi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                loadedBuffer = MLDF_SP_PTR(x);
                if (loadedBuffer == 0)
                {
                    if (MLDF_ID_RT(fileId) == -1)
                    {
                        texRestructRefs(1);
                    }
                    DVDClose(fi);
                    AtomicSList_Push(gDvdFileInfoPool, fi);
                    MLDF_SP_SIZE(x) = 0;
                    MLDF_SP_ID(x) = mapId;
                    return 0;
                }
                else
                {
                    if (sync != 0)
                    {
                        DVDRead(fi, loadedBuffer, MLDF_SP_SIZE(x), 0);
                        DVDClose(fi);
                        AtomicSList_Push(gDvdFileInfoPool, fi);
                        if (((gAssetLoadInFlightFlags & 0x4000) == 0) && ((gAssetLoadInFlightFlags & 0x8000) == 0))
                        {
                            mergeTableFiles(tbl->mergeTex1, 0x21, 0x4c, 0x1000);
                        }
                    }
                    else
                    {
                        if (slot == 0x20)
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x1000;
                        }
                        else
                        {
                            gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x2000;
                        }
                        MLDF_FINFO4(x) = fi;
                        DVDReadAsyncPrio(fi, loadedBuffer, MLDF_SP_SIZE(x), 0, tex1ReadCb, 2);
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
                mm_free(MLDF_SP_PTR(x));
                MLDF_SP_PTR(x) = 0;
            }
            sprintf(buf, sArchivePathFormat, MLDF_MAP_NAME(mapId), MLDF_FILE_NAME(fileId));
            tabFi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, tabFi);
            if (ok == 0)
            {
                return 0;
            }
            else
            {
                MLDF_SP_SIZE_INIT(x) = DVD_FI_LENGTH(tabFi);
                MLDF_SP_PTR(x) = mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
                if (sync != 0)
                {
                    DVDRead(tabFi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
                    DVDClose(tabFi);
                    AtomicSList_Push(gDvdFileInfoPool, tabFi);
                    if (((gAssetLoadInFlightFlags & 0x4000) == 0) && ((gAssetLoadInFlightFlags & 0x8000) == 0))
                    {
                        mergeTableFiles(tbl->mergeTex1, 0x21, 0x4c, 0x1000);
                    }
                }
                else
                {
                    MLDF_FINFO4(x) = tabFi;
                    if (slot == 0x21)
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x4000;
                        DVDReadAsyncPrio(tabFi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex1tab1readCb, 2);
                    }
                    else
                    {
                        gAssetLoadInFlightFlags = gAssetLoadInFlightFlags | 0x8000;
                        DVDReadAsyncPrio(tabFi, MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex1tab2readCb, 2);
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

/* The decompression path below manipulates loaded-buffer addresses as packed
   32-bit values, while mapLoadDataFile itself treats them as pointers. */
#undef MLDF_PTR
#define MLDF_PTR(s) ((u32)tbl->ptrs[s])

char sAssetHaltFormat[] = "HALT\t%s\n";
char sRomlistZlbPathFormat[] = "%s.romlist.zlb";

void* loadAndDecompressDataFile(int fileId, void* destBuf, int offsetFlags, u32 length, int* sizeOut, int entryIndex,
                                u32 flagBits)
{
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    u32 tab0 = 0; /* TAB ptr of the primary slot of the pair, 0 = not ready */
    u32 tab1 = 0; /* TAB ptr of the alternate slot of the pair */
    u8 frame = 0; /* run a full frame per wait iteration once dvd error UI is up */
    /* Slot-select scratch; case 0x2b reuses it for a flags snapshot and cases 0x51/0x4f for a TAB ptr. */
    u32 slotScratch;
    int entryOff;
    int flags;
    int intr;
    int i;
    int prev;
    u32 slotPtrAddr; /* &tbl->ptrs[fileId] biased +0x6A28 for MLDF_QPTR; the size probes reuse it
                        as the payload address */
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
        /* This file family does not use the caller's entry index. Reuse its
           local for one protected snapshot: both the BIN and TAB reads for a
           slot must finish before its merged table pointer is usable. */
        intr = OSDisableInterrupts();
        entryIndex = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0)
        {
            tab0 = MLDF_PTR(0xe);
        }
        if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0)
        {
            tab1 = MLDF_PTR(0x56);
        }
        slotScratch = offsetFlags & 0x80000000;
        if (slotScratch != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), entryIndex != 0)
            {
                if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0)
                {
                    tab0 = *(u32*)((char*)&tbl->ptrs[0] + 0x80000000);
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
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), entryIndex != 0)
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
        else if (slotScratch != 0 && tab0 != 0)
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
        entryIndex = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x2000000) == 0 && (entryIndex & 0x1000000) == 0)
        {
            tab0 = MLDF_PTR(0x1a);
        }
        if ((entryIndex & 0x8000000) == 0 && (entryIndex & 0x4000000) == 0)
        {
            tab1 = MLDF_PTR(0x53);
        }
        slotScratch = offsetFlags & 0x80000000;
        if (slotScratch != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), entryIndex != 0)
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
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), entryIndex != 0)
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
        else if (slotScratch != 0 && tab0 != 0)
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
        entryIndex = gAssetLoadInFlightFlags;
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
        slotScratch = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if (((int)slotScratch & 4) == 0 && ((int)slotScratch & 1) == 0)
        {
            tab0 = MLDF_PTR(0x2a);
        }
        if (((int)slotScratch & 8) == 0 && ((int)slotScratch & 2) == 0)
        {
            tab1 = MLDF_PTR(0x45);
        }
        entryOff = offsetFlags & 0x10000000;
        if (entryOff != 0 && tab0 == 0)
        {
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), flags != 0)
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
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), flags != 0)
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
        flags = gAssetLoadInFlightFlags;
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
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), flags != 0)
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
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), flags != 0)
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
            qptr = *(u32*)((fileId << 2) + (u32)&tbl->ptrs[0]);
            slotPtrAddr = qptr + offsetFlags;
            tmp = ObjModel_IsPackedResource((u8*)slotPtrAddr);
            if (tmp != 0)
            {
                *sizeOut = ObjModel_GetUnpackedResourceSize((u8*)slotPtrAddr, *sizeOut);
            }
        }
        break;
    case 0x51:
        slotScratch = MLDF_PTR(0x52);
        if (slotScratch != 0)
        {
            fileId = 0x51;
            if (sizeOut != NULL)
            {
                *sizeOut = (((u32*)(slotScratch + 4))[entryIndex] & 0xfffffff) -
                           (((u32*)slotScratch)[entryIndex] & 0xfffffff);
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        if (((u8)flagBits & 1) != 0)
        {
            qptr = *(u32*)((fileId << 2) + (u32)&tbl->ptrs[0]);
            slotPtrAddr = qptr + offsetFlags;
            tmp = ObjModel_IsPackedResource((u8*)slotPtrAddr);
            if (tmp != 0)
            {
                *sizeOut = ObjModel_GetUnpackedResourceSize((u8*)slotPtrAddr, *sizeOut);
            }
        }
        break;
    case 0x23:
        intr = OSDisableInterrupts();
        i = gAssetLoadInFlightFlags;
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
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0)
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
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0)
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
        i = gAssetLoadInFlightFlags;
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
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0)
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
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0)
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
    {
        u32 tabPtr;

        tabPtr = MLDF_PTR(0x50);
        if (tabPtr != 0)
        {
            fileId = 0x4f;
            if (sizeOut != NULL)
            {
                offsetFlags = ((int*)tabPtr)[entryIndex] & 0xffffff;
                if (offsetFlags == 0)
                {
                    do
                    {
                        prev = tab0;
                        tab0 = tab0 + 1;
                    } while ((((int*)tabPtr)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tabPtr - 4))[tab0] & 0xffffff) - offsetFlags;
                }
                else
                {
                    i = entryIndex;
                    do
                    {
                        prev = i;
                        i = i + 1;
                    } while ((((int*)tabPtr)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tabPtr - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        offsetFlags = offsetFlags & 0xfffffff;
        break;
    }
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
            memcpy(destBuf, (void*)(qptr + offsetFlags), length);
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
                zlbDecompress((u8*)(MLDF_QPTR + offsetFlags + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
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
                zlbDecompress((u8*)(MLDF_QPTR + offsetFlags + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
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
                memcpy(destBuf, (void*)(qptr + ((hdr->auxSize + 0x18) + (int)hdr - (int)qptr)),
                       hdr->decompressedSize);
            }
            else if (hdr->magic == 0xfacefeed)
            {
                zlbDecompress((u8*)(qptr + ((hdr->auxSize + 0x28) + (int)hdr - (int)qptr)), hdr->compressedSize - 0x10,
                              (u8*)destBuf, &hdr->decompressedSize);
                DCStoreRange(destBuf, hdr->decompressedSize);
            }
        }
        else if (fileId == 0x23 || fileId == 0x4d)
        {
            fileBuf = qptr + (offsetFlags & 0xffffff);
            decompSize = ZLB_HDR(fileBuf)->decompressedSize;
            zlbDecompress((u8*)(fileBuf + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf, &decompSize);
            DCStoreRange(destBuf, decompSize);
        }
        else if (fileId == 0x20 || fileId == 0x4b)
        {
            entryIndex = offsetFlags & 0xffffff;
            fileBuf = qptr + entryIndex;
            if (strncmp(sDirBlockTag, (char*)fileBuf, 3) == 0)
            {
                return (void*)(MLDF_QPTR + entryIndex + 0x20);
            }
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0)
            {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + entryIndex + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
            }
        }
        else if (fileId == 0x4f)
        {
            entryIndex = offsetFlags & 0xffffff;
            fileBuf = qptr + entryIndex;
            if (strncmp(sDirBlockTag, (char*)fileBuf, 3) == 0)
            {
                return (void*)(MLDF_QPTR + entryIndex + 0x20);
            }
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0)
            {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + entryIndex + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
            }
        }
        else if (fileId == 0x30 || fileId == 0x51 || fileId == 0x4a)
        {
            fileBuf = qptr + offsetFlags;
            tmp = ObjModel_IsPackedResource((u8*)fileBuf);
            if (tmp != 0)
            {
                ObjModel_UnpackResourcePayload((u8*)fileBuf, *sizeOut, (u8*)destBuf,
                                               ObjModel_GetUnpackedResourceSize((u8*)fileBuf, *sizeOut));
            }
            else
            {
                memcpy(destBuf, (void*)(MLDF_QPTR + offsetFlags), length);
            }
        }
        else
        {
            memcpy(destBuf, (void*)(qptr + offsetFlags), length);
        }
    }
    else if (fileId == 0x20 || fileId == 0x4b)
    {
        u32 srcBuf;

        DVDOpen(sResourceFileNameTable[fileId], &buf);
        alignedSize = (length + 0x1f) & 0xffffffe0;
        srcBuf = (u32)mmAlloc(alignedSize, 0x7f7f7fff, 0);
        DVDRead(&buf, (void*)srcBuf, alignedSize, offsetFlags & 0xffffff);
        DVDClose(&buf);
        DCStoreRange((void*)srcBuf, length);
        if (strncmp(sDirBlockTag, (char*)srcBuf, 3) == 0)
        {
            for (;;)
            {
            }
        }
        if (strncmp((char*)srcBuf, sZlbBlockTag, 3) == 0)
        {
            decompSize = ZLB_HDR(srcBuf)->decompressedSize;
            zlbDecompress((u8*)(srcBuf + 0x10), ZLB_HDR(srcBuf)->compressedSize, (u8*)destBuf, &decompSize);
        }
        mm_free((void*)srcBuf);
    }
    else
    {
        DVDOpen(sResourceFileNameTable[fileId], &buf);
        if (((u32)destBuf & 0x1f) != 0 || ((int)length & 0x1f) != 0)
        {
            u32 bounceSize;
            int bounceBuf;

            bounceSize = (length + 0x1f) & 0xffffffe0;
            bounceBuf = (int)mmAlloc(bounceSize, 0x7f7f7fff, 0);
            DVDRead(&buf, (void*)bounceBuf, bounceSize, offsetFlags);
            memcpy(destBuf, (void*)bounceBuf, length);
            mm_free((void*)bounceBuf);
        }
        else
        {
            DVDRead(&buf, destBuf, length, offsetFlags);
        }
        DCStoreRange(destBuf, length);
        DVDClose(&buf);
    }
    return 0;
}

extern int gMapRomListBuffers[];


int mapGetDirIdx(int idx)
{
    if (idx >= 0x4b)
        return 5;
    return sMapFileNameIndexRemapTable[idx];
}


extern int gResourcePendingMapIds[];

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
    if (gDefragDelayFrames != 0)
    {
        if (gDefragDelayFrames == 1)
        {
            defragMemory(0);
        }
        gDefragDelayFrames--;
    }
    for (i = 0; i <= 0x57; i++)
    {
        if (gResourcePendingMapIds[i] != -1)
        {
            debugPrintSetColor(0, 0xff, 0, 0xff);
            logPrintf(sAssetHaltFormat, sResourceFileNameTable[i]);
            debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
            gForceLoadImmediately = 1;
            if (mapLoadDataFile(gResourcePendingMapIds[i], i) != 0)
            {
                gResourcePendingMapIds[i] = -1;
                printHeapStats(1);
            }
            gForceLoadImmediately = 0;
        }
    }
    loadTableFiles();
}
void piRomLoadSection(int romOffset, int mapIndex, void* destBuf)
{
    char buf[1024];
    DVDFileInfo* fi;
    int ok;
    struct PackHeader* hdr;

    if ((destBuf == NULL) && ((void*)gMapRomListBuffers[mapIndex] == NULL))
    {
        sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
        fi = AtomicSList_Pop(gDvdFileInfoPool);
        ok = DVDOpen(buf, fi);
        if (ok != 0)
        {
            gMapRomListBuffers[mapIndex] = (int)mmAlloc(DVD_FI_LENGTH(fi), 0x7d7d7d7d, 0);
            gRomListLoadInFlight = 1;
            DVDReadAsyncPrio(fi, (void*)gMapRomListBuffers[mapIndex], DVD_FI_LENGTH(fi), 0, romListReadCb, 2);
        }
    }
    else
    {
        if ((void*)gMapRomListBuffers[mapIndex] == NULL)
        {
            sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0)
            {
                return;
            }
            gMapRomListBuffers[mapIndex] = (int)mmAlloc(DVD_FI_LENGTH(fi), 0x7d7d7d7d, 0);
            DVDRead(fi, (void*)gMapRomListBuffers[mapIndex], DVD_FI_LENGTH(fi), 0);
            DVDClose(fi);
            AtomicSList_Push(gDvdFileInfoPool, fi);
        }
        hdr = (struct PackHeader*)(gResourceFileBuffers[0x1d] + romOffset);
        if (hdr->magic == 0xfacefeed)
        {
            zlbDecompress((u8*)(gMapRomListBuffers[mapIndex] + 0x10), hdr->compressedSize, (u8*)destBuf, &hdr->decompressedSize);
            DCStoreRange(destBuf, hdr->decompressedSize);
        }
    }
}

void tex1GetFrame(int texId, int unused, int* outA, int* outB, int count, int* frameTable, int queryMode)
{
    int idx = -1;
    if (gResourceFileBuffers[0x20] != 0 || gResourceFileBuffers[0x4b] != 0)
    {
        int s = OSDisableInterrupts();
        int flags = gAssetLoadInFlightFlags;
        u32 f46c;
        u32 f518;
        OSRestoreInterrupts(s);
        f46c = gResourceFileBuffers[0x21];
        f518 = gResourceFileBuffers[0x4c];
        if ((texId & 0x80000000) != 0 && (flags & 0x2000) == 0)
        {
            idx = 0x4b;
        }
        else if ((texId & 0x40000000) != 0 && (flags & 0x1000) == 0)
        {
            idx = 0x20;
        }
        else if (f46c != 0 && (flags & 0x1000) == 0 && gResourceFileBuffers[0x20] != 0)
        {
            idx = 0x20;
        }
        else if (f518 != 0 && (flags & 0x2000) == 0 && gResourceFileBuffers[0x4b] != 0)
        {
            idx = 0x4b;
        }
        {
            u32 base = gResourceFileBuffers[idx];
            if (base != 0)
            {
                if (queryMode == 1 && frameTable != 0)
                {
                    int e = (texId & 0xffffff) * 2 + frameTable[count];
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
                    int e = frameTable[count];
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


void tex0GetFrame(int texId, int unused, int* outA, int* outB, int count, int* frameTable, int queryMode)
{
    int idx = -1;
    if (gResourceFileBuffers[0x23] != 0 || gResourceFileBuffers[0x4d] != 0)
    {
        int s = OSDisableInterrupts();
        int flags = gAssetLoadInFlightFlags;
        u32 f478;
        u32 f520;
        OSRestoreInterrupts(s);
        f478 = gResourceFileBuffers[0x24];
        f520 = gResourceFileBuffers[0x4e];
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
            int base = gResourceFileBuffers[idx];
            int e = base + (texId & 0xffffff) * 2 + frameTable[count] + 4;
            int v = *(int*)(e + 8);
            *outA = *(int*)(e + 4);
            *outB = v;
        }
        else if (queryMode == 2 && frameTable != 0)
        {
            memcpy(frameTable, (void*)(gResourceFileBuffers[idx] + (texId & 0xffffff) * 2), (count + 1) * 4);
        }
        else
        {
            int e = gResourceFileBuffers[idx] + (texId & 0xffffff) * 2 + 4;
            int v = *(int*)(e + 8);
            *outA = *(int*)(e + 4);
            *outB = v;
        }
    }
}


void texPreGetMipmap(int texId, int unused, int* outA, int* outB, int count, int* frameTable, int queryMode)
{
    u32 base = gResourceFileBuffers[0x4f];
    if (base != 0)
    {
        if (queryMode == 1 && frameTable != 0)
        {
            int e = base + (texId & 0xffffff) * 2 + frameTable[count] + 4;
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
    if (gResourceFileBuffers[0x2b] != 0 || gResourceFileBuffers[0x46] != 0)
    {
        saved = OSDisableInterrupts();
        flags = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(saved);
        if ((flags & 4) == 0 && (flags & 1) == 0)
        {
            tab0 = gResourceFileBuffers[0x2a];
        }
        if ((flags & 8) == 0 && (flags & 2) == 0)
        {
            tab1 = gResourceFileBuffers[0x45];
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
        entry = (char*)gResourceFileBuffers[idx] + (offsetFlags & 0x0fffffff);
        *p18 = *(int*)(entry + 0x18);
        *p1c = *(int*)(entry + 0x1c);
        *p20 = *(int*)(entry + 0x20);
        *p4 = *(int*)(entry + 0x4);
    }
}


void mapsBinGetRomlistSize(int idx, int* out1, int* out2, int* out3, int p5)
{
    char* e;
    if ((void*)gResourceFileBuffers[0x1d] == NULL)
        return;
    if ((void*)gResourceFileBuffers[0x1e] == NULL)
        return;
    e = (char*)gResourceFileBuffers[0x1d] + idx;
    *out1 = *(s16*)(e + 0x1c);
    *out2 = *(s16*)(e + 0x1e);
    *out3 = *(int*)((char*)gResourceFileBuffers[0x1d] +
                    *(int*)((char*)gResourceFileBuffers[0x1e] + p5 * 4 + 0x18) + 4);
}

void checkLoadBlock(int a, int* pc, int* p8)
{
    int idx = -1;
    int flags;
    int saved;
    char* blk;
    u32 t25, t47;
    if ((gResourceFileBuffers[0x26] != 0 && gResourceFileBuffers[0x25] != 0) || (gResourceFileBuffers[0x48] != 0 && gResourceFileBuffers[0x47] != 0))
    {
        saved = OSDisableInterrupts();
        flags = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(saved);
        t25 = gResourceFileBuffers[0x25];
        t47 = gResourceFileBuffers[0x47];
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
        blk = (char*)gResourceFileBuffers[idx] + (a & 0x00ffffff);
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
    if ((gResourceFileBuffers[0x1a] != 0 && gResourceFileBuffers[0x1b] != 0) || (gResourceFileBuffers[0x53] != 0 && gResourceFileBuffers[0x54] != 0))
    {
        saved = OSDisableInterrupts();
        flags = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(saved);
        t1b = gResourceFileBuffers[0x1b];
        t54 = gResourceFileBuffers[0x54];
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
            blk = (char*)gResourceFileBuffers[idx] + (a & 0x00ffffff);
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

extern u32 gResourceFileSizes[];

s32 getDataFileSize(int idx)
{
    if (gResourceFileBuffers[idx] != 0)
    {
        return gResourceFileSizes[idx];
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
    if (gResourceFileBuffers[id] != 0)
    {
        {
            int base = gResourceFileBuffers[id];
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
    if (gResourceFileBuffers[id] != 0)
    {
        memcpy(buffer, (void*)gResourceFileBuffers[id], gResourceFileSizes[id]);
        DCStoreRange(buffer, gResourceFileSizes[id]);
        return gResourceFileSizes[id];
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
    if (gResourceFileBuffers[id] != 0)
    {
        return (void*)gResourceFileBuffers[id];
    }
    DVDOpen(sResourceFileNameTable[id], &fileInfo);
    gResourceFileSizes[id] = fileInfo.length;
    gResourceFileBuffers[id] = (u32)mmAlloc(gResourceFileSizes[id] + 0x20, 0x7d7d7d7d, 0);
    DCInvalidateRange((void*)gResourceFileBuffers[id], gResourceFileSizes[id]);
    DVDRead(&fileInfo, (void*)gResourceFileBuffers[id], gResourceFileSizes[id], 0);
    DVDClose(&fileInfo);
    return (void*)gResourceFileBuffers[id];
}

u8 initLoadFiles(void)
{
    int i;
    DVDFileInfo* fileInfo;
    int* rom;
    struct MldfIterators it;
    u8* himem;
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    if (gLoadFilesInitDone == 0)
    {
        gLoadFilesInitDone = 1;
        gPendingDvdReadCount = 0;
        gDvdFileInfoPool = stackCreate(0x5e, 0x40);
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
                    fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
                    DVDOpen(*it.names, fileInfo);
                    *it.sizes = fileInfo->length;
                    *it.ptrs = mmAlloc(*it.sizes + 0x20, 0x7d7d7d7d, 0);
                    gPendingDvdReadCount = gPendingDvdReadCount + 1;
                    DVDReadAsyncPrio(fileInfo, *it.ptrs, *it.sizes, 0, initLoadFileReadCb, 2);
                }
                *it.owners = -1;
                *it.ids = -1;
                break;
            }
            *it.flags = 0;
        }
    }
    if (gPendingDvdReadCount == 0)
    {
        if (((gAssetLoadInFlightFlags & 0x100) == 0 || (gAssetLoadInFlightFlags & 0x400) == 0) &&
            ((gAssetLoadCompletedFlags & 0x100) == 0 || (gAssetLoadCompletedFlags & 0x400) == 0))
        {
            int saved = mmSetDelay(0);
            mapLoadDataFile(5, MLDF_FILEID_TEX0_BIN_A);
            mapLoadDataFile(5, MLDF_FILEID_TEX0_TAB_A);
            mmSetDelay(saved);
        }
        else if ((gAssetLoadCompletedFlags & 0x100) != 0 && (gAssetLoadCompletedFlags & 0x400) != 0)
        {
            mergeTableFiles(tbl->mergeModels, 0x2a, 0x45, 0x800);
            mergeTableFiles(tbl->mergeAnim, 0x2f, 0x49, 3000);
            mergeTableFiles(tbl->mergeTex0, 0x24, 0x4e, 0x1000);
            mergeTableFiles(tbl->mergeTex1, 0x21, 0x4c, 0x1000);
            mergeTableFiles(tbl->mergeBlocks, 0x26, 0x48, 0x800);
            gAssetLoadCompletedFlags = 0;
            gAssetLoadInFlightFlags = 0;
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


extern volatile PPCWGPipe GXWGFifo : (0xCC008000);


void gpuErrorHandler(u32 retraceCount);
void videoSwapFrameBuffers(u32 retraceCount);
void videoBreakPointCallback(void);

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

    if (gFlipTokenHeldForDisplayedFb != 0 && gFrameBufferFlipped != 0)
    {
        Queue_Pop(&gVideoFlipQueue, tok);
        gGpuStallRetraceCount = 0;
        OSWakeupThread((OSThreadQueue*)&gVideoFlipWaitQueue);
        if (Queue_IsEmpty(&gVideoFlipQueue) != 0)
        {
            GXDisableBreakPt();
            gGxBreakPtEnabled = 0;
        }
        else
        {
            Queue_Peek(&gVideoFlipQueue, tok);
            GXEnableBreakPt((void*)tok[0]);
            gGxBreakPtEnabled = 1;
        }
        gFlipTokenHeldForDisplayedFb = 0;
        gFrameBufferFlipped = 0;
    }
    gPadReadReady = 1;
    gVideoRetracePending = 1;
    switch (gResetButtonPressState)
    {
    case 0:
        if (OSGetResetButtonState() != 0)
        {
            gResetButtonPressState++;
        }
        break;
    case 1:
        if (OSGetResetButtonState() == 0)
        {
            gResetButtonPressState++;
            setShouldResetNextFrame(1);
        }
        break;
    }
    if (enableDebugText != 0 && gVideoWaitThread != NULL && (u32)gGpuStallRetraceCount > 600)
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
        debugPrintfxy(0x32, 0xa0, sProgramCounterFormat, gVideoWaitThread->context.srr0);
    }
}
void logGpuHang(void);

void videoSwapFrameBuffers(u32 retraceCount)
{
    u16 sync;
    int tok[3];
    GXFifoObj fifo;

    gRetraceCountSinceFlip = gRetraceCountSinceFlip + 1;
    sync = GXReadDrawSync();
    if (sync == (u16)(gLastDrawSyncToken + 1))
    {
        gLastDrawSyncToken = sync;
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
        gFrameBufferFlipped = 1;
        lbl_803DB5C8 = gRetraceCountSinceFlip;
        gRetraceCountSinceFlip = 0;
    }
    gGpuStallRetraceCount = gGpuStallRetraceCount + 1;
    if (gGpuHangRecoveryEnabled != 0 && (u32)gGpuStallRetraceCount > 18000)
    {
        logGpuHang();
        mapBlockGpuRecoveryHook();
        ObjModel_TouchModelCache();
        __GXAbortWaitPECopyDone();
        GXInitFifoBase(&fifo, renderFrameBuffer, 0x10000);
        GXSetCPUFifo(&fifo);
        GXSetGPFifo(&fifo);
        gGxFifoObj = GXInit(gGxFifoBase, gGxFifoSize);
        if (Queue_IsEmpty(&gVideoFlipQueue) == 0)
        {
            Queue_Pop(&gVideoFlipQueue, tok);
        }
        OSWakeupThread((OSThreadQueue*)&gVideoFlipWaitQueue);
        if (Queue_IsEmpty(&gVideoFlipQueue) != 0)
        {
            GXDisableBreakPt();
            gGxBreakPtEnabled = 0;
        }
        else
        {
            Queue_Peek(&gVideoFlipQueue, tok);
            GXEnableBreakPt((void*)tok[0]);
        }
        gxSetGPMetricsEnabled(1);
    }
}

void videoBreakPointCallback(void)
{
    char peek[12];
    int tok[3];
    int i;

    if (gAttractMovieState == 2 || gAttractMovieState == 3)
    {
        THPPlayerPostDrawDone();
    }
    Queue_Peek(&gVideoFlipQueue, &peek);
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
        gFlipTokenHeldForDisplayedFb = 1;
        gFrameBufferFlipped = 0;
    }
    else
    {
        Queue_Pop(&gVideoFlipQueue, tok);
        gGpuStallRetraceCount = 0;
        OSWakeupThread((OSThreadQueue*)&gVideoFlipWaitQueue);
        if (Queue_IsEmpty(&gVideoFlipQueue) != 0)
        {
            GXDisableBreakPt();
            gGxBreakPtEnabled = 0;
        }
        else
        {
            Queue_Peek(&gVideoFlipQueue, tok);
            GXEnableBreakPt((void*)tok[0]);
            gGxBreakPtEnabled = 1;
        }
    }
}

RingBufferQueue gVideoFlipQueue;
char gVideoFlipQueueBuffer[0x78];
OSStopwatch gFrameStopwatch;
s16 gObjMapBlockInfo[0x9C];
u32 gResourceFileBuffers[0x58];
int gMapRomListBuffers[0x78];
u32 gResourceFileSizes[0x58];
int gResourcePendingMapIds[0x58];
u32 gObjBlockStatus[0x63F6];
u8 gResourceFileTable[0x160];
