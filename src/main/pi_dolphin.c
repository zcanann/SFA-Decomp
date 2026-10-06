#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/debug_display.h"
#include "main/gamebits.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "dolphin/gx/GXMisc.h"
#include "main/pi_dolphin.h"
#include "main/gpu_hang.h"
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
#include "MSL_C/PPCEABI/bare/H/math_api.h"
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
char* gPathSearchLastNonTrickyPoint;
u32 sPiUnused1;
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
OSThreadQueue gVideoFlipWaitQueue;
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

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200
extern u8 gResourceFileTable[0x160]; /* resource file table -- see struct MldfTables */
extern u32 gObjBlockStatus[];

/* Address view of neighbouring filename, map and path globals, not one allocation. */
struct MldfNames {
    u8 pad0[0x3ac];
    char* fileNames[0x22e];
    char* mapNames[0x49];
    int remapGroups[0x4b];
#if defined(VERSION_GSAE01) || defined(VERSION_GSAJ01)
    s16 adjacency[0x2be];
#else
    s16 adjacency[0x2ae];
#endif
    char fmtAnimCurvBin[0x10];
    char fmtAnimCurvTab[0x10];
    char fmtVoxmapBin[0x10];
    char fmtWarlockVoxmap[0x14];
    char fmtVoxmapTab[0x10];
    char fmtModBin[0x14];
    char fmtModTab[0x10];
};

/* Address view of neighbouring resource arrays relative to gResourceFileTable.
   This is not one allocation: gResourceFileTable itself contains only 0x160 bytes. File slots are
   indexed by resource fileId (0..0x57); map-owned resources use paired slots (e.g.
   ANIMCURV 0xd/0x55) so two maps can be resident at once. Several arrays are also
   addressed directly through their own symbols elsewhere in this file:
   ids   == gResourcePendingMapIds (pending mapId per slot, -1 = none; retried by loadDataFiles)
   sizes == gResourceFileSizes, romList == gMapRomListBuffers, ptrs == gResourceFileBuffers. */
struct MldfTables {
    u8 pad0[0x160];
    DVDFileInfo* fileInfo[0x58]; /* async read in flight */
    u32 mergeAnimCurv[0x1fd0];   /* merged 2-slot TAB, 0x1fd0 entries */
    u32 mergeVoxMap[0x800];      /* 0x800 entries */
    u32 mergeBlocks[0x800];      /* 0x800 entries */
    u32 mergeTex1[0x1000];       /* 0x1000 entries */
    u32 mergeTex0[0x1000];       /* 0x1000 entries */
    u32 mergeAnim[0xbb8];        /* 3000 entries */
    u32 mergeModels[0x800];      /* 0x800 entries */
    u8 loadedFlags[0x58];        /* cleared by initLoadFiles */
    int ids[0x58];               /* mapId whose load must be retried, -1 = none */
    int sizes[0x58];             /* byte size of the loaded file */
    void* romList[0x78];         /* per-MAP romlist buffer (indexed by mapIndex) */
    void* ptrs[0x58];            /* loaded file buffer, NULL = not resident */
    s16 owners[0x60];            /* mapId owning the slot, -1 = free */
};

STATIC_ASSERT(offsetof(struct MldfTables, mergeAnimCurv) == 0x2C0);
STATIC_ASSERT(offsetof(struct MldfTables, mergeVoxMap) == 0x8200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeBlocks) == 0xA200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeTex1) == 0xC200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeTex0) == 0x10200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeAnim) == 0x14200);
STATIC_ASSERT(offsetof(struct MldfTables, mergeModels) == 0x170E0);
STATIC_ASSERT(offsetof(struct MldfTables, ids) == 0x19138);
STATIC_ASSERT(offsetof(struct MldfTables, loadedFlags) == 0x190E0);
STATIC_ASSERT(offsetof(struct MldfTables, sizes) == 0x19298);
STATIC_ASSERT(offsetof(struct MldfTables, romList) == 0x193F8);
STATIC_ASSERT(offsetof(struct MldfTables, ptrs) == 0x195D8);
STATIC_ASSERT(offsetof(struct MldfTables, owners) == 0x19738);

typedef u8 MldfArenaBlock[0x20000];
enum {
    MLDF_ROM_LIST_PTRS_FROM_ARENA_END = (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, romList)) / sizeof(void*),
    MLDF_BUFFER_PTRS_FROM_ARENA_END = sizeof(MldfArenaBlock) - offsetof(struct MldfTables, ptrs),
    MLDF_BUFFER_SLOT_SHIFT = sizeof(void*) == 8 ? 3 : 2
};

/* Keep the retail shift expression: MWCC schedules a multiplication differently. */
STATIC_ASSERT((1u << MLDF_BUFFER_SLOT_SHIFT) == sizeof(void*));
STATIC_ASSERT(sizeof(ptrdiff_t) == sizeof(void*));

struct MldfIterators {
    void** ptrs;
    s16* owners;
    int* ids;
    char** names;
    int* sizes;
    u8* flags;
};

/* Resource-buffer view shared with the payload loader. */
#define MLDF_PTR(s)      (tbl->ptrs[s])
#define MLDF_ID_RT(t, s)    (*(int*)(((s) << 2) + (size_t)(t)->ids))
#define MLDF_OWNER_RT(t, s) (*(s16*)(((s) << 1) + (size_t)(t)->owners))
#define MLDF_PTR_RT(t, s)   (*(void**)(((s) << MLDF_BUFFER_SLOT_SHIFT) + (size_t)(t)->ptrs))
#define MLDF_QPTR        ((u8*)*(void**)(slotPtrAddr - MLDF_BUFFER_PTRS_FROM_ARENA_END))

/* 16-byte header of a "ZLB"-tagged compressed stream; the deflate payload
   follows at +0x10. "DIR"-tagged data is stored raw. */
struct ZlbHeader {
    char tag[4]; /* "ZLB" (sZlbBlockTag) / "DIR" (sDirBlockTag) */
    u32 unk4;
    u32 decompressedSize; /* +0x08 */
    int compressedSize;   /* +0x0c */
};
#define ZLB_HDR(buf) ((struct ZlbHeader*)(buf))

/* DVDFileInfo.length: byte length of the opened file. */
#define DVD_FI_LENGTH(fi) ((fi)->length)

/* header of a packed rom section (romlist blocks, MAPS.BIN sections) */
struct PackHeader {
    u32 magic;            /* 0xFACEFEED = zlb-packed, 0xE0E0E0E0 = stored raw */
    int decompressedSize; /* +0x04 (decompressed in place: also the zlb size out-slot) */
    int auxSize;          /* +0x08: extra bytes between header and payload */
    int compressedSize;   /* +0x0c */
};

/* MODELS archive prefix read by loadModelsBin, before any payload decoding.
 * The auxiliary block may extend beyond these recovered metadata fields. */
typedef struct ModelArchiveHeaderPrefix {
    struct PackHeader pack;
    u8 unk10[8];
    s32 useCachedAnimations;
    s32 animationCount;
    s32 maxAnimationBytes;
} ModelArchiveHeaderPrefix;

STATIC_ASSERT(sizeof(ModelArchiveHeaderPrefix) == 0x24);
STATIC_ASSERT(offsetof(ModelArchiveHeaderPrefix, pack.decompressedSize) == 0x04);
STATIC_ASSERT(offsetof(ModelArchiveHeaderPrefix, useCachedAnimations) == 0x18);
STATIC_ASSERT(offsetof(ModelArchiveHeaderPrefix, animationCount) == 0x1C);
STATIC_ASSERT(offsetof(ModelArchiveHeaderPrefix, maxAnimationBytes) == 0x20);

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

void initLoadFileReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        gPendingDvdReadCount--;
    }
}

// DVDGetCommandBlockStatus() command-block states (DVD_STATE_*)

s32 ObjLoad_GetDvdCommandBlockStatus(DVDCommandBlock* block) {
    s32 status;
    if (block == NULL) {
        return -1;
    }
    status = DVDGetCommandBlockStatus(block);
    switch (status) {
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

void clearForceLoadImmediately(void) {
    gForceLoadImmediately = 0x0;
}
void setForceLoadImmediately(void) {
    gForceLoadImmediately = 0x1;
}
static inline int loadedFileFlags(void) {
    int s = OSDisableInterrupts();
    u32 v = gAssetLoadInFlightFlags;
    OSRestoreInterrupts(s);
    return v;
}

void defragMemory(int mode) {
    void* replacement;
    void** buffers;
    s16* owners;
    int* sizes;
    u8* flags;
    int fileId;
    int passIndex;
    int stable;
    int previousFreeDelay;
    u32 resourceAddress = (u32)gResourceFileTable;
    stable = 0;
    passIndex = 0;
    mmSetTextureAllocationState(2);
    if (loadedFileFlags() != 0) {
        return;
    }
    if (mode == 0 && gDefragDelayFrames == 0) {
        texRestructRefs(0);
        gDefragDelayFrames = 6;
        return;
    }
    if (mode != 0) {
        int fileId;
        void** moveBuffers;
        s16* moveOwners;
        int* moveSizes;
        u8* moveFlags;
        mmSetForceHeaps1and2Only(1);
        fileId = 0;
        {
            u32 biasedBase = resourceAddress + sizeof(MldfArenaBlock);
            moveBuffers = (void**)(biasedBase - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, ptrs)));
            moveOwners = (s16*)(biasedBase - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, owners)));
            moveSizes = (int*)(biasedBase - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, sizes)));
            moveFlags = (u8*)(biasedBase - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, loadedFlags)));
        }
        do {
            switch (fileId) {
            case MLDF_FILEID_ANIMCURV_BIN_A:
            case MLDF_FILEID_VOXMAP_BIN_A:
            case MLDF_FILEID_TEX0_BIN_A:
            case MLDF_FILEID_BLOCKS_BIN_A:
            case MLDF_FILEID_MODELS_BIN_A:
            case MLDF_FILEID_ANIM_BIN_A:
            case MLDF_FILEID_MODELS_BIN_B:
            case MLDF_FILEID_BLOCKS_BIN_B:
            case MLDF_FILEID_ANIM_BIN_B:
            case MLDF_FILEID_TEX0_BIN_B:
            case MLDF_FILEID_VOXMAP_BIN_B:
            case MLDF_FILEID_ANIMCURV_BIN_B: {
                if (*moveBuffers == NULL) {
                    break;
                }
                if (*moveOwners == -1) {
                    break;
                }
                if (mmGetRegionForPtr(*moveBuffers) != 0) {
                    break;
                }
                if (mode == 2) {
                    if (fileId == MLDF_FILEID_TEX1_BIN_A) {
                        break;
                    }
                    if (fileId == MLDF_FILEID_TEX1_BIN_B) {
                        break;
                    }
                    if (fileId == MLDF_FILEID_TEX0_BIN_A) {
                        break;
                    }
                    if (fileId == MLDF_FILEID_TEX0_BIN_B) {
                        break;
                    }
                }
                replacement = mmAlloc(*moveSizes + 0x20, 0x7d7d7d7d, 0);
                if (replacement == NULL) {
                    break;
                }
                memcpy(replacement, *moveBuffers, *moveSizes);
                {
                    int previousFreeDelay = mmSetFreeDelay(0);
                    mm_free(*moveBuffers);
                    *moveBuffers = NULL;
                    *moveBuffers = replacement;
                    mmSetFreeDelay(previousFreeDelay);
                }
                break;
            }
            }
            *moveFlags = 0;
            moveBuffers++;
            moveOwners++;
            moveSizes++;
            moveFlags++;
            fileId++;
        } while (fileId <= MLDF_FILEID_ENVFXACT_BIN);
        mmSetForceHeaps1and2Only(-1);
    }
    resourceAddress = (u32)((char*)resourceAddress + sizeof(MldfArenaBlock));
    while (stable == 0 && passIndex < 10) {
        stable = 1;
        fileId = 0;
        buffers = (void**)(resourceAddress - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, ptrs)));
        owners = (s16*)(resourceAddress - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, owners)));
        sizes = (int*)(resourceAddress - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, sizes)));
        flags = (u8*)(resourceAddress - (int)(sizeof(MldfArenaBlock) - offsetof(struct MldfTables, loadedFlags)));
        do {
            switch (fileId) {
            case MLDF_FILEID_ANIMCURV_BIN_A:
            case MLDF_FILEID_VOXMAP_BIN_A:
            case MLDF_FILEID_TEX0_BIN_A:
            case MLDF_FILEID_BLOCKS_BIN_A:
            case MLDF_FILEID_MODELS_BIN_A:
            case MLDF_FILEID_ANIM_BIN_A:
            case MLDF_FILEID_MODELS_BIN_B:
            case MLDF_FILEID_BLOCKS_BIN_B:
            case MLDF_FILEID_ANIM_BIN_B:
            case MLDF_FILEID_TEX0_BIN_B:
            case MLDF_FILEID_VOXMAP_BIN_B:
            case MLDF_FILEID_ANIMCURV_BIN_B: {
                if (*buffers != NULL && *owners != -1 && mmGetRegionForPtr(*buffers) == 0) {
                    replacement = mmAlloc(*sizes + 0x20, 0x7d7d7d7d, 0);
                    if (replacement == NULL) {
                        break;
                    }
                    if (*sizes >= MM_REGION0_LARGE_ALLOCATION_THRESHOLD && (u32)*buffers < (u32)replacement) {
                        int previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(replacement);
                        mmSetFreeDelay(previousFreeDelay);
                    } else if (*sizes < MM_REGION0_LARGE_ALLOCATION_THRESHOLD && (u32)*buffers > (u32)replacement) {
                        int previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(replacement);
                        mmSetFreeDelay(previousFreeDelay);
                    } else {
                        int previousFreeDelay;
                        memcpy(replacement, *buffers, *sizes);
                        previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(*buffers);
                        *buffers = NULL;
                        *buffers = replacement;
                        mmSetFreeDelay(previousFreeDelay);
                        stable = 0;
                    }
                } else {
                    if (mode == 2) {
                        break;
                    }
                    if (passIndex == 0) {
                        break;
                    }
                    if (*buffers == NULL) {
                        break;
                    }
                    if (*owners == -1) {
                        break;
                    }
                    if (mmGetRegionForPtr(*buffers) != 1 && mmGetRegionForPtr(*buffers) != 2) {
                        break;
                    }
                    if (getHeapItemSize(*buffers) < 0x3000) {
                        break;
                    }
                    replacement = mmAlloc(*sizes + 0x20, 0x7d7d7d7d, 0);
                    if (replacement == NULL) {
                        break;
                    }
                    if (mmGetRegionForPtr(replacement) != 0) {
                        int previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(replacement);
                        mmSetFreeDelay(previousFreeDelay);
                    } else {
                        memcpy(replacement, *buffers, *sizes);
                        previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(*buffers);
                        *buffers = NULL;
                        *buffers = replacement;
                        mmSetFreeDelay(previousFreeDelay);
                        stable = 0;
                    }
                }
                break;
            }
            }
            *flags = 0;
            buffers++;
            owners++;
            sizes++;
            flags++;
            fileId++;
        } while (fileId <= MLDF_FILEID_ENVFXACT_BIN);
        passIndex++;
    }
    mmSetTextureAllocationState(0);
}

void animCurvReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x10000000) {
            gAssetLoadCompletedFlags |= 0x10000000;
            gObjBlockStatus[0x34 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x40000000) {
            gAssetLoadCompletedFlags |= 0x40000000;
            gObjBlockStatus[0x154 / 4] = 0;
        }
    }
}

void animCurvTabReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x20000000) {
            gAssetLoadCompletedFlags |= 0x20000000;
            gObjBlockStatus[0x38 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x80000000) {
            gAssetLoadCompletedFlags |= 0x80000000;
            gObjBlockStatus[0x158 / 4] = 0;
        }
    }
}

void voxMapReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x1000000) {
            gAssetLoadCompletedFlags |= 0x1000000;
            gObjBlockStatus[0x6c / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x4000000) {
            gAssetLoadCompletedFlags |= 0x4000000;
            gObjBlockStatus[0x150 / 4] = 0;
        }
    }
}

void voxMapTabReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x2000000) {
            gAssetLoadCompletedFlags |= 0x2000000;
            gObjBlockStatus[0x68 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x8000000) {
            gAssetLoadCompletedFlags |= 0x8000000;
            gObjBlockStatus[0x14c / 4] = 0;
        }
    }
}

void blocksTabReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x20000) {
            gAssetLoadCompletedFlags |= 0x20000;
            gObjBlockStatus[0x98 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x80000) {
            gAssetLoadCompletedFlags |= 0x80000;
            gObjBlockStatus[0x120 / 4] = 0;
        }
    }
}

void romListReadCb(s32 result, DVDFileInfo* fileInfo) {
    gRomListLoadInFlight = 0;
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    }
}

void blocksReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x10000) {
            gAssetLoadCompletedFlags |= 0x10000;
            gObjBlockStatus[0x94 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x40000) {
            gAssetLoadCompletedFlags |= 0x40000;
            gObjBlockStatus[0x11c / 4] = 0;
        }
    }
}

void tex1tab2readCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free(gResourceFileBuffers[78]);
        gResourceFileBuffers[78] = 0;
        gObjBlockStatus[78] = 0;
        if (gAssetLoadInFlightFlags & 0x8000) {
            gAssetLoadCompletedFlags |= 0x8000;
            gObjBlockStatus[76] = 0;
        }
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x8000) {
            gAssetLoadCompletedFlags |= 0x8000;
            gObjBlockStatus[76] = 0;
        }
    }
}

void tex1tab1readCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free(gResourceFileBuffers[78]);
        gResourceFileBuffers[78] = 0;
        gObjBlockStatus[78] = 0;
        if (gAssetLoadInFlightFlags & 0x4000) {
            gAssetLoadCompletedFlags |= 0x4000;
            gObjBlockStatus[33] = 0;
        }
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x4000) {
            gAssetLoadCompletedFlags |= 0x4000;
            gObjBlockStatus[33] = 0;
        }
    }
}

void tex1ReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x1000) {
            gAssetLoadCompletedFlags |= 0x1000;
            gObjBlockStatus[0x80 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x2000) {
            gAssetLoadCompletedFlags |= 0x2000;
            gObjBlockStatus[0x12c / 4] = 0;
        }
    }
}

void tex0tab2readCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free(gResourceFileBuffers[78]);
        gResourceFileBuffers[78] = 0;
        gObjBlockStatus[78] = 0;
        if (gAssetLoadInFlightFlags & 0x800) {
            gAssetLoadCompletedFlags |= 0x800;
            gObjBlockStatus[78] = 0;
        }
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x800) {
            gAssetLoadCompletedFlags |= 0x800;
            gObjBlockStatus[78] = 0;
        }
    }
}
void tex0tab1readCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        mm_free(gResourceFileBuffers[36]);
        gResourceFileBuffers[36] = 0;
        gObjBlockStatus[36] = 0;
        if (gAssetLoadInFlightFlags & 0x400) {
            gAssetLoadCompletedFlags |= 0x400;
            gObjBlockStatus[36] = 0;
        }
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x400) {
            gAssetLoadCompletedFlags |= 0x400;
            gObjBlockStatus[36] = 0;
        }
    }
}

void tex0readCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x100) {
            gAssetLoadCompletedFlags |= 0x100;
            gObjBlockStatus[0x8c / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x200) {
            gAssetLoadCompletedFlags |= 0x200;
            gObjBlockStatus[0x134 / 4] = 0;
        }
    }
}

void animReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x10) {
            gAssetLoadCompletedFlags |= 0x10;
            gObjBlockStatus[0xc0 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x20) {
            gAssetLoadCompletedFlags |= 0x20;
            gObjBlockStatus[0x128 / 4] = 0;
        }
    }
}

void modelsReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x1) {
            gAssetLoadCompletedFlags |= 0x1;
            gObjBlockStatus[0xac / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x2) {
            gAssetLoadCompletedFlags |= 0x2;
            gObjBlockStatus[0x118 / 4] = 0;
        }
    }
}

void animTabReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x40) {
            gAssetLoadCompletedFlags |= 0x40;
            gObjBlockStatus[0xbc / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x80) {
            gAssetLoadCompletedFlags |= 0x80;
            gObjBlockStatus[0x124 / 4] = 0;
        }
    }
}

void modelsTabReadCb(s32 result, DVDFileInfo* fileInfo) {
    if (result < 0) {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
    } else {
        DVDClose(fileInfo);
        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
        if (gAssetLoadInFlightFlags & 0x4) {
            gAssetLoadCompletedFlags |= 0x4;
            gObjBlockStatus[0xa8 / 4] = 0;
        } else if (gAssetLoadInFlightFlags & 0x8) {
            gAssetLoadCompletedFlags |= 0x8;
            gObjBlockStatus[0x114 / 4] = 0;
        }
    }
}

static inline s32 mapCheckCurBlocksImpl(int v) {
    if (gObjMapBlockInfo[0x25] == v) {
        return 0;
    }
    if (gObjMapBlockInfo[0x47] == v) {
        return 1;
    }
    return -1;
}

void mapLoadDataFiles(int mapIdx) {
    if (sMapFileNameAdjacencyTable[mapIdx] != -1) {
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

int loadMapAndParent(int mapId) {
    int idx;
    int parent;
    if (mapId >= 0x4b) {
        idx = 5;
    } else {
        idx = sMapFileNameIndexRemapTable[mapId];
    }
    parent = sMapFileNameAdjacencyTable[idx];
    if (parent != -1 && mapCheckCurBlocksImpl(parent) == -1) {
        mapLoadDataFiles(parent);
        return parent;
    }
    mapLoadDataFiles(idx);
    return idx;
}

void clearLoadedFileFlags_blocks1(void) {
    int s = OSDisableInterrupts();
    if (gAssetLoadInFlightFlags & 0x100000) {
        gAssetLoadInFlightFlags ^= 0x100000;
    }
    OSRestoreInterrupts(s);
}

void setLoadedFileFlags_blocks1(void) {
    int s = OSDisableInterrupts();
    gAssetLoadInFlightFlags |= 0x100000;
    OSRestoreInterrupts(s);
}
int isRomListLoading(void) {
    return gRomListLoadInFlight;
}

int getLoadedFileFlags(int slot) {
    return loadedFileFlags();
}

u32 loadTableFiles(void) {
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    int s = OSDisableInterrupts();
    int flags = loadedFileFlags();
    int loadedFlags = gAssetLoadInFlightFlags;
    if ((gObjTableFileRequestFlags & 0x4) && !(flags & 0x4) && tbl->ids[0x2b] == -1) {
        mergeTableFiles((u32*)tbl->mergeModels, 0x2a, 0x45, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x8) && !(flags & 0x8) && tbl->ids[0x46] == -1) {
        mergeTableFiles((u32*)tbl->mergeModels, 0x2a, 0x45, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x40) && !(flags & 0x40) && tbl->ids[0x30] == -1) {
        mergeTableFiles((u32*)tbl->mergeAnim, 0x2f, 0x49, 0xbb8);
    }
    if ((gObjTableFileRequestFlags & 0x80) && !(flags & 0x80) && tbl->ids[0x4a] == -1) {
        mergeTableFiles((u32*)tbl->mergeAnim, 0x2f, 0x49, 0xbb8);
    }
    if ((gObjTableFileRequestFlags & 0x400) && !(flags & 0x400) && tbl->ids[0x23] == -1) {
        mergeTableFiles((u32*)tbl->mergeTex0, 0x24, 0x4e, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x800) && !(flags & 0x800) && tbl->ids[0x4d] == -1) {
        mergeTableFiles((u32*)tbl->mergeTex0, 0x24, 0x4e, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x4000) && !(flags & 0x4000) && tbl->ids[0x20] == -1) {
        mergeTableFiles((u32*)tbl->mergeTex1, 0x21, 0x4c, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x8000) && !(flags & 0x8000) && tbl->ids[0x4b] == -1) {
        mergeTableFiles((u32*)tbl->mergeTex1, 0x21, 0x4c, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x20000) && !(flags & 0x20000) && tbl->ids[0x25] == -1) {
        mergeTableFiles((u32*)tbl->mergeBlocks, 0x26, 0x48, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x80000) && !(flags & 0x80000) && tbl->ids[0x47] == -1) {
        mergeTableFiles((u32*)tbl->mergeBlocks, 0x26, 0x48, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x2000000) && !(flags & 0x2000000) && tbl->ids[0x1b] == -1) {
        mergeTableFiles((u32*)tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x8000000) && !(flags & 0x8000000) && tbl->ids[0x54] == -1) {
        mergeTableFiles((u32*)tbl->mergeVoxMap, 0x1a, 0x53, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x20000000) && !(flags & 0x20000000) && tbl->ids[0xd] == -1) {
        mergeTableFiles((u32*)tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
    }
    if ((gObjTableFileRequestFlags & 0x80000000) && !(flags & 0x80000000) && tbl->ids[0x55] == -1) {
        mergeTableFiles((u32*)tbl->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
    }
    gObjTableFileRequestFlags = flags;
    gAssetLoadInFlightFlags ^= gAssetLoadCompletedFlags;
    gAssetLoadCompletedFlags = 0;
    OSRestoreInterrupts(s);
    return gAssetLoadInFlightFlags;
}

int unlockLevel(s32 level, int bucket, int flag) {
    s32 cur;
    if (flag == 1) {
        gObjLevelLockSlots[0] = -2;
        gObjLevelLockSlots[1] = -2;
        return -1;
    }
    cur = gObjLevelLockSlots[bucket];
    if (level == cur || cur == -2) {
        gObjLevelLockSlots[bucket] = -2;
        return -1;
    }
    return cur;
}

int lockLevel(s32 level, int bucket) {
    s32 cur = gObjLevelLockSlots[bucket];
    if (cur == -2) {
        gObjLevelLockSlots[bucket] = level;
        return -1;
    }
    return cur;
}

#if defined(VERSION_GSAE01) || defined(VERSION_GSAJ01)
char sAssetIndexOverflowError[0x1D] = "ERROR: asset index overflow ";
#endif

int getTableFileEntry(int fileId, int index, int* out) {
    u8* base = gResourceFileTable;
    int count = 0;
    void* table = NULL;
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
    u8 needWait = 0;
    u32 waitMask = 0;
#endif
    switch (fileId) {
    case MLDF_FILEID_MODELS_TAB_A:
        count = ARRAY_COUNT(((struct MldfTables*)base)->mergeModels);
        table = (u8*)(base + 0x10000) + ((ptrdiff_t)offsetof(struct MldfTables, mergeModels) - 0x10000);
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
        waitMask = 0xc;
#endif
        break;
    case MLDF_FILEID_ANIM_TAB_A:
        count = ARRAY_COUNT(((struct MldfTables*)base)->mergeAnim);
        table = (u8*)(base + 0x10000) + ((ptrdiff_t)offsetof(struct MldfTables, mergeAnim) - 0x10000);
        break;
    case MLDF_FILEID_TEX0_TAB_A:
        count = ARRAY_COUNT(((struct MldfTables*)base)->mergeTex0);
        table = (u8*)(base + 0x10000) + ((ptrdiff_t)offsetof(struct MldfTables, mergeTex0) - 0x10000);
        break;
    case MLDF_FILEID_TEX1_TAB_A:
        count = ARRAY_COUNT(((struct MldfTables*)base)->mergeTex1);
        table = (u8*)(base + 0x10000) + ((ptrdiff_t)offsetof(struct MldfTables, mergeTex1) - 0x10000);
        break;
    case MLDF_FILEID_TEXPRE_TAB:
        table = ((struct MldfTables*)base)->ptrs[MLDF_FILEID_TEXPRE_TAB];
        break;
    case MLDF_FILEID_BLOCKS_TAB_A:
        count = ARRAY_COUNT(((struct MldfTables*)base)->mergeBlocks);
        table = (u8*)(base + 0x10000) + ((ptrdiff_t)offsetof(struct MldfTables, mergeBlocks) - 0x10000);
        break;
    case MLDF_FILEID_VOXMAP_TAB_A:
        count = ARRAY_COUNT(((struct MldfTables*)base)->mergeVoxMap);
        table = (u8*)(base + 0x10000) + ((ptrdiff_t)offsetof(struct MldfTables, mergeVoxMap) - 0x10000);
        break;
    case MLDF_FILEID_ANIMCURV_TAB_A:
        count = ARRAY_COUNT(((struct MldfTables*)base)->mergeAnimCurv);
        table = ((struct MldfTables*)base)->mergeAnimCurv;
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
        waitMask = 0xa0000000;
#endif
        break;
    }
    if (index < 0 || index >= count) {
#if defined(VERSION_GSAE01) || defined(VERSION_GSAJ01)
        debugPrintfxy(0x14, 0x28, sAssetIndexOverflowError);
#endif
        return 0;
    }
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
    while ((waitMask & loadedFileFlags()) != 0) {
        padUpdate();
        checkReset();
        if (needWait) {
            waitNextFrame();
        }
        loadDataFiles(0);
        dvdCheckError();
        if (needWait) {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (gDvdErrorPauseActive) {
            needWait = 1;
        }
    }
#endif
    if (table != NULL) {
        *out = ((int*)table)[index];
        return 1;
    }
    return 0;
}

#define MAPTBLP(idx) (*(int**)(((idx) << MLDF_BUFFER_SLOT_SHIFT) + (size_t)&((struct MldfTables*)base)->ptrs[0]))
#define MAPID_RT(s)  (*(int*)(((s) << 2) + (resourceAddress + offsetof(struct MldfTables, ids))))
#define MAPPTR_RT(s)                                                                                                   \
    (*(void**)(((s) << MLDF_BUFFER_SLOT_SHIFT) + (resourceAddress + offsetof(struct MldfTables, ptrs))))
#define MAPOWNER_RT(s) (*(s16*)(((s) << 1) + (resourceAddress + offsetof(struct MldfTables, owners))))

void* getCurrentDataFile(int id) {
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    switch (id) {
    case MLDF_FILEID_MODELS_TAB_A:
        return tbl->mergeModels;
    case MLDF_FILEID_ANIM_TAB_A:
        return tbl->mergeAnim;
    case MLDF_FILEID_TEX0_TAB_A:
        return tbl->mergeTex0;
    case MLDF_FILEID_TEX1_TAB_A:
        return tbl->mergeTex1;
    case MLDF_FILEID_TEXPRE_TAB:
        return tbl->ptrs[MLDF_FILEID_TEXPRE_TAB];
    case MLDF_FILEID_BLOCKS_TAB_A:
        return tbl->mergeBlocks;
    case MLDF_FILEID_VOXMAP_TAB_A:
        return tbl->mergeVoxMap;
    case MLDF_FILEID_ANIMCURV_TAB_A:
        return tbl->mergeAnimCurv;
    }
    return NULL;
}

int mapUnload(int mapId, int flags) {
    struct MldfTables* tbl;
    size_t resourceAddress;
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
    resourceAddress = (size_t)tbl;
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

        while (s = OSDisableInterrupts(), n = gAssetLoadInFlightFlags, OSRestoreInterrupts(s), n != 0) {
            if (n == 0x100000) {
                break;
            }
            padUpdate();
            checkReset();
            if (needWait) {
                waitNextFrame();
            }
            loadDataFiles(0);
            dvdCheckError();
            if (needWait) {
                mmFreeTick(0);
                gameTextRun();
                GXFlush_(1, 0);
            }
            if (gDvdErrorPauseActive) {
                needWait = 1;
            }
        }

        st = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
        {
            int v = st->mapDataFileId;
            if (v != gObjLevelLockSlots[0] && v != gObjLevelLockSlots[1]) {
                if ((flags & 0x10000000) && mapId != v) {
                    st->mapDataFileId = -1;
                }
                if ((flags & 0x20000000) && mapId == st->mapDataFileId) {
                    st->mapDataFileId = -1;
                }
                if (flags & 0x80000000) {
                    st->mapDataFileId = -1;
                }
            }
        }

        e = pairs;
        f20 = flags & 0x20000000;
        f10 = flags & 0x10000000;
        f80 = flags & 0x80000000;
        lockp = gObjLevelLockSlots;
        for (; i < 0x38; i += 2) {
            if ((f20 && mapId == MAPID_RT(e[0])) || (f10 && mapId != MAPID_RT(e[0])) ||
                ((flags & e[1]) && mapId == MAPID_RT(e[0]))) {
                MAPID_RT(e[0]) = -1;
            }
            {
                int idx = e[0];
                if (*(void**)((idx << MLDF_BUFFER_SLOT_SHIFT) +
                              (resourceAddress + offsetof(struct MldfTables, ptrs))) != NULL) {
                    s16 v;
                    if (f80 ||
                        ((flags & e[1]) &&
                         mapId == *(s16*)((idx << 1) + (resourceAddress + offsetof(struct MldfTables, owners)))) ||
                        (f10 && mapId != MAPOWNER_RT(idx)) || (f20 && mapId == MAPOWNER_RT(idx))) {
                        if (gObjLevelLockSlots[0] != (v = MAPOWNER_RT(idx)) && lockp[1] != v) {
                            switch (idx) {
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
                                for (j = 0; j < 75; j++) {
                                    if (sMapFileNameIndexRemapTable[j] ==
                                        *(s16*)(resourceAddress + sizeof(MldfArenaBlock) + (e[0] << 1) -
                                                (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, owners)))) {
                                        break;
                                    }
                                }
                                if (j <= 0x50 && j != 0x49 && j != 0x43 && j != 5) {
                                    void** romListSlot =
                                        (void**)((j << MLDF_BUFFER_SLOT_SHIFT) +
                                                 (resourceAddress + offsetof(struct MldfTables, romList)));
                                    mm_free(*romListSlot);
                                    *romListSlot = NULL;
                                }
                                break;
                            }
                            mm_free(MAPPTR_RT(e[0]));
                            mmSetFreeDelay(2);
                            *(void**)((e[0] << MLDF_BUFFER_SLOT_SHIFT) +
                                      (resourceAddress + offsetof(struct MldfTables, ptrs))) = NULL;
                            *(s16*)((e[0] << 1) + (resourceAddress + offsetof(struct MldfTables, owners))) = -1;
                            *(int*)((e[0] << 2) + (resourceAddress + offsetof(struct MldfTables, sizes))) = 0;
                            switch (e[0]) {
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

int mergeTableFiles(void* table, int bankAFileId, int bankBFileId, int unusedCount) {
    u32* merged = table;
    u8* base = gResourceFileTable;
    int written = 0;
    int endedA = 0;
    int endedB = 0;
    int remaining = 0;
    int* bankA;
    int* bankB;
    int* firstBank;

    firstBank = MAPTBLP(bankAFileId);
    if (firstBank == NULL || MAPTBLP(bankBFileId) == NULL) {
        if (firstBank == NULL) {
            endedA = 1;
        }
        if (MAPTBLP(bankBFileId) == NULL) {
            endedB = 1;
        }
    }
    /* This pointer-width round trip preserves MWCC's separate source cursor. */
    bankA = (int*)(size_t)firstBank;
    bankB = MAPTBLP(bankBFileId);
    if (merged == ((struct MldfTables*)base)->mergeModels) {
        remaining = ARRAY_COUNT(((struct MldfTables*)base)->mergeModels);
    } else if (merged == ((struct MldfTables*)base)->mergeAnim) {
        remaining = ARRAY_COUNT(((struct MldfTables*)base)->mergeAnim);
    } else if (merged == ((struct MldfTables*)base)->mergeTex0) {
        remaining = ARRAY_COUNT(((struct MldfTables*)base)->mergeTex0);
    } else if (merged == ((struct MldfTables*)base)->mergeTex1) {
        remaining = ARRAY_COUNT(((struct MldfTables*)base)->mergeTex1);
    } else if (merged == ((struct MldfTables*)base)->mergeBlocks) {
        remaining = ARRAY_COUNT(((struct MldfTables*)base)->mergeBlocks);
    } else if (merged == ((struct MldfTables*)base)->mergeVoxMap) {
        remaining = ARRAY_COUNT(((struct MldfTables*)base)->mergeVoxMap);
    } else if (merged == ((struct MldfTables*)base)->mergeAnimCurv) {
        remaining = ARRAY_COUNT(((struct MldfTables*)base)->mergeAnimCurv);
    }
    if (merged == ((struct MldfTables*)base)->mergeTex0 || merged == ((struct MldfTables*)base)->mergeTex1) {
        int* cursorA = bankA;
        int* destination = (int*)merged;
        int entryA;
        int entryB;
        for (; remaining > 0; remaining--) {
            if (!endedA && *cursorA == -1) {
                endedA = 1;
            }
            if (!endedB && *bankB == -1) {
                endedB = 1;
            }
            if (!endedA && (entryA = *cursorA, entryA != -1) && (entryA & 0x80000000)) {
                *destination = entryA & 0x7fffffff;
                *destination = *destination | 0x40000000;
            } else if (!endedB && (entryB = *bankB, entryB != -1) && (entryB & 0x80000000)) {
                *destination = entryB;
            } else if (!endedA && *cursorA != 0) {
                *destination = *cursorA;
            } else if (!endedB && *bankB != 0) {
                *destination = *bankB;
            } else {
                *destination = 0;
            }
            cursorA++;
            bankB++;
            destination++;
            written++;
        }
    } else if (merged == ((struct MldfTables*)base)->mergeBlocks) {
        int* cursorA = bankA;
        int* destination = (int*)merged;
        int* cursorB = bankB;
        int entryA;
        int entryB;
        for (; remaining > 0; remaining--) {
            if (!endedA && (entryA = *cursorA, entryA != -1) && (entryA & 0x10000000)) {
                *destination = entryA;
                if (bankB != NULL && *cursorB == -1) {
                    endedB = 1;
                }
            } else if (!endedB && (entryB = *cursorB, entryB != -1) && (entryB & 0x10000000)) {
                *destination = (entryB & 0xffffff) | 0x20000000;
                if (bankA != NULL && *cursorA == -1) {
                    endedA = 1;
                }
            } else if (!endedA && *cursorA == -1) {
                *destination = 0;
                endedA = 1;
            } else if (!endedB && *cursorB == -1) {
                *destination = 0;
                endedB = 1;
            } else if (!endedA && *cursorA != 0) {
                *destination = *cursorA;
            } else if (!endedB && *cursorB != 0) {
                *destination = *cursorB;
            } else {
                *destination = 0;
            }
            cursorA++;
            destination++;
            cursorB++;
            written++;
        }
    } else if (merged == ((struct MldfTables*)base)->mergeVoxMap) {
        int* cursorA = bankA;
        int* destination = (int*)merged;
        int entryA;
        int entryB;
        for (; remaining > 0; remaining--) {
            if (!endedA && *cursorA == -1) {
                *destination = 0;
                endedA = 1;
            } else if (!endedB && *bankB == -1) {
                *destination = 0;
                endedB = 1;
            } else if (!endedA && (entryA = *cursorA, entryA != -1) && (entryA & 0x80000000)) {
                *destination = entryA;
            } else if (!endedB && (entryB = *bankB, entryB != -1) && (entryB & 0x80000000)) {
                *destination = (entryB & 0x7fffffff) | 0x20000000;
            } else if (!endedA && *cursorA != 0) {
                *destination = *cursorA;
            } else if (!endedB && *bankB != 0) {
                *destination = *bankB;
            } else {
                *destination = 0;
            }
            cursorA++;
            destination++;
            bankB++;
            written++;
        }
    } else if (merged == ((struct MldfTables*)base)->mergeAnimCurv) {
        int* cursorA = bankA;
        int* destination = (int*)merged;
        int entryA;
        int entryB;
        for (; remaining > 0; remaining--) {
            if (!endedA && *cursorA == -1) {
                *destination = 0;
                endedA = 1;
            } else if (!endedB && *bankB == -1) {
                *destination = 0;
                endedB = 1;
            } else if (!endedA && (entryA = *cursorA, entryA != -1) && (entryA & 0x80000000)) {
                *destination = entryA;
            } else if (!endedB && (entryB = *bankB, entryB != -1) && (entryB & 0x80000000)) {
                *destination = (entryB & 0x7fffffff) | 0x20000000;
            } else if (!endedA && *cursorA != 0) {
                *destination = *cursorA;
            } else if (!endedB && *bankB != 0) {
                *destination = *bankB;
            } else {
                *destination = 0;
            }
            cursorA++;
            destination++;
            bankB++;
            written++;
        }
    } else {
        int* cursorA = bankA;
        int* cursorB = bankB;
        int* destination = (int*)merged;
        int entryA;
        int entryB;
        for (; remaining > 0; remaining--) {
            if (!endedA && *cursorA == -1) {
                endedA = 1;
            }
            if (!endedB && *cursorB == -1) {
                endedB = 1;
            }
            if (!endedA && (entryA = *cursorA, entryA != -1) && (entryA & 0x10000000)) {
                *destination = entryA;
            } else if (!endedB && (entryB = *cursorB, entryB != -1) && (entryB & 0x10000000)) {
                *destination = (entryB & 0xffffff) | 0x20000000;
            } else if (!endedA && bankA != NULL) {
                *destination = *cursorA;
            } else if (!endedB && bankB != NULL) {
                *destination = *cursorB;
            } else {
                *destination = 0;
            }
            cursorA++;
            cursorB++;
            destination++;
            written++;
        }
    }
    {
        int last = written - 1;
        merged[last] = 0xffffffff;
    }
    return 1;
}
#undef MAPTBLP

s32 mapCheckCurBlocks(int v) {
    return mapCheckCurBlocksImpl(v);
}

char sMapAssetPathFormats[0x78] =
    "%s/animcurv.bin\0%s/animcurv.tab\0%s/voxmap.bin\0\0\0warlock/voxmap.bin\0\0%s/voxmap.tab\0\0"
    "\0%s/mod%d.zlb.bin\0\0\0\0%s/mod%d.tab";

void* mapLoadDataFile(int mapId, int fileId) {
    struct MldfNames* names = (struct MldfNames*)sResourceFileNameAudioTab;
    struct MldfTables* resources = (struct MldfTables*)gResourceFileTable;
    DVDFileInfo* tableFileInfo;
    DVDFileInfo* fileInfo;
    int readSynchronously = 0;
    void* result;
    int adjacentMapId;
    int slot;
    int opened;
    void* loadedBuffer;
    int adjacentBank[1];
    char path[56];

    if (gForceNextLoadSync != 0) {
        gForceNextLoadSync = 0;
        readSynchronously = 1;
    }
    adjacentMapId = names->adjacency[mapId];
    if (adjacentMapId != -1) {
        int residentBlockBanks = 0;
        s16 blockOwnerA = resources->owners[MLDF_FILEID_BLOCKS_BIN_A];
        s16 blockOwnerB;
        if (blockOwnerA != -1) {
            residentBlockBanks = 1;
        }
        blockOwnerB = resources->owners[MLDF_FILEID_BLOCKS_BIN_B];
        if (blockOwnerB != -1) {
            residentBlockBanks += 1;
        }
        if (residentBlockBanks == 0) {
            gForceNextLoadSync = 1;
            if (blockOwnerA == adjacentMapId) {
                adjacentBank[0] = 0;
            } else if (blockOwnerB == adjacentMapId) {
                adjacentBank[0] = 1;
            } else {
                adjacentBank[0] = -1;
            }
            if (adjacentBank[0] == -1) {
                mapLoadDataFile(adjacentMapId, fileId);
            }
            readSynchronously = 1;
        }
    }
    readSynchronously |= gForceLoadImmediately;
    switch (fileId) {
    case MLDF_FILEID_ANIMCURV_BIN_A:
    case MLDF_FILEID_ANIMCURV_BIN_B:
        result = resources->ptrs[MLDF_FILEID_ANIMCURV_BIN_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIMCURV_BIN_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_ANIMCURV_BIN_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIMCURV_BIN_B] == mapId)) {
            return result;
        }
        {
            if (resources->ids[MLDF_FILEID_ANIMCURV_BIN_A] == mapId) {
                slot = MLDF_FILEID_ANIMCURV_BIN_A;
                resources->ids[MLDF_FILEID_ANIMCURV_BIN_A] = -1;
            } else if (resources->ids[MLDF_FILEID_ANIMCURV_BIN_B] == mapId) {
                slot = MLDF_FILEID_ANIMCURV_BIN_B;
                resources->ids[MLDF_FILEID_ANIMCURV_BIN_B] = -1;
            } else if (resources->owners[MLDF_FILEID_ANIMCURV_BIN_A] == -1) {
                slot = MLDF_FILEID_ANIMCURV_BIN_A;
            } else if (resources->owners[MLDF_FILEID_ANIMCURV_BIN_B] == -1) {
                slot = MLDF_FILEID_ANIMCURV_BIN_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, names->fmtAnimCurvBin, names->mapNames[mapId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                if (resources->sizes[slot] == 0) {
                    return 0;
                } else {
                    MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                    DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                    loadedBuffer = MLDF_PTR_RT(resources, slot);
                    if (loadedBuffer == 0) {
                        if (MLDF_ID_RT(resources, fileId) == -1) {
                            texRestructRefs(1);
                        }
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        resources->sizes[slot] = 0;
                        resources->ids[slot] = mapId;
                        return 0;
                    } else {
                        if (readSynchronously != 0) {
                            DVDRead(fileInfo, loadedBuffer, resources->sizes[slot], 0);
                            DVDClose(fileInfo);
                            AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                            if (((gAssetLoadInFlightFlags & 0x20000000) == 0) &&
                                ((gAssetLoadInFlightFlags & 0x80000000) == 0)) {
                                mergeTableFiles(resources->mergeAnimCurv, MLDF_FILEID_ANIMCURV_TAB_A, MLDF_FILEID_ANIMCURV_TAB_B, 0x1fd0);
                            }
                        } else {
                            if (slot == MLDF_FILEID_ANIMCURV_BIN_A) {
                                gAssetLoadInFlightFlags |= 0x10000000;
                            } else {
                                gAssetLoadInFlightFlags |= 0x40000000;
                            }
                            DVDReadAsyncPrio(fileInfo, loadedBuffer, resources->sizes[slot], 0, animCurvReadCb, 2);
                            resources->fileInfo[slot] = fileInfo;
                        }
                        MLDF_OWNER_RT(resources, slot) = mapId;
                        return MLDF_PTR_RT(resources, slot);
                    }
                }
            }
        }
        break;
    case MLDF_FILEID_ANIMCURV_TAB_A:
    case MLDF_FILEID_ANIMCURV_TAB_B:
        result = resources->ptrs[MLDF_FILEID_ANIMCURV_TAB_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIMCURV_TAB_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_ANIMCURV_TAB_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIMCURV_TAB_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->owners[MLDF_FILEID_ANIMCURV_TAB_A] == -1) {
                slot = MLDF_FILEID_ANIMCURV_TAB_A;
            } else if (resources->owners[MLDF_FILEID_ANIMCURV_TAB_B] == -1) {
                slot = MLDF_FILEID_ANIMCURV_TAB_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, names->fmtAnimCurvTab, names->mapNames[mapId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                if (resources->sizes[slot] == 0) {
                    return 0;
                } else {
                    MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                    DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                    if (readSynchronously != 0) {
                        DVDRead(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        if (((gAssetLoadInFlightFlags & 0x20000000) == 0) &&
                            ((gAssetLoadInFlightFlags & 0x80000000) == 0)) {
                            mergeTableFiles(resources->mergeAnimCurv, MLDF_FILEID_ANIMCURV_TAB_A, MLDF_FILEID_ANIMCURV_TAB_B, 0x1fd0);
                        }
                    } else {
                        if (slot == MLDF_FILEID_ANIMCURV_TAB_A) {
                            gAssetLoadInFlightFlags |= 0x20000000;
                        } else {
                            gAssetLoadInFlightFlags |= 0x80000000;
                        }
                        DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, animCurvTabReadCb, 2);
                        resources->fileInfo[slot] = fileInfo;
                    }
                    MLDF_OWNER_RT(resources, slot) = mapId;
                    return MLDF_PTR_RT(resources, slot);
                }
            }
        }
        break;
    case MLDF_FILEID_VOXMAP_BIN_A:
    case MLDF_FILEID_VOXMAP_BIN_B:
        result = resources->ptrs[MLDF_FILEID_VOXMAP_BIN_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_VOXMAP_BIN_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_VOXMAP_BIN_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_VOXMAP_BIN_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->owners[MLDF_FILEID_VOXMAP_BIN_A] == -1) {
                slot = MLDF_FILEID_VOXMAP_BIN_A;
            } else if (resources->owners[MLDF_FILEID_VOXMAP_BIN_B] == -1) {
                slot = MLDF_FILEID_VOXMAP_BIN_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, names->fmtVoxmapBin, names->mapNames[mapId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                sprintf(path, names->fmtWarlockVoxmap);
                opened = DVDOpen(path, fileInfo);
                if (opened == 0) {
                    return 0;
                    break;
                }
            }
            resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
            if (resources->sizes[slot] == 0) {
                sprintf(path, names->fmtWarlockVoxmap);
                opened = DVDOpen(path, fileInfo);
                if (opened == 0) {
                    return 0;
                    break;
                }
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
            }
            MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
            DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
            if (readSynchronously != 0) {
                DVDRead(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                DVDClose(fileInfo);
                AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                if (((gAssetLoadInFlightFlags & 0x2000000) == 0) && ((gAssetLoadInFlightFlags & 0x8000000) == 0)) {
                    mergeTableFiles(resources->mergeVoxMap, MLDF_FILEID_VOXMAP_TAB_A, MLDF_FILEID_VOXMAP_TAB_B, 0x800);
                }
            } else {
                if (slot == MLDF_FILEID_VOXMAP_BIN_A) {
                    gAssetLoadInFlightFlags |= 0x1000000;
                } else {
                    gAssetLoadInFlightFlags |= 0x4000000;
                }
                resources->fileInfo[slot] = fileInfo;
                DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, voxMapReadCb, 2);
            }
            MLDF_OWNER_RT(resources, slot) = mapId;
            return MLDF_PTR_RT(resources, slot);
        }
        break;
    case MLDF_FILEID_VOXMAP_TAB_A:
    case MLDF_FILEID_VOXMAP_TAB_B:
        result = resources->ptrs[MLDF_FILEID_VOXMAP_TAB_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_VOXMAP_TAB_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_VOXMAP_TAB_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_VOXMAP_TAB_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->owners[MLDF_FILEID_VOXMAP_TAB_A] == -1) {
                slot = MLDF_FILEID_VOXMAP_TAB_A;
            } else if (resources->owners[MLDF_FILEID_VOXMAP_TAB_B] == -1) {
                slot = MLDF_FILEID_VOXMAP_TAB_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, names->fmtVoxmapTab, names->mapNames[mapId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                if (resources->sizes[slot] == 0) {
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    return 0;
                } else {
                    MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                    DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                    if (readSynchronously != 0) {
                        DVDRead(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        if (((gAssetLoadInFlightFlags & 0x2000000) == 0) &&
                            ((gAssetLoadInFlightFlags & 0x8000000) == 0)) {
                            mergeTableFiles(resources->mergeVoxMap, MLDF_FILEID_VOXMAP_TAB_A, MLDF_FILEID_VOXMAP_TAB_B, 0x800);
                        }
                    } else {
                        if (slot == MLDF_FILEID_VOXMAP_TAB_A) {
                            gAssetLoadInFlightFlags |= 0x2000000;
                        } else {
                            gAssetLoadInFlightFlags |= 0x8000000;
                        }
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, voxMapTabReadCb, 2);
                    }
                    MLDF_OWNER_RT(resources, slot) = mapId;
                    return MLDF_PTR_RT(resources, slot);
                }
            }
        }
        break;
    case MLDF_FILEID_BLOCKS_BIN_A:
    case MLDF_FILEID_BLOCKS_BIN_B:
        result = resources->ptrs[MLDF_FILEID_BLOCKS_BIN_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_BLOCKS_BIN_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_BLOCKS_BIN_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_BLOCKS_BIN_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->ids[MLDF_FILEID_BLOCKS_BIN_A] == mapId) {
                slot = MLDF_FILEID_BLOCKS_BIN_A;
                resources->ids[MLDF_FILEID_BLOCKS_BIN_A] = -1;
            } else if (resources->ids[MLDF_FILEID_BLOCKS_BIN_B] == mapId) {
                slot = MLDF_FILEID_BLOCKS_BIN_B;
                resources->ids[MLDF_FILEID_BLOCKS_BIN_B] = -1;
            } else if (resources->owners[MLDF_FILEID_BLOCKS_BIN_A] == -1) {
                slot = MLDF_FILEID_BLOCKS_BIN_A;
            } else if (resources->owners[MLDF_FILEID_BLOCKS_BIN_B] == -1) {
                slot = MLDF_FILEID_BLOCKS_BIN_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            if (mapId > 4) {
                sprintf(path, names->fmtModBin, names->mapNames[mapId], mapId + 1);
            } else {
                sprintf(path, names->fmtModBin, names->mapNames[mapId], mapId);
            }
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                loadedBuffer = MLDF_PTR_RT(resources, slot);
                if (loadedBuffer == 0) {
                    if (MLDF_ID_RT(resources, fileId) == -1) {
                        texRestructRefs(1);
                    }
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    resources->sizes[slot] = 0;
                    resources->ids[slot] = mapId;
                    return 0;
                } else {
                    if (readSynchronously != 0) {
                        DVDRead(fileInfo, loadedBuffer, resources->sizes[slot], 0);
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        if (((gAssetLoadInFlightFlags & 0x20000) == 0) && ((gAssetLoadInFlightFlags & 0x80000) == 0)) {
                            mergeTableFiles(resources->mergeBlocks, MLDF_FILEID_BLOCKS_TAB_A, MLDF_FILEID_BLOCKS_TAB_B, 0x800);
                        }
                    } else {
                        if (slot == MLDF_FILEID_BLOCKS_BIN_A) {
                            gAssetLoadInFlightFlags |= 0x10000;
                        } else {
                            gAssetLoadInFlightFlags |= 0x40000;
                        }
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, loadedBuffer, resources->sizes[slot], 0, blocksReadCb, 2);
                    }
                    MLDF_OWNER_RT(resources, slot) = mapId;
                    return MLDF_PTR_RT(resources, slot);
                }
            }
        }
        break;
    case MLDF_FILEID_BLOCKS_TAB_A:
    case MLDF_FILEID_BLOCKS_TAB_B: {
        int idx;
        int* grp;
        result = resources->ptrs[MLDF_FILEID_BLOCKS_TAB_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_BLOCKS_TAB_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_BLOCKS_TAB_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_BLOCKS_TAB_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->owners[MLDF_FILEID_BLOCKS_TAB_A] == -1) {
                slot = MLDF_FILEID_BLOCKS_TAB_A;
            } else if (resources->owners[MLDF_FILEID_BLOCKS_TAB_B] == -1) {
                slot = MLDF_FILEID_BLOCKS_TAB_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            grp = names->remapGroups;
            for (idx = 0; idx < 0x4b; idx++) {
                if (mapId == grp[idx]) {
                    break;
                }
            }
            piRomLoadSection(0, idx, 0);
            if (mapId > 4) {
                sprintf(path, names->fmtModTab, names->mapNames[mapId], mapId + 1);
            } else {
                sprintf(path, names->fmtModTab, names->mapNames[mapId], mapId);
            }
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                if (readSynchronously != 0) {
                    DVDRead(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    if (((gAssetLoadInFlightFlags & 0x20000) == 0) && ((gAssetLoadInFlightFlags & 0x80000) == 0)) {
                        mergeTableFiles(resources->mergeBlocks, MLDF_FILEID_BLOCKS_TAB_A, MLDF_FILEID_BLOCKS_TAB_B, 0x800);
                    }
                } else {
                    if (slot == MLDF_FILEID_BLOCKS_TAB_A) {
                        gAssetLoadInFlightFlags |= 0x20000;
                    } else {
                        gAssetLoadInFlightFlags |= 0x80000;
                    }
                    resources->fileInfo[slot] = fileInfo;
                    DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, blocksTabReadCb, 2);
                }
                MLDF_OWNER_RT(resources, slot) = mapId;
                return MLDF_PTR_RT(resources, slot);
            }
        }
        break;
    }
    case MLDF_FILEID_MODELS_BIN_A:
    case MLDF_FILEID_MODELS_BIN_B:
        result = resources->ptrs[MLDF_FILEID_MODELS_BIN_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_MODELS_BIN_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_MODELS_BIN_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_MODELS_BIN_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->ids[MLDF_FILEID_MODELS_BIN_A] == mapId) {
                slot = MLDF_FILEID_MODELS_BIN_A;
                resources->ids[MLDF_FILEID_MODELS_BIN_A] = -1;
            } else if (resources->ids[MLDF_FILEID_MODELS_BIN_B] == mapId) {
                slot = MLDF_FILEID_MODELS_BIN_B;
                resources->ids[MLDF_FILEID_MODELS_BIN_B] = -1;
            } else if (resources->owners[MLDF_FILEID_MODELS_BIN_A] == -1) {
                slot = MLDF_FILEID_MODELS_BIN_A;
            } else if (resources->owners[MLDF_FILEID_MODELS_BIN_B] == -1) {
                slot = MLDF_FILEID_MODELS_BIN_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                loadedBuffer = MLDF_PTR_RT(resources, slot);
                if (loadedBuffer == 0) {
                    if (MLDF_ID_RT(resources, fileId) == -1) {
                        texRestructRefs(1);
                    }
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    resources->sizes[slot] = 0;
                    resources->ids[slot] = mapId;
                    return 0;
                } else {
                    if (readSynchronously != 0) {
                        DVDRead(fileInfo, loadedBuffer, resources->sizes[slot], 0);
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        if (((gAssetLoadInFlightFlags & 4) == 0) && ((gAssetLoadInFlightFlags & 8) == 0)) {
                            mergeTableFiles(resources->mergeModels, MLDF_FILEID_MODELS_TAB_A, MLDF_FILEID_MODELS_TAB_B, 0x800);
                        }
                        gModelsArchiveLoadCount += 1;
                    } else {
                        gModelsArchiveLoadCount += 1;
                        if (slot == MLDF_FILEID_MODELS_BIN_A) {
                            gAssetLoadInFlightFlags |= 1;
                        } else {
                            gAssetLoadInFlightFlags |= 2;
                        }
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, loadedBuffer, resources->sizes[slot], 0, modelsReadCb, 2);
                    }
                    MLDF_OWNER_RT(resources, slot) = mapId;
                    return MLDF_PTR_RT(resources, slot);
                }
            }
        }
        break;
    case MLDF_FILEID_MODELS_TAB_A:
    case MLDF_FILEID_MODELS_TAB_B:
        result = resources->ptrs[MLDF_FILEID_MODELS_TAB_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_MODELS_TAB_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_MODELS_TAB_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_MODELS_TAB_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->owners[MLDF_FILEID_MODELS_TAB_A] == -1) {
                slot = MLDF_FILEID_MODELS_TAB_A;
            } else if (resources->owners[MLDF_FILEID_MODELS_TAB_B] == -1) {
                slot = MLDF_FILEID_MODELS_TAB_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                if (readSynchronously != 0) {
                    DVDRead(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    if (((gAssetLoadInFlightFlags & 4) == 0) && ((gAssetLoadInFlightFlags & 8) == 0)) {
                        mergeTableFiles(resources->mergeModels, MLDF_FILEID_MODELS_TAB_A, MLDF_FILEID_MODELS_TAB_B, 0x800);
                    }
                } else {
                    if (slot == MLDF_FILEID_MODELS_TAB_A) {
                        gAssetLoadInFlightFlags |= 4;
                    } else {
                        gAssetLoadInFlightFlags |= 8;
                    }
                    resources->fileInfo[slot] = fileInfo;
                    DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, modelsTabReadCb, 2);
                }
                MLDF_OWNER_RT(resources, slot) = mapId;
                return MLDF_PTR_RT(resources, slot);
            }
        }
        break;
    case MLDF_FILEID_ANIM_BIN_A:
    case MLDF_FILEID_ANIM_BIN_B:
        result = resources->ptrs[MLDF_FILEID_ANIM_BIN_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIM_BIN_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_ANIM_BIN_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIM_BIN_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->ids[MLDF_FILEID_ANIM_BIN_A] == mapId) {
                slot = MLDF_FILEID_ANIM_BIN_A;
                resources->ids[MLDF_FILEID_ANIM_BIN_A] = -1;
            } else if (resources->ids[MLDF_FILEID_ANIM_BIN_B] == mapId) {
                slot = MLDF_FILEID_ANIM_BIN_B;
                resources->ids[MLDF_FILEID_ANIM_BIN_B] = -1;
            } else if (resources->owners[MLDF_FILEID_ANIM_BIN_A] == -1) {
                slot = MLDF_FILEID_ANIM_BIN_A;
            } else if (resources->owners[MLDF_FILEID_ANIM_BIN_B] == -1) {
                slot = MLDF_FILEID_ANIM_BIN_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                loadedBuffer = MLDF_PTR_RT(resources, slot);
                if (loadedBuffer == 0) {
                    if (MLDF_ID_RT(resources, fileId) == -1) {
                        texRestructRefs(1);
                    }
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    resources->sizes[slot] = 0;
                    resources->ids[slot] = mapId;
                    return 0;
                } else {
                    if (readSynchronously != 0) {
                        DVDRead(fileInfo, loadedBuffer, resources->sizes[slot], 0);
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        if (((gAssetLoadInFlightFlags & 0x40) == 0) && ((gAssetLoadInFlightFlags & 0x80) == 0)) {
                            mergeTableFiles(resources->mergeAnim, MLDF_FILEID_ANIM_TAB_A, MLDF_FILEID_ANIM_TAB_B, 3000);
                        }
                    } else {
                        if (slot == MLDF_FILEID_ANIM_BIN_A) {
                            gAssetLoadInFlightFlags |= 0x10;
                        } else {
                            gAssetLoadInFlightFlags |= 0x20;
                        }
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, loadedBuffer, resources->sizes[slot], 0, animReadCb, 2);
                    }
                    MLDF_OWNER_RT(resources, slot) = mapId;
                    return MLDF_PTR_RT(resources, slot);
                }
            }
        }
        break;
    case MLDF_FILEID_ANIM_TAB_A:
    case MLDF_FILEID_ANIM_TAB_B:
        result = resources->ptrs[MLDF_FILEID_ANIM_TAB_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIM_TAB_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_ANIM_TAB_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_ANIM_TAB_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->owners[MLDF_FILEID_ANIM_TAB_A] == -1) {
                slot = MLDF_FILEID_ANIM_TAB_A;
            } else if (resources->owners[MLDF_FILEID_ANIM_TAB_B] == -1) {
                slot = MLDF_FILEID_ANIM_TAB_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                if (readSynchronously != 0) {
                    DVDRead(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    if (((gAssetLoadInFlightFlags & 0x40) == 0) && ((gAssetLoadInFlightFlags & 0x80) == 0)) {
                        mergeTableFiles(resources->mergeAnim, MLDF_FILEID_ANIM_TAB_A, MLDF_FILEID_ANIM_TAB_B, 3000);
                    }
                } else {
                    if (slot == MLDF_FILEID_ANIM_TAB_A) {
                        gAssetLoadInFlightFlags |= 0x40;
                    } else {
                        gAssetLoadInFlightFlags |= 0x80;
                    }
                    resources->fileInfo[slot] = fileInfo;
                    DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, animTabReadCb, 2);
                }
                MLDF_OWNER_RT(resources, slot) = mapId;
                return MLDF_PTR_RT(resources, slot);
            }
        }
        break;
    case MLDF_FILEID_TEX0_BIN_A:
    case MLDF_FILEID_TEX0_BIN_B:
        result = resources->ptrs[MLDF_FILEID_TEX0_BIN_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX0_BIN_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_TEX0_BIN_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX0_BIN_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->ids[MLDF_FILEID_TEX0_BIN_A] == mapId) {
                slot = MLDF_FILEID_TEX0_BIN_A;
                resources->ids[MLDF_FILEID_TEX0_BIN_A] = -1;
            } else if (resources->ids[MLDF_FILEID_TEX0_BIN_B] == mapId) {
                slot = MLDF_FILEID_TEX0_BIN_B;
                resources->ids[MLDF_FILEID_TEX0_BIN_B] = -1;
            } else if (resources->owners[MLDF_FILEID_TEX0_BIN_A] == -1) {
                slot = MLDF_FILEID_TEX0_BIN_A;
            } else if (resources->owners[MLDF_FILEID_TEX0_BIN_B] == -1) {
                slot = MLDF_FILEID_TEX0_BIN_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot] + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                loadedBuffer = MLDF_PTR_RT(resources, slot);
                if (loadedBuffer == 0) {
                    if (MLDF_ID_RT(resources, fileId) == -1) {
                        texRestructRefs(1);
                    }
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    resources->sizes[slot] = 0;
                    resources->ids[slot] = mapId;
                    return 0;
                } else {
                    if (readSynchronously != 0) {
                        DVDRead(fileInfo, loadedBuffer, resources->sizes[slot], 0);
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        if (((gAssetLoadInFlightFlags & 0x400) == 0) && ((gAssetLoadInFlightFlags & 0x800) == 0)) {
                            mergeTableFiles(resources->mergeTex0, MLDF_FILEID_TEX0_TAB_A, MLDF_FILEID_TEX0_TAB_B, 0x1000);
                        }
                    } else {
                        if (slot == MLDF_FILEID_TEX0_BIN_A) {
                            gAssetLoadInFlightFlags |= 0x100;
                        } else {
                            gAssetLoadInFlightFlags |= 0x200;
                        }
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, loadedBuffer, resources->sizes[slot], 0, tex0readCb, 2);
                    }
                    MLDF_OWNER_RT(resources, slot) = mapId;
                    return MLDF_PTR_RT(resources, slot);
                }
            }
        }
        break;
    case MLDF_FILEID_TEX0_TAB_A:
    case MLDF_FILEID_TEX0_TAB_B:
        result = resources->ptrs[MLDF_FILEID_TEX0_TAB_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX0_TAB_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_TEX0_TAB_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX0_TAB_B] == mapId)) {
            return result;
        }
        {
            int slot;
            DVDFileInfo* fileInfo;
            int opened;

            if (resources->owners[MLDF_FILEID_TEX0_TAB_A] == -1) {
                slot = MLDF_FILEID_TEX0_TAB_A;
            } else if (resources->owners[MLDF_FILEID_TEX0_TAB_B] == -1) {
                slot = MLDF_FILEID_TEX0_TAB_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot] + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                if (readSynchronously != 0) {
                    DVDRead(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    if (((gAssetLoadInFlightFlags & 0x400) == 0) && ((gAssetLoadInFlightFlags & 0x800) == 0)) {
                        mergeTableFiles(resources->mergeTex0, MLDF_FILEID_TEX0_TAB_A, MLDF_FILEID_TEX0_TAB_B, 0x1000);
                    }
                } else {
                    if (slot == MLDF_FILEID_TEX0_TAB_A) {
                        gAssetLoadInFlightFlags |= 0x400;
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, tex0tab1readCb, 2);
                    } else {
                        gAssetLoadInFlightFlags |= 0x800;
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, tex0tab2readCb, 2);
                    }
                }
                MLDF_OWNER_RT(resources, slot) = mapId;
                return MLDF_PTR_RT(resources, slot);
            }
        }
        break;
    case MLDF_FILEID_TEX1_BIN_A:
    case MLDF_FILEID_TEX1_BIN_B:
        result = resources->ptrs[MLDF_FILEID_TEX1_BIN_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX1_BIN_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_TEX1_BIN_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX1_BIN_B] == mapId)) {
            return result;
        }
        {
            DVDFileInfo* fileInfo;

            if (resources->ids[MLDF_FILEID_TEX1_BIN_A] == mapId) {
                slot = MLDF_FILEID_TEX1_BIN_A;
                resources->ids[MLDF_FILEID_TEX1_BIN_A] = -1;
            } else if (resources->ids[MLDF_FILEID_TEX1_BIN_B] == mapId) {
                slot = MLDF_FILEID_TEX1_BIN_B;
                resources->ids[MLDF_FILEID_TEX1_BIN_B] = -1;
            } else if (resources->owners[MLDF_FILEID_TEX1_BIN_A] == -1) {
                slot = MLDF_FILEID_TEX1_BIN_A;
            } else if (resources->owners[MLDF_FILEID_TEX1_BIN_B] == -1) {
                slot = MLDF_FILEID_TEX1_BIN_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, fileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(fileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot] + 0x20, 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                loadedBuffer = MLDF_PTR_RT(resources, slot);
                if (loadedBuffer == 0) {
                    if (MLDF_ID_RT(resources, fileId) == -1) {
                        texRestructRefs(1);
                    }
                    DVDClose(fileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                    resources->sizes[slot] = 0;
                    resources->ids[slot] = mapId;
                    return 0;
                } else {
                    if (readSynchronously != 0) {
                        DVDRead(fileInfo, loadedBuffer, resources->sizes[slot], 0);
                        DVDClose(fileInfo);
                        AtomicSList_Push(gDvdFileInfoPool, fileInfo);
                        if (((gAssetLoadInFlightFlags & 0x4000) == 0) && ((gAssetLoadInFlightFlags & 0x8000) == 0)) {
                            mergeTableFiles(resources->mergeTex1, MLDF_FILEID_TEX1_TAB_A, MLDF_FILEID_TEX1_TAB_B, 0x1000);
                        }
                    } else {
                        if (slot == MLDF_FILEID_TEX1_BIN_A) {
                            gAssetLoadInFlightFlags |= 0x1000;
                        } else {
                            gAssetLoadInFlightFlags |= 0x2000;
                        }
                        resources->fileInfo[slot] = fileInfo;
                        DVDReadAsyncPrio(fileInfo, loadedBuffer, resources->sizes[slot], 0, tex1ReadCb, 2);
                    }
                    MLDF_OWNER_RT(resources, slot) = mapId;
                    return MLDF_PTR_RT(resources, slot);
                }
            }
        }
        break;
    case MLDF_FILEID_TEX1_TAB_A:
    case MLDF_FILEID_TEX1_TAB_B:
        result = resources->ptrs[MLDF_FILEID_TEX1_TAB_A];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX1_TAB_A] == mapId)) {
            return result;
        }
        result = resources->ptrs[MLDF_FILEID_TEX1_TAB_B];
        if ((result != 0) && (resources->owners[MLDF_FILEID_TEX1_TAB_B] == mapId)) {
            return result;
        }
        {
            if (resources->owners[MLDF_FILEID_TEX1_TAB_A] == -1) {
                slot = MLDF_FILEID_TEX1_TAB_A;
            } else if (resources->owners[MLDF_FILEID_TEX1_TAB_B] == -1) {
                slot = MLDF_FILEID_TEX1_TAB_B;
            } else {
                return 0;
            }
            if (MLDF_PTR_RT(resources, slot) != 0) {
                mm_free(MLDF_PTR_RT(resources, slot));
                MLDF_PTR_RT(resources, slot) = 0;
            }
            sprintf(path, sArchivePathFormat, names->mapNames[mapId], names->fileNames[fileId]);
            tableFileInfo = AtomicSList_Pop(gDvdFileInfoPool);
            opened = DVDOpen(path, tableFileInfo);
            if (opened == 0) {
                return 0;
            } else {
                resources->sizes[slot] = DVD_FI_LENGTH(tableFileInfo);
                MLDF_PTR_RT(resources, slot) = mmAlloc(resources->sizes[slot], 0x7d7d7d7d, 0);
                DCInvalidateRange(MLDF_PTR_RT(resources, slot), resources->sizes[slot]);
                if (readSynchronously != 0) {
                    DVDRead(tableFileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0);
                    DVDClose(tableFileInfo);
                    AtomicSList_Push(gDvdFileInfoPool, tableFileInfo);
                    if (((gAssetLoadInFlightFlags & 0x4000) == 0) && ((gAssetLoadInFlightFlags & 0x8000) == 0)) {
                        mergeTableFiles(resources->mergeTex1, MLDF_FILEID_TEX1_TAB_A, MLDF_FILEID_TEX1_TAB_B, 0x1000);
                    }
                } else {
                    resources->fileInfo[slot] = tableFileInfo;
                    if (slot == MLDF_FILEID_TEX1_TAB_A) {
                        gAssetLoadInFlightFlags |= 0x4000;
                        DVDReadAsyncPrio(tableFileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, tex1tab1readCb, 2);
                    } else {
                        gAssetLoadInFlightFlags |= 0x8000;
                        DVDReadAsyncPrio(tableFileInfo, MLDF_PTR_RT(resources, slot), resources->sizes[slot], 0, tex1tab2readCb, 2);
                    }
                }
                MLDF_OWNER_RT(resources, slot) = mapId;
                return MLDF_PTR_RT(resources, slot);
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

void* loadAndDecompressDataFile(int fileId, void* destBuf, int offsetFlags, u32 length, int* sizeOut, int entryIndex,
                                u32 flagBits) {
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    size_t tab0 = 0; /* Primary TAB address, reused as a TEXPRE search index. */
    u8* tab1 = NULL; /* TAB ptr of the alternate slot of the pair */
    u8 frame = 0;    /* run a full frame per wait iteration once dvd error UI is up */
    /* Slot-select scratch; case 0x2b reuses it for a flags snapshot and case 0x51 for a TAB address. */
    size_t slotScratch;
    int entryOff;
    int flags;
    int intr;
    int i;
    int prev;
    size_t slotPtrAddr; /* Slot address biased to the arena end for MLDF_QPTR; reused
                        as the payload address during size probes. */
    u8* fileBuf;
    u32 alignedSize;
    int tmp;
    u32 decompSize;
    int entryByteOff;
    u8* qptr; /* MLDF_QPTR from the guard, reused for the first use of each branch */
    DVDFileInfo buf;

    switch (fileId) {
    case 0xd:
        /* This file family does not use the caller's entry index. Reuse its
           local for one protected snapshot: both the BIN and TAB reads for a
           slot must finish before its merged table pointer is usable. */
        intr = OSDisableInterrupts();
        entryIndex = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0) {
            tab0 = (size_t)MLDF_PTR(0xe);
        }
        if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0) {
            tab1 = MLDF_PTR(0x56);
        }
        slotScratch = offsetFlags & 0x80000000;
        if (slotScratch != 0 && tab0 == 0) {
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   entryIndex != 0) {
                if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0) {
                    tab0 = (size_t)*(void**)((size_t)tbl->ptrs + 0x80000000u);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        } else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0) {
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   entryIndex != 0) {
                if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0) {
                    tab1 = MLDF_PTR(0);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        }
        if ((offsetFlags & 0x20000000) != 0 && tab1 != 0) {
            fileId = 0x55;
        } else if (slotScratch != 0 && tab0 != 0) {
            fileId = 0xd;
        } else if (tab0 != 0) {
            fileId = 0xd;
        } else if (tab1 != 0) {
            fileId = 0x55;
        }
        offsetFlags &= 0xfffffff;
        break;
    case 0x1b:
        intr = OSDisableInterrupts();
        entryIndex = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x2000000) == 0 && (entryIndex & 0x1000000) == 0) {
            tab0 = (size_t)MLDF_PTR(0x1a);
        }
        if ((entryIndex & 0x8000000) == 0 && (entryIndex & 0x4000000) == 0) {
            tab1 = MLDF_PTR(0x53);
        }
        slotScratch = offsetFlags & 0x80000000;
        if (slotScratch != 0 && tab0 == 0) {
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   entryIndex != 0) {
                if ((entryIndex & 0x2000000) == 0 && (entryIndex & 0x1000000) == 0) {
                    tab0 = (size_t)MLDF_PTR(0x1a);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        } else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0) {
            while (intr = OSDisableInterrupts(), entryIndex = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   entryIndex != 0) {
                if ((entryIndex & 0x8000000) == 0 && (entryIndex & 0x4000000) == 0) {
                    tab1 = MLDF_PTR(0x53);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        }
        if ((offsetFlags & 0x20000000) != 0 && tab1 != 0) {
            fileId = 0x54;
        } else if (slotScratch != 0 && tab0 != 0) {
            fileId = 0x1b;
        } else if (tab0 != 0) {
            fileId = 0x1b;
        } else if (tab1 != 0) {
            fileId = 0x54;
        }
        offsetFlags &= 0xfffffff;
        break;
    case 0x25:
        intr = OSDisableInterrupts();
        entryIndex = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((entryIndex & 0x20000) == 0 && (entryIndex & 0x10000) == 0) {
            tab0 = (size_t)MLDF_PTR(0x26);
        }
        if ((entryIndex & 0x80000) == 0 && (entryIndex & 0x40000) == 0) {
            tab1 = MLDF_PTR(0x48);
        }
        if ((offsetFlags & 0x20000000) != 0 && tab1 != 0) {
            fileId = 0x47;
        } else if ((offsetFlags & 0x10000000) != 0 && tab0 != 0) {
            fileId = 0x25;
        } else if (tab0 != 0) {
            fileId = 0x25;
        } else if (tab1 != 0) {
            fileId = 0x47;
        }
        offsetFlags &= 0xfffffff;
        break;
    case 0x2b:
        intr = OSDisableInterrupts();
        slotScratch = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if (((int)slotScratch & 4) == 0 && ((int)slotScratch & 1) == 0) {
            tab0 = (size_t)MLDF_PTR(0x2a);
        }
        if (((int)slotScratch & 8) == 0 && ((int)slotScratch & 2) == 0) {
            tab1 = MLDF_PTR(0x45);
        }
        entryOff = offsetFlags & 0x10000000;
        if (entryOff != 0 && tab0 == 0) {
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   flags != 0) {
                if ((flags & 4) == 0 && (flags & 1) == 0) {
                    tab0 = (size_t)MLDF_PTR(0x2a);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        } else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0) {
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   flags != 0) {
                if ((flags & 8) == 0 && (flags & 2) == 0) {
                    tab1 = MLDF_PTR(0x45);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        }
        if (tab1 != 0 && (offsetFlags & 0x20000000) != 0) {
            fileId = 0x46;
            if (sizeOut != NULL) {
                entryOff = ((int*)tab1)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0) {
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                } else if (entryOff < (((int*)(tab1 - 4))[entryIndex] & 0xffffff)) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while (entryOff != (((int*)tab1)[prev] & 0xffffff));
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        } else if (tab0 != 0 && entryOff != 0) {
            fileId = 0x2b;
            if (sizeOut != NULL) {
                entryOff = ((int*)tab0)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0) {
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                } else if (entryOff < (((int*)(tab0 - 4))[entryIndex] & 0xffffff)) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while (entryOff != (((int*)tab0)[prev] & 0xffffff));
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        } else if (tab0 != 0) {
            fileId = 0x2b;
            if (sizeOut != NULL) {
                entryOff = ((int*)tab0)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0) {
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                } else if (entryOff < (((int*)(tab0 - 4))[entryIndex] & 0xffffff)) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while (entryOff != (((int*)tab0)[prev] & 0xffffff));
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        } else if (tab1 != 0) {
            fileId = 0x46;
            if (sizeOut != NULL) {
                entryOff = ((int*)tab1)[entryIndex] & 0xffffff;
                i = 0;
                if (entryOff == 0) {
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                } else if (entryOff < (((int*)(tab1 - 4))[entryIndex] & 0xffffff)) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while (entryOff != (((int*)tab1)[prev] & 0xffffff));
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= entryOff);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - entryOff;
                }
            }
        }
        offsetFlags &= 0xfffffff;
        break;
    case 0x30:
        intr = OSDisableInterrupts();
        flags = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((flags & 0x40) == 0 && (flags & 0x10) == 0) {
            tab0 = (size_t)MLDF_PTR(0x2f);
        }
        if ((flags & 0x80) == 0 && (flags & 0x20) == 0) {
            tab1 = MLDF_PTR(0x49);
        }
        if ((offsetFlags & 0x10000000) != 0 && tab0 == 0) {
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   flags != 0) {
                if ((flags & 0x40) == 0 && (flags & 0x10) == 0) {
                    tab0 = (size_t)MLDF_PTR(0x2f);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        } else if ((offsetFlags & 0x20000000) != 0 && tab1 == 0) {
            while (intr = OSDisableInterrupts(), flags = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr),
                   flags != 0) {
                if ((flags & 0x80) == 0 && (flags & 0x20) == 0) {
                    tab1 = MLDF_PTR(0x49);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        }
        if ((offsetFlags & 0x20000000) != 0) {
            fileId = 0x4a;
            if (sizeOut != NULL) {
                *sizeOut = (((u32*)(tab1 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab1)[entryIndex] & 0xfffffff);
            }
        } else if ((offsetFlags & 0x10000000) != 0) {
            fileId = 0x30;
            if (sizeOut != NULL) {
                *sizeOut = (((u32*)(tab0 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab0)[entryIndex] & 0xfffffff);
            }
        } else if (tab0 != 0) {
            fileId = 0x30;
            if (sizeOut != NULL) {
                *sizeOut = (((u32*)(tab0 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab0)[entryIndex] & 0xfffffff);
            }
        } else if (tab1 != 0) {
            fileId = 0x4a;
            if (sizeOut != NULL) {
                *sizeOut = (((u32*)(tab1 + 4))[entryIndex] & 0xfffffff) - (((u32*)tab1)[entryIndex] & 0xfffffff);
            }
        }
        offsetFlags &= 0xfffffff;
        if (((u8)flagBits & 1) != 0) {
            qptr = *(void**)((fileId << MLDF_BUFFER_SLOT_SHIFT) + (size_t)tbl->ptrs);
            slotPtrAddr = (size_t)(qptr + offsetFlags);
            tmp = ObjModel_IsPackedResource((u8*)slotPtrAddr);
            if (tmp != 0) {
                *sizeOut = ObjModel_GetUnpackedResourceSize((u8*)slotPtrAddr, *sizeOut);
            }
        }
        break;
    case 0x51:
        slotScratch = (size_t)MLDF_PTR(0x52);
        if (slotScratch != 0) {
            fileId = 0x51;
            if (sizeOut != NULL) {
                *sizeOut =
                    (((u32*)(slotScratch + 4))[entryIndex] & 0xfffffff) - (((u32*)slotScratch)[entryIndex] & 0xfffffff);
            }
        }
        offsetFlags &= 0xfffffff;
        if (((u8)flagBits & 1) != 0) {
            qptr = *(void**)((fileId << MLDF_BUFFER_SLOT_SHIFT) + (size_t)tbl->ptrs);
            slotPtrAddr = (size_t)(qptr + offsetFlags);
            tmp = ObjModel_IsPackedResource((u8*)slotPtrAddr);
            if (tmp != 0) {
                *sizeOut = ObjModel_GetUnpackedResourceSize((u8*)slotPtrAddr, *sizeOut);
            }
        }
        break;
    case 0x23:
        intr = OSDisableInterrupts();
        i = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((i & 0x100) == 0 && (i & 0x100) == 0) {
            tab0 = (size_t)MLDF_PTR(0x24);
        }
        if ((i & 0x800) == 0 && (i & 0x200) == 0) {
            tab1 = MLDF_PTR(0x4e);
        }
        if ((offsetFlags & 0x40000000) != 0 && tab0 == 0) {
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0) {
                if ((i & 0x100) == 0 && (i & 0x100) == 0) {
                    tab0 = (size_t)MLDF_PTR(0x24);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        } else if ((offsetFlags & 0x80000000) != 0 && tab1 == 0) {
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0) {
                if ((i & 0x800) == 0 && (i & 0x200) == 0) {
                    tab1 = MLDF_PTR(0x4e);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        }
        if (tab1 != 0 &&
            (entryByteOff = entryIndex << 2, (*(u32*)((u8*)tbl->mergeTex0 + entryByteOff) & 0x80000000) != 0)) {
            fileId = 0x4d;
            if (sizeOut != NULL) {
                offsetFlags = *(int*)((u8*)tab1 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        } else if (tab0 != 0 &&
                   (entryByteOff = entryIndex << 2, (*(int*)((u8*)tbl->mergeTex0 + entryByteOff) & 0x40000000) != 0)) {
            fileId = 0x23;
            if (sizeOut != NULL) {
                offsetFlags = *(int*)((u8*)tab0 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        } else if (tab1 != 0) {
            fileId = 0x4d;
            if (sizeOut != NULL) {
                offsetFlags = ((int*)tab1)[entryIndex] & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        } else if (tab0 != 0) {
            fileId = 0x23;
            if (sizeOut != NULL) {
                offsetFlags = ((int*)tab0)[entryIndex] & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        offsetFlags &= 0xfffffff;
        break;
    case 0x20:
        intr = OSDisableInterrupts();
        i = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(intr);
        if ((i & 0x4000) == 0 && (i & 0x1000) == 0) {
            tab0 = (size_t)MLDF_PTR(0x21);
        }
        if ((i & 0x8000) == 0 && (i & 0x2000) == 0) {
            tab1 = MLDF_PTR(0x4c);
        }
        if ((offsetFlags & 0x40000000) != 0 && tab0 == 0) {
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0) {
                if ((i & 0x1000) == 0 && (i & 0x1000) == 0) {
                    tab0 = (size_t)MLDF_PTR(0x21);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        } else if ((offsetFlags & 0x80000000) != 0 && tab1 == 0) {
            while (intr = OSDisableInterrupts(), i = gAssetLoadInFlightFlags, OSRestoreInterrupts(intr), i != 0) {
                if ((i & 0x8000) == 0 && (i & 0x2000) == 0) {
                    tab1 = MLDF_PTR(0x4c);
                    break;
                }
                padUpdate();
                checkReset();
                if (frame != 0) {
                    waitNextFrame();
                }
                loadDataFiles(0);
                dvdCheckError();
                if (frame != 0) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != 0) {
                    frame = 1;
                }
            }
        }
        if (tab1 != 0 &&
            (entryByteOff = entryIndex << 2, (*(u32*)((u8*)tbl->mergeTex1 + entryByteOff) & 0x80000000) != 0)) {
            fileId = 0x4b;
            if (sizeOut != NULL) {
                offsetFlags = *(int*)((u8*)tab1 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        } else if (tab0 != 0 &&
                   (entryByteOff = entryIndex << 2, (*(int*)((u8*)tbl->mergeTex1 + entryByteOff) & 0x40000000) != 0)) {
            fileId = 0x20;
            if (sizeOut != NULL) {
                offsetFlags = *(int*)((u8*)tab0 + entryByteOff) & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        } else if (tab1 != 0) {
            fileId = 0x4b;
            if (sizeOut != NULL) {
                offsetFlags = ((int*)tab1)[entryIndex] & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab1)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab1 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        } else if (tab0 != 0) {
            fileId = 0x20;
            if (sizeOut != NULL) {
                offsetFlags = ((int*)tab0)[entryIndex] & 0xffffff;
                if (offsetFlags == 0) {
                    i = 0;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tab0)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tab0 - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        offsetFlags &= 0xfffffff;
        break;
    case 0x4f: {
        u8* tabPtr;

        tabPtr = MLDF_PTR(0x50);
        if (tabPtr != 0) {
            fileId = 0x4f;
            if (sizeOut != NULL) {
                offsetFlags = ((int*)tabPtr)[entryIndex] & 0xffffff;
                if (offsetFlags == 0) {
                    do {
                        prev = tab0;
                        tab0 += 1;
                    } while ((((int*)tabPtr)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tabPtr - 4))[tab0] & 0xffffff) - offsetFlags;
                } else {
                    i = entryIndex;
                    do {
                        prev = i;
                        i += 1;
                    } while ((((int*)tabPtr)[prev] & 0xffffff) <= offsetFlags);
                    *sizeOut = (((int*)(tabPtr - 4))[i] & 0xffffff) - offsetFlags;
                }
            }
        }
        offsetFlags &= 0xfffffff;
        break;
    }
    }
    if (((u8)flagBits & 1) != 0) {
        return 0;
    }
    slotPtrAddr = (fileId << MLDF_BUFFER_SLOT_SHIFT) + ((size_t)tbl->ptrs + MLDF_BUFFER_PTRS_FROM_ARENA_END);
    qptr = MLDF_QPTR;
    if (qptr != 0) {
        if (fileId == 0xd || fileId == 0x55) {
            if (qptr == 0) {
                return 0;
            }
            memcpy(destBuf, (void*)(qptr + offsetFlags), length);
        } else if (fileId == 0x1b || fileId == 0x54) {
            if (qptr == 0) {
                return 0;
            }
            fileBuf = qptr + offsetFlags;
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0) {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + offsetFlags + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
            } else {
                return 0;
            }
        } else if (fileId == 0x25 || fileId == 0x47) {
            if (qptr == 0) {
                return 0;
            }
            fileBuf = qptr + offsetFlags;
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0) {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + offsetFlags + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
            } else {
                return 0;
            }
        } else if (fileId == 0x2b || fileId == 0x46) {
            struct PackHeader* hdr = (struct PackHeader*)(qptr + offsetFlags);
            /* Preserve the signed archive-relative arithmetic and its retail load order. */
            if (hdr->magic == 0xe0e0e0e0) {
                memcpy(destBuf, (u8*)((size_t)qptr + ((hdr->auxSize + 0x18) + (ptrdiff_t)hdr - (ptrdiff_t)qptr)),
                       hdr->decompressedSize);
            } else if (hdr->magic == 0xfacefeed) {
                zlbDecompress((u8*)((size_t)qptr + ((hdr->auxSize + 0x28) + (ptrdiff_t)hdr - (ptrdiff_t)qptr)),
                              hdr->compressedSize - 0x10, (u8*)destBuf, &hdr->decompressedSize);
                DCStoreRange(destBuf, hdr->decompressedSize);
            }
        } else if (fileId == 0x23 || fileId == 0x4d) {
            fileBuf = qptr + (offsetFlags & 0xffffff);
            decompSize = ZLB_HDR(fileBuf)->decompressedSize;
            zlbDecompress((u8*)(fileBuf + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf, &decompSize);
            DCStoreRange(destBuf, decompSize);
        } else if (fileId == 0x20 || fileId == 0x4b) {
            entryIndex = offsetFlags & 0xffffff;
            fileBuf = qptr + entryIndex;
            if (strncmp(sDirBlockTag, (char*)fileBuf, 3) == 0) {
                return (void*)(MLDF_QPTR + entryIndex + 0x20);
            }
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0) {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + entryIndex + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
            }
        } else if (fileId == 0x4f) {
            entryIndex = offsetFlags & 0xffffff;
            fileBuf = qptr + entryIndex;
            if (strncmp(sDirBlockTag, (char*)fileBuf, 3) == 0) {
                return (void*)(MLDF_QPTR + entryIndex + 0x20);
            }
            if (strncmp((char*)fileBuf, sZlbBlockTag, 3) == 0) {
                decompSize = ZLB_HDR(fileBuf)->decompressedSize;
                zlbDecompress((u8*)(MLDF_QPTR + entryIndex + 0x10), ZLB_HDR(fileBuf)->compressedSize, (u8*)destBuf,
                              &decompSize);
                DCStoreRange(destBuf, decompSize);
            }
        } else if (fileId == 0x30 || fileId == 0x51 || fileId == 0x4a) {
            fileBuf = qptr + offsetFlags;
            tmp = ObjModel_IsPackedResource((u8*)fileBuf);
            if (tmp != 0) {
                ObjModel_UnpackResourcePayload((u8*)fileBuf, *sizeOut, (u8*)destBuf,
                                               ObjModel_GetUnpackedResourceSize((u8*)fileBuf, *sizeOut));
            } else {
                memcpy(destBuf, (void*)(MLDF_QPTR + offsetFlags), length);
            }
        } else {
            memcpy(destBuf, (void*)(qptr + offsetFlags), length);
        }
    } else if (fileId == 0x20 || fileId == 0x4b) {
        u8* srcBuf;

        DVDOpen(sResourceFileNameTable[fileId], &buf);
        alignedSize = (length + 0x1f) & 0xffffffe0;
        srcBuf = mmAlloc(alignedSize, 0x7f7f7fff, 0);
        DVDRead(&buf, (void*)srcBuf, alignedSize, offsetFlags & 0xffffff);
        DVDClose(&buf);
        DCStoreRange((void*)srcBuf, length);
        if (strncmp(sDirBlockTag, (char*)srcBuf, 3) == 0) {
            for (;;) {
            }
        }
        if (strncmp((char*)srcBuf, sZlbBlockTag, 3) == 0) {
            decompSize = ZLB_HDR(srcBuf)->decompressedSize;
            zlbDecompress((u8*)(srcBuf + 0x10), ZLB_HDR(srcBuf)->compressedSize, (u8*)destBuf, &decompSize);
        }
        mm_free((void*)srcBuf);
    } else {
        DVDOpen(sResourceFileNameTable[fileId], &buf);
        if (((size_t)destBuf & 0x1f) != 0 || ((int)length & 0x1f) != 0) {
            u32 bounceSize;
            void* bounceBuf;

            bounceSize = (length + 0x1f) & 0xffffffe0;
            bounceBuf = mmAlloc(bounceSize, 0x7f7f7fff, 0);
            DVDRead(&buf, (void*)bounceBuf, bounceSize, offsetFlags);
            memcpy(destBuf, (void*)bounceBuf, length);
            mm_free((void*)bounceBuf);
        } else {
            DVDRead(&buf, destBuf, length, offsetFlags);
        }
        DCStoreRange(destBuf, length);
        DVDClose(&buf);
    }
    return 0;
}

extern void* gMapRomListBuffers[];

int mapGetDirIdx(int idx) {
    if (idx >= 0x4b) {
        return 5;
    }
    return sMapFileNameIndexRemapTable[idx];
}

extern int gResourcePendingMapIds[];

void loadDataFiles() {
    int i;
    if (getButtonsJustPressed(2) & PAD_BUTTON_A) {
        int vi = 0x4F;
        vi++;
        for (; vi < 0x57; vi++) {
        }
        printHeapStats(1);
    }
    if (getButtonsJustPressed(2) & PAD_BUTTON_B) {
        defragMemory(0);
    }
    if (gDefragDelayFrames != 0) {
        if (gDefragDelayFrames == 1) {
            defragMemory(0);
        }
        gDefragDelayFrames--;
    }
    for (i = 0; i <= 0x57; i++) {
        if (gResourcePendingMapIds[i] != -1) {
            debugPrintSetColor(0, 0xff, 0, 0xff);
            logPrintf(sAssetHaltFormat, sResourceFileNameTable[i]);
            debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
            gForceLoadImmediately = 1;
            if (mapLoadDataFile(gResourcePendingMapIds[i], i) != 0) {
                gResourcePendingMapIds[i] = -1;
                printHeapStats(1);
            }
            gForceLoadImmediately = 0;
        }
    }
    loadTableFiles();
}
void piRomLoadSection(int mapsOffset, int mapIndex, void* destBuf) {
    char buf[1024];
    DVDFileInfo* fi;
    int ok;
    struct PackHeader* hdr;

    if ((destBuf == NULL) && (gMapRomListBuffers[mapIndex] == NULL)) {
        sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
        fi = AtomicSList_Pop(gDvdFileInfoPool);
        ok = DVDOpen(buf, fi);
        if (ok != 0) {
            gMapRomListBuffers[mapIndex] = mmAlloc(DVD_FI_LENGTH(fi), 0x7d7d7d7d, 0);
            gRomListLoadInFlight = 1;
            DVDReadAsyncPrio(fi, gMapRomListBuffers[mapIndex], DVD_FI_LENGTH(fi), 0, romListReadCb, 2);
        }
    } else {
        if (gMapRomListBuffers[mapIndex] == NULL) {
            sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex]);
            fi = AtomicSList_Pop(gDvdFileInfoPool);
            ok = DVDOpen(buf, fi);
            if (ok == 0) {
                return;
            }
            gMapRomListBuffers[mapIndex] = mmAlloc(DVD_FI_LENGTH(fi), 0x7d7d7d7d, 0);
            DVDRead(fi, gMapRomListBuffers[mapIndex], DVD_FI_LENGTH(fi), 0);
            DVDClose(fi);
            AtomicSList_Push(gDvdFileInfoPool, fi);
        }
        /* MAPS.bin owns the header; the per-map romlist owns the compressed payload. */
        hdr = (struct PackHeader*)((u8*)gResourceFileBuffers[0x1d] + mapsOffset);
        if (hdr->magic == 0xfacefeed) {
            zlbDecompress((u8*)gMapRomListBuffers[mapIndex] + 0x10, hdr->compressedSize, (u8*)destBuf,
                          &hdr->decompressedSize);
            DCStoreRange(destBuf, hdr->decompressedSize);
        }
    }
}

void tex1GetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                  int* frameOffsets, int queryMode) {
    int idx = -1;
    if (gResourceFileBuffers[0x20] != 0 || gResourceFileBuffers[0x4b] != 0) {
        int s = OSDisableInterrupts();
        int flags = gAssetLoadInFlightFlags;
        void* f46c;
        void* f518;
        OSRestoreInterrupts(s);
        f46c = gResourceFileBuffers[0x21];
        f518 = gResourceFileBuffers[0x4c];
        if ((bankWord & 0x80000000) != 0 && (flags & 0x2000) == 0) {
            idx = 0x4b;
        } else if ((bankWord & 0x40000000) != 0 && (flags & 0x1000) == 0) {
            idx = 0x20;
        } else if (f46c != 0 && (flags & 0x1000) == 0 && gResourceFileBuffers[0x20] != 0) {
            idx = 0x20;
        } else if (f518 != 0 && (flags & 0x2000) == 0 && gResourceFileBuffers[0x4b] != 0) {
            idx = 0x4b;
        }
        {
            u8* base = gResourceFileBuffers[idx];
            if (base != 0) {
                if (queryMode == TEXTURE_FRAME_QUERY_INDEXED_HEADER && frameOffsets != 0) {
                    size_t e = (bankWord & 0xffffff) * 2 + frameOffsets[frameIndexOrCount];
                    int v;
                    e = (size_t)base + e + 4;
                    v = *(int*)(e + 4);
                    *compressedSize = *(int*)(e + 8);
                    *decompressedSize = v;
                } else if (queryMode == TEXTURE_FRAME_QUERY_OFFSETS && frameOffsets != 0) {
                    memcpy(frameOffsets, (void*)(base + (bankWord & 0xffffff) * 2), (frameIndexOrCount + 1) * 4);
                } else {
                    u8* e = base + (bankWord & 0xffffff) * 2;
                    int v = *(int*)(e + 0xc);
                    *decompressedSize = *(int*)(e + 8);
                    if (strncmp(sDirBlockTag, (char*)e, 3) == 0) {
                        *compressedSize = 0xffffffff;
                    } else {
                        *compressedSize = v;
                    }
                }
            } else {
                DVDFileInfo fileInfo;
                int v;
                char* buf;
                DVDOpen(sResourceFileNameTable[idx], &fileInfo);
                buf = mmAlloc(0x400, 0x7f7f7fff, 0);
                DVDRead(&fileInfo, buf, 0x400, (bankWord & 0xffffff) * 2);
                DVDClose(&fileInfo);
                DCStoreRange(buf, 0x400);
                if (queryMode == TEXTURE_FRAME_QUERY_INDEXED_HEADER && frameOffsets != 0) {
                    size_t e = frameOffsets[frameIndexOrCount];
                    int v;
                    e = (size_t)buf + e + 4;
                    v = *(int*)(e + 4);
                    *compressedSize = *(int*)(e + 8);
                    *decompressedSize = v;
                } else if (queryMode == TEXTURE_FRAME_QUERY_OFFSETS && frameOffsets != 0) {
                    memcpy(frameOffsets, buf, (frameIndexOrCount + 1) * 4);
                } else {
                    v = *(int*)(buf + 0xc);
                    *decompressedSize = *(int*)(buf + 8);
                    if (strncmp(sDirBlockTag, buf, 3) == 0) {
                        *compressedSize = 0xffffffff;
                    } else {
                        *compressedSize = v;
                    }
                }
                mm_free(buf);
            }
        }
    }
}

void tex0GetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                  int* frameOffsets, int queryMode) {
    int idx = -1;
    if (gResourceFileBuffers[0x23] != 0 || gResourceFileBuffers[0x4d] != 0) {
        int s = OSDisableInterrupts();
        int flags = gAssetLoadInFlightFlags;
        void* f478;
        void* f520;
        OSRestoreInterrupts(s);
        f478 = gResourceFileBuffers[0x24];
        f520 = gResourceFileBuffers[0x4e];
        if ((bankWord & 0x80000000) != 0 && (flags & 0x200) == 0) {
            idx = 0x4d;
        } else if ((bankWord & 0x40000000) != 0 && (flags & 0x100) == 0) {
            idx = 0x23;
        } else if (f478 != 0 && (flags & 0x100) == 0) {
            idx = 0x23;
        } else if (f520 != 0 && (flags & 0x200) == 0) {
            idx = 0x4d;
        }
        if (queryMode == TEXTURE_FRAME_QUERY_INDEXED_HEADER && frameOffsets != 0) {
            u8* base = gResourceFileBuffers[idx];
            u8* e = base + (bankWord & 0xffffff) * 2 + frameOffsets[frameIndexOrCount] + 4;
            int v = *(int*)(e + 8);
            *decompressedSize = *(int*)(e + 4);
            *compressedSize = v;
        } else if (queryMode == TEXTURE_FRAME_QUERY_OFFSETS && frameOffsets != 0) {
            memcpy(frameOffsets, (void*)((u8*)gResourceFileBuffers[idx] + (bankWord & 0xffffff) * 2),
                   (frameIndexOrCount + 1) * 4);
        } else {
            u8* e = (u8*)gResourceFileBuffers[idx] + (bankWord & 0xffffff) * 2 + 4;
            int v = *(int*)(e + 8);
            *decompressedSize = *(int*)(e + 4);
            *compressedSize = v;
        }
    }
}

void texPreGetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                    int* frameOffsets, int queryMode) {
    u8* base = gResourceFileBuffers[0x4f];
    if (base != 0) {
        if (queryMode == TEXTURE_FRAME_QUERY_INDEXED_HEADER && frameOffsets != 0) {
            u8* e = base + (bankWord & 0xffffff) * 2 + frameOffsets[frameIndexOrCount] + 4;
            int v = *(int*)(e + 8);
            *decompressedSize = *(int*)(e + 4);
            *compressedSize = v;
        } else if (queryMode == TEXTURE_FRAME_QUERY_OFFSETS && frameOffsets != 0) {
            memcpy(frameOffsets, (void*)(base + (bankWord & 0xffffff) * 2), (frameIndexOrCount + 1) * 4);
        } else {
            u8* e = base + (bankWord & 0xffffff) * 2;
            int v = *(int*)(e + 0xc);
            *decompressedSize = *(int*)(e + 8);
            if (strncmp(sDirBlockTag, (char*)e, 3) == 0) {
                *compressedSize = 0xffffffff;
            } else {
                *compressedSize = v;
            }
        }
    }
}

void loadModelsBin(int offsetFlags, int* animationCount, int* maxAnimationBytes, int* useCachedAnimations,
                   int* modelBytes, int modelId) {
    void* tableA = 0;
    void* tableB = 0;
    int archiveId = -1;
    int loadFlags;
    int interruptState;
    ModelArchiveHeaderPrefix* entry;
    if (gResourceFileBuffers[MLDF_FILEID_MODELS_BIN_A] != 0 || gResourceFileBuffers[MLDF_FILEID_MODELS_BIN_B] != 0) {
        interruptState = OSDisableInterrupts();
        loadFlags = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(interruptState);
        if ((loadFlags & 4) == 0 && (loadFlags & 1) == 0) {
            tableA = gResourceFileBuffers[MLDF_FILEID_MODELS_TAB_A];
        }
        if ((loadFlags & 8) == 0 && (loadFlags & 2) == 0) {
            tableB = gResourceFileBuffers[MLDF_FILEID_MODELS_TAB_B];
        }
        if (tableB != 0 && (offsetFlags & 0x20000000) != 0) {
            archiveId = MLDF_FILEID_MODELS_BIN_B;
        } else if (tableA != 0 && (offsetFlags & 0x10000000) != 0) {
            archiveId = MLDF_FILEID_MODELS_BIN_A;
        } else if (tableA != 0) {
            archiveId = MLDF_FILEID_MODELS_BIN_A;
        } else if (tableB != 0) {
            archiveId = MLDF_FILEID_MODELS_BIN_B;
        }
        entry = (ModelArchiveHeaderPrefix*)((u8*)gResourceFileBuffers[archiveId] + (offsetFlags & 0x0fffffff));
        *useCachedAnimations = entry->useCachedAnimations;
        *animationCount = entry->animationCount;
        *maxAnimationBytes = entry->maxAnimationBytes;
        *modelBytes = entry->pack.decompressedSize;
    }
}

void mapsBinGetRomlistSize(int idx, int* out1, int* out2, int* out3, int p5) {
    char* e;
    if (gResourceFileBuffers[0x1d] == NULL) {
        return;
    }
    if (gResourceFileBuffers[0x1e] == NULL) {
        return;
    }
    e = (char*)gResourceFileBuffers[0x1d] + idx;
    *out1 = *(s16*)(e + 0x1c);
    *out2 = *(s16*)(e + 0x1e);
    *out3 = *(int*)((char*)gResourceFileBuffers[0x1d] + *(int*)((char*)gResourceFileBuffers[0x1e] + p5 * 4 + 0x18) + 4);
}

void checkLoadBlock(int a, int* pc, int* p8) {
    int idx = -1;
    int flags;
    int saved;
    char* blk;
    void* t25;
    void* t47;
    if ((gResourceFileBuffers[0x26] != 0 && gResourceFileBuffers[0x25] != 0) ||
        (gResourceFileBuffers[0x48] != 0 && gResourceFileBuffers[0x47] != 0)) {
        saved = OSDisableInterrupts();
        flags = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(saved);
        t25 = gResourceFileBuffers[0x25];
        t47 = gResourceFileBuffers[0x47];
        if (t25 != 0 && (a & 0x10000000) != 0 && (flags & 0x10000) == 0) {
            idx = 0x25;
        } else if (t47 != 0 && (a & 0x20000000) != 0 && (flags & 0x40000) == 0) {
            idx = 0x47;
        } else if (t25 != 0 && (flags & 0x10000) == 0) {
            idx = 0x25;
        } else if (t47 != 0 && (flags & 0x40000) == 0) {
            idx = 0x47;
        }
        blk = (char*)gResourceFileBuffers[idx] + (a & 0x00ffffff);
        if (strncmp(blk, sZlbBlockTag, 3) != 0) {
            *p8 = 0;
            *pc = 0;
        } else {
            {
                int vc = ZLB_HDR(blk)->compressedSize;
                *p8 = ZLB_HDR(blk)->decompressedSize;
                *pc = vc;
            }
        }
    } else {
        *p8 = 0;
        *pc = 0;
    }
}

void loadVoxMaps(int a, int* pc, int* p8) {
    int idx = -1;
    int flags;
    int saved;
    char* blk;
    void* t1b;
    void* t54;
    if ((gResourceFileBuffers[0x1a] != 0 && gResourceFileBuffers[0x1b] != 0) ||
        (gResourceFileBuffers[0x53] != 0 && gResourceFileBuffers[0x54] != 0)) {
        saved = OSDisableInterrupts();
        flags = gAssetLoadInFlightFlags;
        OSRestoreInterrupts(saved);
        t1b = gResourceFileBuffers[0x1b];
        t54 = gResourceFileBuffers[0x54];
        if (t1b != 0 && (a & 0x80000000) != 0 && (flags & 0x1000000) == 0) {
            idx = 0x1b;
        } else if (t54 != 0 && (a & 0x20000000) != 0 && (flags & 0x4000000) == 0) {
            idx = 0x54;
        } else if (t1b != 0 && (flags & 0x1000000) == 0) {
            idx = 0x1b;
        } else if (t54 != 0 && (flags & 0x4000000) == 0) {
            idx = 0x54;
        }
        if ((a & 0xf0000000) != 0) {
            blk = (char*)gResourceFileBuffers[idx] + (a & 0x00ffffff);
            if (strncmp(blk, sZlbBlockTag, 3) != 0) {
                *p8 = 0;
                *pc = 0;
            } else {
                {
                    int vc = ZLB_HDR(blk)->compressedSize;
                    *p8 = ZLB_HDR(blk)->decompressedSize;
                    *pc = vc;
                }
            }
        } else {
            *p8 = 0;
            *pc = 0;
        }
    } else {
        *p8 = 0;
        *pc = 0;
    }
}

extern u32 gResourceFileSizes[];

s32 getDataFileSize(int idx) {
    if (gResourceFileBuffers[idx] != 0) {
        return gResourceFileSizes[idx];
    }
    *(u8*)0 = 0;
    return 0;
}
int fileLoadToBufferOffset(int id, void* buffer, int offset, int size) {
    DVDFileInfo fileInfo;
    int asize;
    void* tmp;
    if (size == 0) {
        return 0;
    }
    if (gResourceFileBuffers[id] != 0) {
        {
            u8* base = gResourceFileBuffers[id];
            memcpy(buffer, (void*)(base + offset), size);
        }
        DCStoreRange(buffer, size);
        return size;
    }
    DVDOpen(sResourceFileNameTable[id], &fileInfo);
    if (((size_t)buffer & 0x1fu) != 0 || (size & 0x1f) != 0) {
        asize = (size + 0x1f) & ~0x1f;
        tmp = mmAlloc(asize, 0x7d7d7d7d, 0);
        DCInvalidateRange(tmp, asize);
        DVDRead(&fileInfo, tmp, asize, offset);
        memcpy(buffer, tmp, size);
        mm_free(tmp);
    } else {
        DCInvalidateRange(buffer, size);
        DVDRead(&fileInfo, buffer, size, offset);
    }
    DVDClose(&fileInfo);
    DCStoreRange(buffer, size);
    return size;
}

int fileLoadToBuffer(int id, void* buffer) {
    DVDFileInfo fileInfo;
    if (gResourceFileBuffers[id] != 0) {
        memcpy(buffer, gResourceFileBuffers[id], gResourceFileSizes[id]);
        DCStoreRange(buffer, gResourceFileSizes[id]);
        return gResourceFileSizes[id];
    }
    DVDOpen(sResourceFileNameTable[id], &fileInfo);
    DCInvalidateRange(buffer, fileInfo.length);
    DVDRead(&fileInfo, buffer, fileInfo.length, 0);
    DVDClose(&fileInfo);
    return fileInfo.length;
}

void* fileLoad(int id, int wpad0) {
    DVDFileInfo fileInfo;
    if (gResourceFileBuffers[id] != 0) {
        return gResourceFileBuffers[id];
    }
    DVDOpen(sResourceFileNameTable[id], &fileInfo);
    gResourceFileSizes[id] = fileInfo.length;
    gResourceFileBuffers[id] = mmAlloc(gResourceFileSizes[id] + 0x20, 0x7d7d7d7d, 0);
    DCInvalidateRange(gResourceFileBuffers[id], gResourceFileSizes[id]);
    DVDRead(&fileInfo, gResourceFileBuffers[id], gResourceFileSizes[id], 0);
    DVDClose(&fileInfo);
    return gResourceFileBuffers[id];
}

u8 initLoadFiles(void) {
    int i;
    DVDFileInfo* fileInfo;
    void** rom;
    struct MldfIterators it;
    u8* himem;
    struct MldfTables* tbl = (struct MldfTables*)gResourceFileTable;
    if (gLoadFilesInitDone == 0) {
        gLoadFilesInitDone = 1;
        gPendingDvdReadCount = 0;
        gDvdFileInfoPool = stackCreate(0x5e, 0x40);
        i = 0;
        rom = (void**)((MldfArenaBlock*)tbl + 1) - MLDF_ROM_LIST_PTRS_FROM_ARENA_END;
        for (; i < 0x75; rom++, i++) {
            *rom = 0;
            if (i >= 0x50 || i == 0x49 || ((i == 0x43) | (i == 5))) {
                piRomLoadSection(0, i, 0);
            }
        }
        lbl_803DCC98 = 0;
        for (i = 0, himem = (u8*)tbl + 0x20000,
            it.ptrs = (void**)(himem - (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, ptrs))),
            it.owners = (s16*)(himem - (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, owners))),
            it.ids = (int*)(himem - (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, ids))),
            it.names = sResourceFileNameTable,
            it.sizes = (int*)(himem - (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, sizes))),
            it.flags = himem - (sizeof(MldfArenaBlock) - offsetof(struct MldfTables, loadedFlags));
             i <= 0x57; it.ptrs++, it.owners++, it.ids++, it.names++, it.sizes++, it.flags++, i++) {
            switch (i) {
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
                if (*it.ptrs == 0) {
                    fileInfo = AtomicSList_Pop(gDvdFileInfoPool);
                    DVDOpen(*it.names, fileInfo);
                    *it.sizes = fileInfo->length;
                    *it.ptrs = mmAlloc(*it.sizes + 0x20, 0x7d7d7d7d, 0);
                    gPendingDvdReadCount += 1;
                    DVDReadAsyncPrio(fileInfo, *it.ptrs, *it.sizes, 0, initLoadFileReadCb, 2);
                }
                *it.owners = -1;
                *it.ids = -1;
                break;
            }
            *it.flags = 0;
        }
    }
    if (gPendingDvdReadCount == 0) {
        if (((gAssetLoadInFlightFlags & 0x100) == 0 || (gAssetLoadInFlightFlags & 0x400) == 0) &&
            ((gAssetLoadCompletedFlags & 0x100) == 0 || (gAssetLoadCompletedFlags & 0x400) == 0)) {
            int saved = mmSetForceHeap3Only(0);
            mapLoadDataFile(5, MLDF_FILEID_TEX0_BIN_A);
            mapLoadDataFile(5, MLDF_FILEID_TEX0_TAB_A);
            mmSetForceHeap3Only(saved);
        } else if ((gAssetLoadCompletedFlags & 0x100) != 0 && (gAssetLoadCompletedFlags & 0x400) != 0) {
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
void tvInit(void) {
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

void gpuErrorHandler(u32 retraceCount) {
    char* strs = (char*)gLoadingScreenTextures;
    VideoFlipToken token;
    u32 xfTopBefore;
    u32 xfBottomBefore;
    u32 setupReadyBefore;
    u32 rasterReadyBefore;
    u32 xfTopAfter;
    u32 xfBottomAfter;
    u32 setupReadyAfter;
    u32 rasterReadyAfter;
    GXBool fifoReadIdle;
    GXBool commandIdle;
    GXBool unusedStatus;
    u32 xfTopUnchanged;
    u32 xfBottomUnchanged;
    u32 setupReadyAdvanced;
    u32 rasterReadyAdvanced;

    if (gFlipTokenHeldForDisplayedFb != 0 && gFrameBufferFlipped != 0) {
        Queue_Pop(&gVideoFlipQueue, &token);
        gGpuStallRetraceCount = 0;
        OSWakeupThread(&gVideoFlipWaitQueue);
        if (Queue_IsEmpty(&gVideoFlipQueue) != 0) {
            GXDisableBreakPt();
            gGxBreakPtEnabled = 0;
        } else {
            Queue_Peek(&gVideoFlipQueue, &token);
            GXEnableBreakPt(token.fifoWritePointer);
            gGxBreakPtEnabled = 1;
        }
        gFlipTokenHeldForDisplayedFb = 0;
        gFrameBufferFlipped = 0;
    }
    gPadReadReady = 1;
    gVideoRetracePending = 1;
    switch (gResetButtonPressState) {
    case 0:
        if (OSGetResetButtonState() != 0) {
            gResetButtonPressState++;
        }
        break;
    case 1:
        if (OSGetResetButtonState() == 0) {
            gResetButtonPressState++;
            setShouldResetNextFrame(1);
        }
        break;
    }
    if (enableDebugText != 0 && gVideoWaitThread != NULL && (u32)gGpuStallRetraceCount > 600) {
        debugPrintfxy(0x32, 100, strs + 0x40000);
        GXReadXfRasMetric(&xfBottomBefore, &xfTopBefore, &rasterReadyBefore, &setupReadyBefore);
        GXReadXfRasMetric(&xfBottomAfter, &xfTopAfter, &rasterReadyAfter, &setupReadyAfter);
        xfTopUnchanged = (xfTopAfter - xfTopBefore) == 0;
        xfBottomUnchanged = (xfBottomAfter - xfBottomBefore) == 0;
        setupReadyAdvanced = (setupReadyAfter - setupReadyBefore) != 0;
        rasterReadyAdvanced = (rasterReadyAfter - rasterReadyBefore) != 0;
        GXGetGPStatus(&unusedStatus, &unusedStatus, &fifoReadIdle, &commandIdle, &unusedStatus);
        debugPrintfxy(0x32, 0x78, strs + 0x4002c, fifoReadIdle, commandIdle, xfTopUnchanged, xfBottomUnchanged,
                      setupReadyAdvanced, rasterReadyAdvanced);
        if (xfBottomUnchanged == 0 && setupReadyAdvanced != 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x40048);
        } else if (xfTopUnchanged == 0 && xfBottomUnchanged != 0 && setupReadyAdvanced != 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x40068);
        } else if (commandIdle == 0 && xfTopUnchanged != 0 && xfBottomUnchanged != 0 && setupReadyAdvanced != 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x40090);
        } else if (fifoReadIdle != 0 && commandIdle != 0 && xfTopUnchanged != 0 && xfBottomUnchanged != 0 &&
                   setupReadyAdvanced != 0 && rasterReadyAdvanced != 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x400b4);
        } else {
            debugPrintfxy(0x32, 0x8c, strs + 0x400e4);
        }
        debugPrintfxy(0x32, 0xa0, sProgramCounterFormat, gVideoWaitThread->context.srr0);
    }
}

void videoSwapFrameBuffers(u32 retraceCount) {
    u16 sync;
    VideoFlipToken token;
    GXFifoObj fifo;

    gRetraceCountSinceFlip += 1;
    sync = GXReadDrawSync();
    if (sync == (u16)(gLastDrawSyncToken + 1)) {
        gLastDrawSyncToken = sync;
        if (displayFrameBuffer == externalFrameBuffer0) {
            displayFrameBuffer = externalFrameBuffer1;
        } else {
            displayFrameBuffer = externalFrameBuffer0;
        }
        VISetNextFrameBuffer(displayFrameBuffer);
        VIFlush();
        gFrameBufferFlipped = 1;
        lbl_803DB5C8 = gRetraceCountSinceFlip;
        gRetraceCountSinceFlip = 0;
    }
    gGpuStallRetraceCount += 1;
    if (gGpuHangRecoveryEnabled != 0 && (u32)gGpuStallRetraceCount > 18000) {
        logGpuHang();
        mapBlockGpuRecoveryHook();
        ObjModel_TouchModelCache();
        __GXAbortWaitPECopyDone();
        GXInitFifoBase(&fifo, renderFrameBuffer, 0x10000);
        GXSetCPUFifo(&fifo);
        GXSetGPFifo(&fifo);
        gGxFifoObj = GXInit(gGxFifoBase, gGxFifoSize);
        if (Queue_IsEmpty(&gVideoFlipQueue) == 0) {
            Queue_Pop(&gVideoFlipQueue, &token);
        }
        OSWakeupThread(&gVideoFlipWaitQueue);
        if (Queue_IsEmpty(&gVideoFlipQueue) != 0) {
            GXDisableBreakPt();
            gGxBreakPtEnabled = 0;
        } else {
            Queue_Peek(&gVideoFlipQueue, &token);
            GXEnableBreakPt(token.fifoWritePointer);
        }
        videoSetGpuHangMetricsEnabled(1);
    }
}

void videoBreakPointCallback(void) {
    VideoFlipToken peek;
    VideoFlipToken token;
    int i;

    if (gAttractMovieState == 2 || gAttractMovieState == 3) {
        THPPlayerPostDrawDone();
    }
    Queue_Peek(&gVideoFlipQueue, &peek);
    for (i = 0; i < (int)(u32)gDepthReadPendingCount; i++) {
        gDepthReadResults[i].x = gDepthReadPendingQueue[i].x;
        gDepthReadResults[i].y = gDepthReadPendingQueue[i].y;
        gDepthReadResults[i].key = gDepthReadPendingQueue[i].key;
        GXPeekZ(gDepthReadResults[i].x, gDepthReadResults[i].y, &gDepthReadResults[i].value);
    }
    gDepthReadResultCount = gDepthReadPendingCount;
    gDepthReadPendingCount = 0;
    if (peek.frameBuffer == displayFrameBuffer) {
        gFlipTokenHeldForDisplayedFb = 1;
        gFrameBufferFlipped = 0;
    } else {
        Queue_Pop(&gVideoFlipQueue, &token);
        gGpuStallRetraceCount = 0;
        OSWakeupThread(&gVideoFlipWaitQueue);
        if (Queue_IsEmpty(&gVideoFlipQueue) != 0) {
            GXDisableBreakPt();
            gGxBreakPtEnabled = 0;
        } else {
            Queue_Peek(&gVideoFlipQueue, &token);
            GXEnableBreakPt(token.fifoWritePointer);
            gGxBreakPtEnabled = 1;
        }
    }
}

RingBufferQueue gVideoFlipQueue;
VideoFlipToken gVideoFlipQueueBuffer[VIDEO_FLIP_QUEUE_CAPACITY];
OSStopwatch gFrameStopwatch;
s16 gObjMapBlockInfo[0x9C];
void* gResourceFileBuffers[0x58];
void* gMapRomListBuffers[0x78];
u32 gResourceFileSizes[0x58];
int gResourcePendingMapIds[0x58];
u32 gObjBlockStatus[0x63F6];
u8 gResourceFileTable[0x160];
