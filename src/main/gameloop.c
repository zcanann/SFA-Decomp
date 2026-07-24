#include "main/dll/partfx_interface.h"
#include "dolphin/os.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/audio/music_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/stream_api.h"
#include "main/map_load.h"
#include "main/pi_data_file_api.h"
#include "main/pi_flush_api.h"
#include "main/objprint_render_api.h"
#include "track/intersect_card_api.h"
#include "dolphin/pad.h"

u8 framesThisStep = 1;
u8 lbl_803DB411 = 1;
f32 timeDelta = 1.0f;
f32 oneOverTimeDelta = 1.0f;
int gGameLoopPendingUiDllId = -1;
f32 gGameLoopMusicFadeTimer = -30.0f;
u8 lbl_803DB424 = 0xFF;
u8 gGameLoopResetComboDebounce = 10;
int lbl_803DB428 = 0xAA;
int lbl_803DB42C = 0x16A;
#include "dolphin/vi.h"
#include "dolphin/dvd.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/carryable_interface.h"
#include "main/checkpoint_interface.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/savegame_load_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/projgfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/cloudaction_interface.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/mapEventTypes.h"
#include "main/model_engine.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/object_api.h"
#include "main/newclouds.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/pad.h"
#include "main/gameloop_api.h"
#include "main/gameloop_internal.h"
#include "main/newshadows.h"
#include "main/track_dolphin_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin.h"
#include "main/rcp_dolphin.h"
#include "main/lightmap_lifecycle_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "main/textrender_api.h"
#include "main/object_render.h"
#include "main/dll/dll_0011_screens.h"
#include "main/dll/dll_0031_minimap.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/dll_003C_tumbleweedbush.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "main/dll/path_control_interface.h"
#include "main/voxmaps.h"
#include "main/dll/FRONT/dll_0032_n_rareware.h"
#include "main/dll/dll_BC.h"
#include "track/intersect_api.h"
#include "dolphin/ai.h"
#include "main/lightmap.h"
#include "string.h"

f32 gGameLoopResetFadeOutTimer;
void* lbl_803DCAFC;
int gGameLoopPendingMapId;
int gGameLoopPendingMapDataFileId;
u8 gGameLoopPendingMusicId;
int gGameLoopButtonObjects[2];
u8 gGameLoopProgressiveMode;
u8* gGameBitSaveData;
u8* gGameBitTable;
s16 gGameBitCount;
int gGameLoopPlayerTrailIndex;
int gGameLoopPlayerTrailTime;
int lbl_803DCACC;
f32 gGameLoopResetHoldTimer;
u8 gGameLoopHardReset;
u8 lbl_803DCAC4;
CarryableInterface** gCarryableInterface;
MinimapInterface* gMinimapInterface;
BaddieControlInterface** gBaddieControlInterface;
BoneParticleEffectInterface** gBoneParticleEffectInterface;
void* lbl_803DCAB0;
MapEventInterface** gMapEventInterface;
PathControlInterface** gPathControlInterface;
TitleMenuItemInterface* gTitleMenuItemInterface;
LinkInterface* gTitleMenuLinkInterface;
RomCurveInterface** gRomCurveInterface;
WaterfxInterface** gWaterfxInterface;
void* lbl_803DCA94;
ScreensInterface* gScreensInterface;
PlayerControlInterface** gPlayerInterface;
EffectInterface** gPartfxInterface;
PlayerShadowInterface** gPlayerShadowInterface;
ProjgfxInterface** gProjgfxInterface;
ModgfxInterface** gModgfxInterface;
ExpgfxInterface** gExpgfxInterface;
Dummy04Interface* gTitleMenuControlInterfaceCopy;
Dummy04Interface* gTitleMenuControlInterface;
CheckpointInterface** gCheckpointInterface;
GameUIInterface** gGameUIInterface;
CloudActionInterface** gCloudActionInterface;
NewCloudsInterface** gNewCloudsInterface;
Sky2Interface** gSky2Interface;
SkyInterface** gSkyInterface;
ObjectTriggerInterface** gObjectTriggerInterface;
CameraInterface** gCameraInterface;
ScreenTransitionInterface** gScreenTransitionInterface;
u8 gGameLoopInitComplete;
u8 gGameLoopButtonObjectCount;
s16 screenBlankFrameCount;
u8 gGameLoopMusicActive;
u16 gGameLoopMusicRequestCount;
u8 gGameLoopMapLoadPending;
u8 lbl_803DCA40;
u8 lbl_803DCA3F;
u8 shouldResetNextFrame;
u8 gameState;
u8 timeStop;
s8 frameCountdown;
s8 hudHiddenFrameCount;
u8 gGameLoopReloadRequested;
u8 lbl_803DCA38;


typedef struct
{
    u8 pending;
    u8 type;
    u8 _2[2];
    int resourceId;
    int dest;
    int argC;
    int offset;
    int arg14;
    int arg18;
    int arg1c;
    int arg20;
    int arg24;
    int arg28;
} AssetReq;
void loadAsset(AssetReq* req)
{
    u8 tmp[0x10];

    switch (req->type)
    {
    case 0:
        *(void**)req->dest = fileLoad(req->resourceId, 0);
        break;
    case 1:
        fileLoadToBuffer(req->resourceId, (void*)req->dest);
        break;
    case 2:
        fileLoadToBufferOffset(req->resourceId, (void*)req->dest, req->offset, req->argC);
        break;
    case 4:
        *(void**)req->dest =
            loadCharacter((s16*)req->arg18, req->arg1c, req->arg24, req->arg20, (void*)req->arg14, req->arg28);
        break;
    case 3:
        *(void**)req->dest = (void*)textureLoad(req->resourceId, 0);
        break;
    case 5:
        *(void**)req->dest = Resource_Acquire(req->resourceId & 0xffff, req->argC & 0xffff);
        break;
    case 6:
        *(void**)req->dest = return0_8002969C(req->resourceId, req->argC, tmp);
        break;
    case 7:
        *(void**)req->dest = loadAnimation(req->arg24, req->resourceId, (s16)req->argC, (u8*)req->arg20);
        break;
    }
}

void doNothing_8001F678(int wpad0, int wpad1)
{
}
void doNothing_startOfFrame(void)
{
}
extern AssetReq gGameLoopAssetReq;

void animationLoad(void** out, int animId, int moveIndex, u8* cache, struct ObjAnimDef* animDef)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 7;
    gGameLoopAssetReq.resourceId = (s16)animId;
    gGameLoopAssetReq.dest = (int)out;
    gGameLoopAssetReq.argC = (s16)moveIndex;
    gGameLoopAssetReq.arg20 = (int)cache;
    gGameLoopAssetReq.arg24 = (int)animDef;
    loadAsset(&gGameLoopAssetReq);
}

void loadTextureFile(void** out, int assetId)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 3;
    gGameLoopAssetReq.resourceId = assetId;
    gGameLoopAssetReq.dest = (int)out;
    loadAsset(&gGameLoopAssetReq);
}

void getTabEntry(void* dst, int fileId, int offset, int size)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 2;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.dest = (int)dst;
    gGameLoopAssetReq.offset = offset;
    gGameLoopAssetReq.argC = size;
    loadAsset(&gGameLoopAssetReq);
}

void loadAssetFileById(void* out, int fileId)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 0;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.dest = (int)out;
    loadAsset(&gGameLoopAssetReq);
}

void crash(int wpad0, int wpad1, int wpad2, int wpad3, int wpad4, int wpad5, int wpad6, int wpad7)
{
    *(u8*)0 = 0;
}

char sGameLoopResetMessages[0x50] =
    "28/03/02 12:19\000\000Version 2.8 14/12/98 15.30 L.Schuneman\000\000\377\377\377\377\000\000\000.\000\000\0000";


void cardShowMessage(void)
{
    u32 held;
    int st;
    u8 ok;

    st = saveGameGetStatus();
    ok = 0;
    if (st < 0xc)
    {
        cutsceneEnterExit(1, 1);
        timeStop = 0xff;
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        if (lbl_803DCACC == 0)
        {
            switch (st)
            {
            case 1:
                gameTextShow(0x325);
                break;
            case 2:
                gameTextShow(0x494);
                break;
            case 3:
                gameTextShow(0x496);
                break;
            case 4:
                gameTextShow(0x32c);
                break;
            case 5:
            case 6:
                gameTextShow(0x326);
                ok = 1;
                break;
            case 9:
                gameTextShow(0x32a);
                break;
            case 10:
                gameTextShow(0x497);
                ok = 1;
                break;
            case 0xb:
                gameTextShow(0x4c7);
                break;
            }
        }
        held = getButtonsHeld(0);
        if (ok)
        {
            gameTextFn_80016810(0x495, 0, 0xc8);
        }
        else
        {
            gameTextFn_80016810(0x493, 0, 0xc8);
        }
        if (held & PAD_BUTTON_A)
        {
            buttonDisable(0, PAD_BUTTON_A);
            cardSetStatusNeedInit();
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            if (st == 0xa)
            {
                cardDeleteFn_8007d99c();
                return;
            }
            return;
        }
        else if (ok && (held & PAD_BUTTON_B))
        {
            buttonDisable(0, PAD_BUTTON_B);
            lbl_803DB424 = 0;
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            cardSetStatusNeedInit();
        }
    }
}






int cacheAllocAndCopy(u32 srcAddress, u32 size, u32* cacheCursor, u32* outEnd, u32 limit)
{
    u8* dst;
    u32 alignOffset;

    dst = getCache();
    alignOffset = srcAddress & 0x1f;
    size += alignOffset;
    size += 0x1f;
    size &= ~0x1f;
    if (*cacheCursor + size <= limit)
    {
        srcAddress -= alignOffset;
        *outEnd = *cacheCursor + size;
        dst += *cacheCursor;
        *cacheCursor = (u32)(dst + alignOffset);
        size >>= 5;
        while (size > 0x7f)
        {
            copyToCache(dst, (void*)srcAddress, 0);
            dst += 0x1000;
            srcAddress += 0x1000;
            size -= 0x80;
        }
        if (size != 0)
        {
            copyToCache(dst, (void*)srcAddress, size);
        }
        return 1;
    }
    *outEnd = *cacheCursor;
    *cacheCursor = srcAddress;
    return 0;
}
void askProgressiveScanMode(void)
{
    int showId;
    u32 counter;
    int sel;
    s32 textId;
    u32 i;
    u32 j;
    u8* box;
    u8 savedByte;

    counter = 0;
    sel = 1;
    box = gameTextGetBox(0);
    savedByte = box[0x10];
    box[0x10] = 0;
    do
    {
        counter++;
        padUpdate();
        checkReset();
        mmFreeTick(0);
        waitNextFrame();
        gameTextSetColor(0xc0, 0xc0, 0xc0, 0xff);
        gameTextShow(0x33f);
        if ((u8)sel == 1)
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        else
        {
            gameTextSetColor(0x80, 0x80, 0x80, 0x80);
        }
        gameTextShowStr(gameTextGetStr(0x3cd), 0, lbl_803DB428, 0x64);
        if ((u8)sel == 1)
        {
            gameTextSetColor(0x80, 0x80, 0x80, 0x80);
        }
        else
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        gameTextShowStr(gameTextGetStr(0x3cc), 0, lbl_803DB42C, 0x64);
        gameTextRun();
        dvdCheckError();
        doNothing_endOfFrame();
        GXFlush_(0, 0);
        if (padGetStickX(0) < 0 || padGetCX(0) < 0)
        {
            sel = 1;
        }
        else if (padGetStickX(0) > 0 || padGetCX(0) > 0)
        {
            sel = 0;
        }
    } while ((getButtonsJustPressed(0) & PAD_BUTTON_A) == 0 && counter < 600);
    box[0x10] = savedByte;
    waitNextFrame();
    GXFlush_(0, 0);
    waitNextFrame();
    GXFlush_(0, 0);
    VISetBlack(1);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    VIWaitForRetrace();
    VIWaitForRetrace();
    if ((u8)sel != 0)
    {
        gRenderModeObj = &GXNtsc480Prog;
        OSSetProgressiveMode(1);
        GXSetCopyFilter(gRenderModeObj->aa, gRenderModeObj->sample_pattern, GX_FALSE, gRenderModeObj->vfilter);
        VIConfigure(gRenderModeObj);
        VISetBlack(1);
        VIFlush();
        textId = 0x340;
    }
    else
    {
        gRenderModeObj = &GXNtsc480IntDf;
        OSSetProgressiveMode(0);
        GXSetCopyFilter(gRenderModeObj->aa, gRenderModeObj->sample_pattern, GX_TRUE, gRenderModeObj->vfilter);
        VIConfigure(gRenderModeObj);
        VISetBlack(1);
        VIFlush();
        textId = 0x341;
    }
    i = 0;
    do
    {
        VIWaitForRetrace();
        i++;
    } while (i < 100);
    VISetBlack(0);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    j = 0;
    showId = textId;
    do
    {
        j++;
        padUpdate();
        checkReset();
        mmFreeTick(0);
        waitNextFrame();
        if (j < 0xff)
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        else
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        gameTextShow(showId);
        gameTextRun();
        dvdCheckError();
        doNothing_endOfFrame();
        GXFlush_(0, 0);
    } while (j < 0xf0);
}


AssetReq gGameLoopAssetReq;
