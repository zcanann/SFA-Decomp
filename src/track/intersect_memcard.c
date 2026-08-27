#include "global.h"
#include "dolphin/card.h"
#include "dolphin/mtx.h"
#include "string.h"
#include "track/intersect_card_api.h"
#include "track/intersect_hud_color_api.h"
#include "main/texture.h"
#include "main/dll/player_state.h"
#include "main/sky_interface.h"
#include "main/textrender_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gameloop_api.h"
#include "main/frame_timing.h"
#include "main/trig.h"
#include "main/camera.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/object_render.h"
#include "main/screen_transition.h"
#include "dolphin/gx/GXPixel.h"
#include "main/mm.h"
#include "main/newshadows.h"
#include "main/maketex_api.h"
#include "main/pad.h"
#include "main/pi_dolphin.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXTransform.h"
#include "main/gametext_internal.h"
#include "main/model_engine.h"
#include "main/pi_flush_api.h"
#include "track/intersect_api.h"
#include "dolphin/os.h"

typedef void (*GXSetAlphaCompareIntFn)(int comp0, int ref0, int op, int comp1, int ref1);

typedef struct ReflectionTextureMatrixLayout {
    Mtx modelView;
    Mtx lightPerspective;
    Mtx lightPerspectiveFlipY;
    Mtx lightPerspectiveScaled;
} ReflectionTextureMatrixLayout;

STATIC_ASSERT(offsetof(ReflectionTextureMatrixLayout, lightPerspectiveFlipY) == 0x60);
STATIC_ASSERT(offsetof(ReflectionTextureMatrixLayout, lightPerspectiveScaled) == 0x90);

char sMemoryCardFileNameString[20] = "Star Fox Adventures";




u8* gSaveCardImageBuffer;
u8 gSaveCardFileOpen;
u8 gSaveCardIdentityCheckEnabled;
u8 gSaveCardRetry;
u32 gSaveCardChecksumLo;
u32 gSaveCardChecksumHi;
u32 gSaveCardSerialLo;
u32 gSaveCardSerialHi;
char* gSaveCardIoBuffer;
void* gSaveCardWorkArea;
void loadReflectionTexMtxs(void) {
    u8* base = (u8*)&gCameraModelViewMatrix;
    Mtx tmp;
    PSMTXConcat((void*)(base + offsetof(ReflectionTextureMatrixLayout, lightPerspectiveScaled)), (void*)(int)base, tmp);
    GXLoadTexMtxImm(tmp, GX_TEXMTX0, GX_MTX3x4);
    PSMTXConcat((void*)(base + offsetof(ReflectionTextureMatrixLayout, lightPerspectiveFlipY)), (void*)(int)base, tmp);
    GXLoadTexMtxImm(tmp, GX_TEXMTX2, GX_MTX3x4);
}

/*
 * Retail ships a locally-defined empty OSReport that disables debug
 * output.
 */
void OSReport(const char* msg, ...)
{
}

/*
 * Card init / serial-no validation. Mounts slot 0; if the mount comes back
 * "no card filesystem" (-13) it remembers we need to format. On a check
 * error (-6) it runs CARDCheck; if that also returns -6 it formats. On a
 * clean mount (or after the recovery path) it reads the card serial and
 * compares against the cached pair (gSaveCardSerialHi/Lo). If the cached pair
 * is zero, or doesn't match the live card, the cache is rejected with a
 * "wrong card" error code (-0x55, gSaveCardState = 11). Otherwise CARDFormat
 * if we still owe one, else success: clear the cache, set state 13,
 * unmount, return 1.
 */
int cardFormatMemoryCard(void)
{
    int need_format;
    int res;
    u64 serial;
    int ok;

    need_format = 0;
    if (cardProbe(0) == 0)
    {
        ok = 0;
    }
    else
    {
        gSaveCardWorkArea = mmAlloc(0xA000, -1, 0);
        if (gSaveCardWorkArea == 0)
        {
            gSaveCardState = 8;
            ok = 0;
        }
        else
        {
            ok = 1;
        }
    }
    if (ok == 0)
    {
        return 0;
    }
    gSaveCardState = 0;
    res = CARDMount(0, gSaveCardWorkArea, (void*)cardSetStatusNoCard2);
    if (res == -13)
    {
        need_format = 1;
    }
    if (res == -6)
    {
        res = CARDCheck(0);
        if (res == -6)
        {
            res = CARDFormat(0);
        }
    }
    else if (res == -13 || res == 0)
    {
        res = CARDGetSerialNo(0, &serial);
        if (res == 0)
        {
            u64 cache = *(u64*)&gSaveCardSerialHi;
            if (cache == 0 || cache != serial)
            {
                res = -0x55;
                gSaveCardState = 0xB;
            }
            else if (need_format)
            {
                res = CARDFormat(0);
            }
            else
            {
                CARDUnmount(0);
                mm_free(gSaveCardWorkArea);
                gSaveCardWorkArea = 0;
                gSaveCardState = 0xD;
                return 1;
            }
        }
    }
    CARDUnmount(0);
    mm_free(gSaveCardWorkArea);
    gSaveCardWorkArea = 0;
    switch (res)
    {
    case -2:
        gSaveCardState = 1;
        break;
    case -3:
        if (gSaveCardState != 3)
            gSaveCardState = 2;
        break;
    case -5:
        gSaveCardState = 4;
        break;
    case 0:
        gSaveCardState = 0xD;
        gSaveCardSerialLo = 0;
        gSaveCardSerialHi = 0;
        gSaveCardChecksumLo = 0;
        gSaveCardChecksumHi = 0;
        return 1;
    default:
        break;
    }
    return 0;
}

void cardSetIdentityCheckEnabled(u32 enable)
{
    u8 v = enable;
    gSaveCardIdentityCheckEnabled = v;
    if (v != 0)
    {
        return;
    }
    gSaveCardSerialLo = 0;
    gSaveCardSerialHi = 0;
    gSaveCardChecksumLo = 0;
    gSaveCardChecksumHi = 0;
}

void cardSetStatusNeedInit(void)
{
    gSaveCardState = 0xd;
}

s32 saveGameGetStatus(void)
{
    return gSaveCardState;
}

int cardDeleteSaveFile(void)
{
    int res;
    int ok;

    gSaveCardRetry = 0;

    do
    {
        if (cardProbe(0) == 0)
        {
            ok = 0;
        }
        else
        {
            gSaveCardWorkArea = mmAlloc(0xA000, -1, 0);
            if (gSaveCardWorkArea == 0)
            {
                gSaveCardState = 8;
                ok = 0;
            }
            else
            {
                ok = 1;
            }
        }
        if (ok == 0)
        {
            return 0;
        }
        gSaveCardState = 0;
        res = CARDMount(0, gSaveCardWorkArea, (CARDCallback)cardSetStatusNoCard2);
        if (res == 0 || res == -6)
        {
            res = CARDCheck(0);
        }
        if (res == 0)
        {
            res = CARDDelete(0, sMemoryCardFileName);
        }
        CARDUnmount(0);
        mm_free(gSaveCardWorkArea);
        gSaveCardWorkArea = 0;

        switch (res + 13)
        {
        case 11:
            gSaveCardState = 1;
            break;
        case 10:
            if (gSaveCardState != 3)
                gSaveCardState = 2;
            break;
        case 0:
            gSaveCardState = 6;
            break;
        case 8:
            gSaveCardState = 4;
            break;
        case 13:
            gSaveCardState = 13;
            return 1;
        }
        showMemCardError(0);
    } while (gSaveCardRetry != 0);
    return 0;
}

int _saveGame(int slot, void* save, void* data)
{
    int ret;
    gSaveCardRetry = 0;
    cardShowLoadingMsg(1);
    do
    {
        ret = saveGame_prepareAndWrite(0, slot, 0, save, data, (SaveGameCallback)saveGameWriteSlotCb);
        showMemCardError(0);
        if (gSaveCardRetry != 0)
        {
            cardShowLoadingMsg(1);
        }
    } while (gSaveCardRetry != 0);
    return ret;
}

int maybeTryLoadSave(void* data)
{
    int ret;
    gSaveCardRetry = 0;
    cardShowLoadingMsg(0);
    do
    {
        ret = saveGame_prepareAndWrite(1, 0, 0, data, NULL, (SaveGameCallback)saveGameReadGlobalsCb);
        showMemCardError(1);
        if (gSaveCardRetry != 0)
        {
            cardShowLoadingMsg(0);
        }
    } while (gSaveCardRetry != 0);
    return ret;
}

int loadSaveGame(int slot, void* save)
{
    int ret;
    gSaveCardRetry = 0;
    cardShowLoadingMsg(0);
    do
    {
        ret = saveGame_prepareAndWrite(1, slot, 0, save, NULL, (SaveGameCallback)saveGameReadSlotCb);
        showMemCardError(0);
        if (gSaveCardRetry != 0)
        {
            cardShowLoadingMsg(0);
        }
    } while (gSaveCardRetry != 0);
    return ret;
}

int cardCreateSaveFile(u8 retry)
{
    int ret;

    if (retry != 0)
    {
        gSaveCardRetry = 0;
        cardShowLoadingMsg(2);
    }
    do
    {
        ret = saveGame(0);
        if (ret != 0)
        {
            if (gSaveCardFileOpen != 0)
            {
                gSaveCardFileOpen = 0;
                CARDClose(&gSaveCardFileInfo.fileInfo);
            }
            CARDUnmount(0);
            mm_free(gSaveCardWorkArea);
            gSaveCardWorkArea = 0;
            gSaveCardState = 13;
            if (ret == 2)
            {
                ret = saveGame_prepareAndWrite(0, 0, 0, NULL, NULL, NULL);
            }
        }
        if (retry != 0)
        {
            showMemCardError(0);
        }
        if (gSaveCardRetry != 0)
        {
            cardShowLoadingMsg(2);
        }
    } while (gSaveCardRetry != 0 && retry != 0);
    return ret;
}
int cardProbe(u8 retry)
{

    s32 memSize;
    s32 sectorSize;
    s32 res;

    if (retry != 0)
    {
        gSaveCardRetry = 0;
    }
    do
    {
        res = -1;
        while (res == -1)
        {
            res = CARDProbeEx(0, &memSize, &sectorSize);
        }
        if (res == 0)
        {
            if (sectorSize == 0x2000)
            {
                gSaveCardState = 13;
                return 1;
            }
            gSaveCardState = 7;
        }
        else if (res == -3)
        {
            gSaveCardState = 2;
        }
        else if (res == -2)
        {
            gSaveCardState = 1;
        }
        else
        {
            gSaveCardState = 0;
        }
        if (retry != 0)
        {
            showMemCardError(0);
        }
    } while (gSaveCardRetry != 0 && retry != 0);
    return 0;
}

void _initCardAndDsp(void)
{
    CARDInit();
}

void cardGetMessage(u32* buttons, u32* texts, u32* count)
{
    if (gSaveCardIdentityCheckEnabled != 0 && (gSaveCardState == 7 || gSaveCardState == 9))
    {
        gSaveCardState = 11;
    }
    switch (gSaveCardState)
    {
    case 0:
        *count = 0;
        gSaveCardState = 13;
        return;
    case 1:
        buttons[0] = 1;
        buttons[1] = 2;
        texts[0] = 0x325;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        *count = 2;
        return;
    case 2:
        buttons[0] = 1;
        buttons[1] = 2;
        texts[0] = 0x51A;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        *count = 2;
        return;
    case 3:
        buttons[0] = 1;
        buttons[1] = 2;
        texts[0] = 0x51A;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        *count = 2;
        return;
    case 4:
        buttons[0] = 1;
        buttons[1] = 2;
        texts[0] = 0x329;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        *count = 2;
        return;
    case 5:
        buttons[0] = 1;
        buttons[1] = 2;
        buttons[2] = 0;
        texts[0] = 0x51F;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        texts[3] = 0x326;
        *count = 3;
        return;
    case 6:
        buttons[0] = 1;
        buttons[1] = 2;
        buttons[2] = 0;
        texts[0] = 0x51E;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        texts[3] = 0x326;
        *count = 3;
        return;
    case 7:
        buttons[0] = 1;
        buttons[1] = 2;
        texts[0] = 0x51C;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        *count = 2;
        return;
    case 8:
        *count = 0;
        return;
    case 9:
        buttons[0] = 1;
        buttons[1] = 2;
        buttons[2] = 3;
        texts[0] = 0x32A;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        texts[3] = 0x520;
        *count = 3;
        return;
    case 10:
        buttons[0] = 2;
        buttons[1] = 4;
        texts[0] = 0x497;
        texts[1] = 0x51B;
        texts[2] = 0x522;
        *count = 2;
        return;
    case 11:
    case 12:
        buttons[0] = 1;
        buttons[1] = 2;
        texts[0] = 0x521;
        texts[1] = 0x51D;
        texts[2] = 0x51B;
        *count = 2;
        return;
    case 13:
    default:
        *count = 0;
        gSaveCardState = 13;
        return;
    }
}

void showMemCardError(u8 err)
{
    int opts[8];
    int msgs[8];
    int count;
    u32 saved;
    int sel;
    u8 submenu;
    int timer;
    u8 held;
    int* m;
    int y;
    int i;
    int j;
    int yy;
    GameTextDef* t;
    int v;

    sel = 0;
    submenu = 0;
    timer = 0;
    held = 0;
    gSaveCardRetry = 0;
    if (gSaveCardState == 0xd || (err != 0 && gSaveCardState == 0xc))
    {
        return;
    }
    do
    {
        checkReset();
        padUpdate();
        mmFreeTick(0);
        timer += 0x3e8;
        waitNextFrame();
        saved = gSaveCardBackdropColor;
        hudDrawColored((Texture*)newshadows_getReflectionColorTexture(), 0, 0, &saved, 0x200, 0);
        if (submenu != 0)
        {
            opts[0] = 6;
            opts[1] = 5;
            msgs[0] = 0x327;
            msgs[1] = 0x321;
            msgs[2] = 0x320;
            count = 2;
        }
        else
        {
            cardGetMessage((u32*)opts, (u32*)msgs, (u32*)&count);
        }
        gameTextSetColor(0xff, 0xc0, 0x40, 0xff);
        for (i = 0, m = msgs, y = 0x64; i < count + 1; m++, y += 0x14, i++)
        {
            t = (GameTextDef*)gameTextGet(*m);
            yy = y + ((i > 0) ? 0x64 : 0);
            for (j = 0; j < t->count; j++)
            {
                gameTextShowStr(t->strings[j], 0, 0, yy);
                yy += 0x18;
            }
            if (i == sel)
            {
                v = (int)(47.0f * fcos16HighPrecision(timer) + 208.0f);
                gameTextSetColor(v, v, v, 0xff);
            }
            else
            {
            gameTextSetColor(0xa0, 0xa0, 0xa0, 0xff);
            }
        }
        gameTextRun();
        GXFlush_(1, 0);
        if (padGetStickY(0) < 0 || padGetCY(0) < 0)
        {
            if (held == 0)
            {
                sel++;
                held = 1;
            }
        }
        else if (padGetStickY(0) > 0 || padGetCY(0) > 0)
        {
            if (held == 0)
            {
                sel--;
                held = 1;
            }
        }
        else
        {
            held = 0;
        }
        if (sel < 0)
        {
            sel = 0;
        }
        else if (sel > count - 1)
        {
            sel = count - 1;
        }
        if (getButtonsJustPressed(0) & 0x100)
        {
            switch (opts[sel])
            {
            case 0:
                submenu = 1;
                sel = 0;
                break;
            case 1:
                gSaveCardState = 0xd;
                gSaveCardRetry = 1;
                break;
            case 2:
                gSaveGameEnabled = 0;
                gSaveCardState = 0xd;
                break;
            case 3:
                setGameState(6);
                gSaveGameEnabled = 0;
                gSaveCardState = 0xd;
                break;
            case 4:
                cardDeleteSaveFile();
                cardCreateSaveFile(0);
                if (gSaveCardState == 0xd)
                {
                    gSaveCardRetry = 1;
                }
                break;
            case 5:
                submenu = 0;
                if (cardFormatMemoryCard() != 0)
                {
                    cardCreateSaveFile(0);
                }
                if (gSaveCardState == 0xd)
                {
                    gSaveCardRetry = 1;
                }
                break;
            case 6:
                submenu = 0;
                break;
            default:
                gSaveCardState = 0xd;
            }
        }
    } while (gSaveCardState != 0xd);
}

/*
 * Per-frame "blocking" dialog renderer driven by the card-write retry
 * loops in _saveGame, maybeTryLoadSave, loadSaveGame and cardCreateSaveFile.
 * Pumps 60 frames of the GX/dialog
 * pipeline; on each frame either lets the active controller draw its own
 * popup (gScreenTransitionInterface[0]->vtbl[1]) or falls back to hudDrawColored
 * tinting the reflection texture with gSaveCardBackdropColor, then routes the OK/Cancel/back text
 * to gameTextShowAt based on the dialog kind passed in.
 */
void cardShowLoadingMsg(u8 kind)
{
    GameObject** buttons;
    u32 saved;
    int frame;
    int j;
    int count;
    f32 rectAlpha;
    void (*draw)(int, int, int);
    u8 mode = kind;

    gameTextSetWindow(0);
    for (frame = 0; frame < 0x3C; frame++)
    {
        padUpdate();
        mmFreeTick(0);
        waitNextFrame();
        count = getButtonObjects(&buttons) & 0xFF;
        if ((u32)count != 0)
        {
            draw = (*gScreenTransitionInterface)->init;
            draw(0, 0, 0);
            rectAlpha = 0.0f;
            drawRect(rectAlpha, rectAlpha, 0x280, 0x1E0);
            for (j = 0; j < count; j++)
            {
                objRenderModelAndHitVolumes(buttons[j], 0, 0, 0, 0, 1.0f);
            }
            curUiDllDraw(0, 0, 0, 0);
        }
        else
        {
            saved = gSaveCardBackdropColor;
            hudDrawColored((Texture*)newshadows_getReflectionColorTexture(), 0, 0, &saved, 0x200, 0);
        }
    gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
        if (mode == 1)
        {
            gameTextShowAt(0x323, 0, 0xC8);
        }
        else if (mode == 2)
        {
            gameTextShowAt(0x573, 0, 0xC8);
        }
        else
        {
            gameTextShowAt(0x56C, 0, 0xC8);
        }
        gameTextRun();
        GXFlush_(1, 0);
    }
}

/*
 * Card-write callback dispatched through saveGame_prepareAndWrite from _saveGame.
 * Stages a per-slot 0x6EC-byte block plus the shared 0xE4-byte trailer
 * into the card-IO buffer (gSaveCardIoBuffer), then asks saveGame_doWrite(2) to
 * commit; if that fails it falls back to saveGame_doWrite(1).
 */
int saveGameWriteSlotCb(u8 slot, int unused, void* src1, void* src2)
{
    int ret;
    memcpy(gSaveCardIoBuffer + slot * 0x6EC + 0xA50, src1, 0x6EC);
    memcpy(gSaveCardIoBuffer + 0x1F14, src2, 0xE4);
    ret = saveGame_doWrite(2);
    if (ret == 0)
    {
        ret = saveGame_doWrite(1);
    }
    return ret;
}

/*
 * Card-write callback dispatched through saveGame_prepareAndWrite from maybeTryLoadSave.
 * Copies the 0xE4-byte block at offset 0x1F14 in the card buffer (held in
 * gSaveCardIoBuffer) into the caller-supplied destination.
 */
int saveGameReadGlobalsCb(int saveId, int size, void* dst)
{
    memcpy(dst, gSaveCardIoBuffer + 0x1F14, 0xE4);
    return 0;
}


/* .bss block 0x80391DC0-0x803967C0 */
