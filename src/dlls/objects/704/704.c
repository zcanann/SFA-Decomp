/*
 * DLL 704 (0x2C0) - the title/attract-mode front-end object and its
 * UI. gTitleScreenObjDescriptor drives the title-screen actor: init
 * seeds anim moves per romDefNo (0x77d..0x780 = the four pilots on the Great
 * Fox bridge - retail OBJECTS.bin names FrontFox/FrontPeppy/FrontSlippy/
 * FrontRob; 0x781/0x78a are both retail-named FrontPilots: the group
 * actor and the attract camera/movie), update runs the actor
 * anim state machine plus the per-actor footstep/voice sfx grid at
 * gTitleScreenSfxFlagGrid and the random blink blend, release/initialise manage the
 * 19-slot texture table at gTitleScreenTextures.
 *
 * Standalone leaf entry points cover the credits roll (creditsStart /
 * creditsStart_, walking gCreditEntries with fade-in/out), the
 * copyright/title text layout (titleScreenDrawMenuFrame,
 * titleScreenShowCopyright, titleScreenPositionElements), and the GX
 * quad emitters for the title and name-entry text (titleScreenTextDrawFunc
 * / nameEntryTextDrawFunc, writing through GXWGFifo). showCredits gates
 * the credits sequence; getCurUiDll selects the active front-end UI DLL.
 */
#include "main/dll/FRONT/n_options.h"
#include "main/texture.h"
#include "main/frame_timing.h"
#include "main/gametext_box_api.h"
#include "main/textrender_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/music_api.h"
#include "main/object_render.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "main/render_envfx_api.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/gx_scissor_api.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/objprint_character_api.h"
#include "sys/objects.h"
#include "dlls/object_descriptor.h"
#include "main/model.h"
#include "main/dll/dll_003C_link_api.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/objseq.h"
#include "main/dll/FRONT/dll_0034_n_attractmode.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "main/dll/dll_0057_cameramodetitle.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXEnum.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx.h"
#include "main/gametext_color_api.h"
#include "track/intersect_hud_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/gamebits_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/dll/dll_02C0_front.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/dll/front_game_text_box_api.h"

s8 gTitleScreenPrevMenuSelection = -1;
s8 gTitleScreenPrevMenuActive = -1;
u16 gTitleScreenCreditCount = 0x35;
f32 gTitleScreenFoxTypeMoveRate = 0.01f;

#define TITLE_SCREEN_TEXTURE_COUNT 19

/* Env-fx id activated on title-screen setup (getEnvfxAct 3rd arg) */
#define FRONT_ENVFX_TITLE 0x21f

/* title-screen actor seqIds (retail OBJECTS.bin names, all DLL 0x2C0) */
#define FRONT_SEQID_FOX            0x77d /* "FrontFox" */
#define FRONT_SEQID_PEPPY          0x77e /* "FrontPeppy" */
#define FRONT_SEQID_SLIPPY         0x77f /* "FrontSlippy" */
#define FRONT_SEQID_ROB            0x780 /* "FrontRob" */
#define FRONT_SEQID_PILOTS         0x781 /* "FrontPilots" */
#define FRONT_SEQID_PILOTS_ATTRACT 0x78a /* "FrontPilots" */

typedef struct TitlescreenState
{
    s16 unk0;
    s16 unk2;
    s16 unk4;
    u8 pad6[0x18 - 0x6];
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    u8 pad24[0x30 - 0x24];
    u8 animPhase; /* 0x30: anim state-machine phase (0-5); also the move index passed to ObjAnim_SetCurrentMove */
    s8 poseIndex; /* 0x31: per-actor pose index (romDefNo - FRONT_SEQID_FOX), or -2 for non-pilot actors */
    u8 pad32[0x34 - 0x32];
    f32 moveProgress;
} TitlescreenState;

typedef struct TitlescreenPlacement
{
    ObjPlacement base;
    s8 spawnRot;
} TitlescreenPlacement;

STATIC_ASSERT(offsetof(TitlescreenPlacement, spawnRot) == 0x18);

void* gTitleScreenMainTex;
f32 lbl_803DD9D0;
f32 lbl_803DD9CC;
f32 gTitleScreenCursorY;
f32 gTitleScreenPulseTimer;
u8 gTitleScreenPulseAlpha;
u32 gNameEntryScrollX;
u32 gNameEntryScrollY;
f32 gTitleScreenSlideProgressX;
f32 gTitleScreenCursorX;
int gTitleScreenCopyrightBaseY;
u8 gTitleScreenActorsEnabled;
u8 gTitleScreenCreditsStarted;
s16 gTitleScreenCreditDelay;
int gTitleScreenCreditsEndTriggered;
u8 gTitleScreenCopyrightLatch;
f32 gTitleScreenCopyrightFade;
u16 gTitleScreenCreditIndex;
u16 gTitleScreenCreditTimer;
u16 gTitleScreenCreditsElapsed;
u8 showCredits;
u8 gTitleScreenSetupDone;
s8 gTitleScreenMenuActive;
s8 gTitleScreenMenuSelection;
#define FRONT_TEXT_COPYRIGHT 0x3d9
typedef struct TitleAnimMoves
{
    f32 moves[8];
} TitleAnimMoves;
volatile PPCWGPipe GXWGFifo : (0xCC008000);
extern u8 gTitleScreenSfxFlagGrid[0x48];
extern u8 gTitleScreenMtx[0x34];
extern TitleAnimMoves gTitleScreenAnimMoves[];

void titleScreenPlayActorSfx(GameObject* obj, u8* arr)
{
    s8* sarr = (s8*)arr;
    int i;
    for (i = 0; i < sarr[0x1b]; i++)
    {
        s8 t;
        switch (obj->anim.romDefNo)
        {
        case FRONT_SEQID_FOX:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_fox_keytap);
            }
            break;
        case FRONT_SEQID_PEPPY:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_pep_snoreout);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_pep_snorein);
            }
            break;
        case FRONT_SEQID_SLIPPY:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_kickbox);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_fingersnap);
            }
            break;
        case FRONT_SEQID_ROB:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_servo2);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_servo1);
            }
            break;
        }
    }
}

typedef struct
{
    u16 textId;
    u16 duration;
} CreditEntry;
extern CreditEntry gCreditEntries[];

void creditsStart_(void)
{
    int alpha;
    if (gTitleScreenCreditIndex >= gTitleScreenCreditCount)
    {
        if ((*gCameraInterface)->getMode() == CAMERA_MODE_TITLE_RESOURCE_ID)
        {
            showCredits = 0;
            loadUiDll(4);
            TitleMenu_setSelection(4);
        }
        return;
    }
    if (gTitleScreenCreditDelay > 0)
    {
        gTitleScreenCreditDelay -= framesThisStepUnclamped;
        if (gTitleScreenCreditDelay < 0)
        {
            gTitleScreenCreditDelay = 0;
        }
        return;
    }
    if (gTitleScreenCreditTimer < 0x14)
    {
        alpha = gTitleScreenCreditTimer * 0xff / 0x14 & 0xff;
    }
    else if (gTitleScreenCreditTimer >= gCreditEntries[gTitleScreenCreditIndex].duration - 0x14)
    {
        if (gTitleScreenCreditIndex == gTitleScreenCreditCount - 1 && gTitleScreenCreditsEndTriggered == 0)
        {
            Music_StopChannelsByPriorityGroup(3, MUSIC_CHANNEL_STOP_FADE, 0xfa0);
            gTitleScreenCreditsEndTriggered = 1;
        }
        alpha =
            0xff - (gTitleScreenCreditTimer - gCreditEntries[gTitleScreenCreditIndex].duration) * 0xff / 0x14 & 0xff;
    }
    else
    {
        alpha = 0xff;
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    gameTextShowAt(gCreditEntries[gTitleScreenCreditIndex].textId, 0, 0);
    gTitleScreenCreditsElapsed += framesThisStepUnclamped;
    gTitleScreenCreditTimer += framesThisStepUnclamped;
    if (gTitleScreenCreditTimer < gCreditEntries[gTitleScreenCreditIndex].duration)
    {
        return;
    }
    gTitleScreenCreditIndex++;
    gTitleScreenCreditDelay = 0x3c;
    if (gTitleScreenCreditIndex < gTitleScreenCreditCount)
    {
        gTitleScreenCreditTimer = 0;
    }
}

u8 shouldShowCredits(void)
{
    return showCredits;
}


/* Reset the per-frame state group: latch showCredits = 1 and zero five
 * halfword/byte counters. */
void creditsStart(void)
{
    showCredits = 1;
    gTitleScreenCreditsElapsed = 0;
    gTitleScreenCreditTimer = 0;
    gTitleScreenCreditDelay = 0;
    gTitleScreenCreditIndex = 0;
    gTitleScreenCreditsStarted = 0;
}

/* Predicate. Returns 1 when the value from getCurUiDll is in {2..6} or
 * equals 7, else 0. */
int isFrontEndUiActive(void)
{
    int x = getCurUiDll();
    if ((u32)(x - 2) <= 4 || x == 7)
    {
        return 1;
    }
    return 0;
}
void titleScreenShowCopyright(u8 arg)
{
    void* tb;
    TextSlot* box;

    if (arg != 0)
    {
        gTitleScreenCopyrightFade = 1.0f;
        gTitleScreenCopyrightLatch = 0;
    }
    else if (gTitleScreenCopyrightLatch != 0)
    {
        gTitleScreenCopyrightFade = gTitleScreenSlideProgressX;
    }
    else
    {
        gTitleScreenCopyrightFade = 1.0f;
        if (gTitleScreenSlideProgressX > 0.9999f)
        {
            gTitleScreenCopyrightLatch = 1;
        }
    }
    tb = gameTextGet(FRONT_TEXT_COPYRIGHT);
    if (*(u16*)tb != 0xffff)
    {
        box = gameTextGetBox(*(u8*)((char*)tb + 4));
        if (gTitleScreenCopyrightBaseY == 0)
        {
            gTitleScreenCopyrightBaseY = box->y;
        }
        box->y =
            (s16)(80.0f * (1.0f - gTitleScreenCopyrightFade) + gTitleScreenCopyrightBaseY);
        gameTextSetColor(0xff, 0xff, 0xff, (s32)(255.0f * gTitleScreenCursorX));
        gameTextShow(FRONT_TEXT_COPYRIGHT);
    }
}

extern void* gTitleScreenTextures[TITLE_SCREEN_TEXTURE_COUNT];

void titleScreenDrawMenuFrame(int alpha, int hideHighlight, u32 showArrows)
{
    int i;
    Texture* tex;
    int xb;
    f32* mtx;
    Texture** texs;
    Texture** texs2;
    f32 m;
    f32 sc3;
    u16 boxIndex;
    int idx;
    int yb;
    int r;

    m = (gTitleScreenPulseTimer = gTitleScreenPulseTimer + timeDelta);
    if (m > 100.0f)
    {
        gTitleScreenPulseTimer = m - 100.0f;
    }
    gTitleScreenPulseAlpha =
        127.0f * mathCosf(3.142f * (2.0f * gTitleScreenPulseTimer) / 100.0f) + 128.0f;
    if (gTitleScreenCursorY > 0.0f)
    {
        f32 (*m2)[4] = (f32 (*)[4])gTitleScreenMtx;
        Texture* tex;
        int xb;
        int yb;
        int y;
        xb = (int)m2[0][3] - 0x32;
        yb = (int)m2[1][3];
        texs = (Texture**)gTitleScreenTextures;
        tex = texs[4];
        drawScaledTexture(tex, (f32)(int)(xb + 0x5a + (texs2 = (Texture**)gTitleScreenTextures)[6]->width),
                          (f32)(y = yb - 0x10), alpha, 0x100, tex->width,
                          (u32)(268.0f * gTitleScreenCursorY) + 0x10, 0);
        tex = texs2[6];
        drawScaledTexture(tex, (f32)(int)(xb + 0x5a), (f32)(y = yb - 0x10), 0xff, 0x100, tex->width,
                          (u32)(268.0f * gTitleScreenCursorY) + 0x10, 0);
        tex = texs2[6];
        drawScaledTexture(tex, (f32)(int)(xb + 0x57 + texs[4]->width + tex->width), (f32)(y = yb - 0x10), 0xff, 0x100,
                          tex->width, (u32)(268.0f * gTitleScreenCursorY) + 0x10, 1);
        tex = (Texture*)gTitleScreenTextures[0];
        drawScaledTexture(tex, (f32)(int)(xb + 0x23), (f32)(y = yb - 0x10), 0xff, 0x100, tex->width,
                          (u32)(268.0f * gTitleScreenCursorY) + 0x10, 0);
    }
    mtx = (f32*)gTitleScreenMtx;
    {
        int xb = (int)mtx[3];
        int yb = (int)mtx[7];
        int a = (gTitleScreenCursorY > 0.0f) ? 0xff : gTitleScreenPulseAlpha;
        drawTexture(gTitleScreenTextures[1], (f32)(int)(xb - 0x18),
                    (f32)(int)(yb - ((Texture*)gTitleScreenTextures[1])->height + 3), 0xff, 0xff);
        texs2 = (Texture**)gTitleScreenTextures;
        drawTexture(texs2[7], (f32)(int)(xb + 0xa1), (f32)(int)(yb - 0x2e), a, 0xff);
    }
    {
        int xb = (int)mtx[3];
        int yb = (int)mtx[7];
        f32 cy = gTitleScreenCursorY;
        int a = (cy > 0.0f) ? 0xff : gTitleScreenPulseAlpha;
        drawTexture(gTitleScreenTextures[2], (f32)(int)(xb - 0x18), -6.0f + (268.0f * cy + (f32)yb),
                    0xff, 0xff);
        drawTexture(texs2[7], (f32)(int)(xb + 0xa1), 16.0f + (268.0f * gTitleScreenCursorY + (f32)yb),
                    a, 0xff);
    }
    gameTextSetColor(0xff, 0xff, 0xff, (int)((f64)gTitleScreenPulseAlpha * (1.0 - gTitleScreenCursorY)));
    gameTextShow(0x3da);
    drawTexture(gTitleScreenTextures[3], (f32)(int)((int)mtx[3] - 0x32),
                (f32)(int)(0xfe - ((u32)((Texture*)gTitleScreenTextures[3])->width >> 1)), 0xff, 0xff);
    if (gTitleScreenCursorY >= 0.99f && (hideHighlight & 0xff) == 0u)
    {
        int xb = (int)mtx[3] - 0x32;
        int yb = (int)mtx[7];
        i = 0;
        texs = (Texture**)gTitleScreenTextures;
        sc3 = 268.0f;
        do
        {
            tex = texs[4];
            drawScaledTexture(tex, (f32)(int)(xb + 0x5a + texs[6]->width - (i + 1) * 4),
                              (f32)(int)(yb - 0x10 - (i + 1) * 3), (int)(u32)gTitleScreenPulseAlpha >> (i + 3) & 0xff, 0x100,
                              tex->width + (i + 1) * 8, (u32)(sc3 * gTitleScreenCursorY) + ((i + 1) * 6 + 0x10), 4);
            i++;
        } while (i < 4);
    }
    if (gTitleScreenCursorY > 0.0f && (boxIndex = linkGetSelectedItemId()) != 0xFFFF)
    {
        int t = ((TextSlot*)gameTextGetBox(boxIndex))->y;
        xb = (int)mtx[3];
        yb = t + (int)mtx[7];
        if ((hideHighlight & 0xff) == 0u)
        {
            drawTexture(gTitleScreenTextures[5], (f32)(int)(xb + 0x2f), (f32)(int)(yb - 1), alpha, 0xff);
        }
    }
    idx = (u8)((int)((u32)gTitleScreenPulseAlpha << 3) / 0x100);
    texs = (Texture**)gTitleScreenTextures;
    {
        Texture* t = texs[18];
        drawScaledTexture(t, (f32)(int)((int)(100.0f * gTitleScreenCursorX) - 0x50),
                          (f32)(int)((int)(-80.0f * gTitleScreenSlideProgressX) + 0x1e0), 0xff, 0x100, t->width, t->height, 1);
    }
    texs2 = &((Texture**)(gTitleScreenTextures + 8))[idx];
    {
        Texture* t = *texs2;
        drawScaledTexture(t, (f32)(int)((int)(100.0f * gTitleScreenCursorX) + ((tex = texs[18])->width - 0x4a)),
                          (f32)(int)((int)(-80.0f * gTitleScreenSlideProgressX) + 0x1e0), 0xff, 0x100, t->width, t->height, 0);
    }
    {
        Texture* t = texs[18];
        drawScaledTexture(t,
                          (f32)(int)(0x280 - ((int)(100.0f * gTitleScreenCursorX) - 0x50) - texs[18]->width),
                          (f32)(int)((int)(-80.0f * gTitleScreenSlideProgressX) + 0x1e0), 0xff, 0x100, t->width, t->height, 0);
    }
    {
        Texture* t = *texs2;
        drawScaledTexture(
            t,
            (f32)(int)(0x27a - ((int)(100.0f * gTitleScreenCursorX) - 0x50) - texs[18]->width - t->width),
            (f32)(int)((int)(-80.0f * gTitleScreenSlideProgressX) + 0x1e0), 0xff, 0x100, t->width, t->height, 1);
    }
    m = gTitleScreenSlideProgressX;
    if (gTitleScreenSlideProgressX > gTitleScreenCursorX)
    {
        m = gTitleScreenCursorX;
    }
    drawTexture(gTitleScreenMainTex,
                (f32)(int)((0x280 - (((int)((Texture*)gTitleScreenMainTex)->width * 0xbe) / 0x100)) / 2),
                (f32)(int)(250.0f * m + -200.0f), 0xff, 0xbe);
    if ((showArrows & 0xff) != 0u)
    {
        int yb;
        int xb;
        xb = (int)mtx[3];
        yb = (int)mtx[7];
        drawTexture(gTitleScreenTextures[17], (f32)(r = xb + 0x2f), (f32)(int)(yb + 0x14), 0xff, 0xff);
        drawTexture(gTitleScreenTextures[16], (f32)(r = xb + 0x2f), (f32)(int)(yb + 0x4b), 0xff, 0xff);
    }
}

/* Sets the name-entry text scroll offsets (x is applied in 4-px steps). */
void nameEntrySetScroll(u32 a, u32 b)
{
    gNameEntryScrollX = a;
    gNameEntryScrollY = b;
}
void titleScreenPositionElements(f32 a, f32 b)
{
    PSMTXTrans((MtxPtr)gTitleScreenMtx, a, b, 0.0f);
    gTitleScreenCursorY = (254.0f - b) / 134.0f;
    gTitleScreenSlideProgressX = (a - -380.0f) / 420.0f;
    gTitleScreenCursorX = 1.0f - gTitleScreenCursorY;
}


void nameEntryTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((MtxPtr)gTitleScreenMtx, GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetScissor((int)((u32) ((MtxPtr)gTitleScreenMtx)[0][3] + 0x39),
                 (int)((u32) ((MtxPtr)gTitleScreenMtx)[1][3] + 0x4e), 0x104, 0x16);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    GXWGFifo.s16 = (s16)(x0 - *(u32*)&gNameEntryScrollX * 4 + 0x208);
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - *(u32*)&gNameEntryScrollX * 4 + 0x208);
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - *(u32*)&gNameEntryScrollX * 4 + 0x208);
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)(x0 - *(u32*)&gNameEntryScrollX * 4 + 0x208);
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
    GXSetScissor(0, 0, 0x280, 0x1e0);
    Camera_RebuildProjectionMatrix();
}


/* Set up the title-screen translation matrix at gTitleScreenMtx and derive
 * the three normalized cursor positions from the supplied (a, b) coordinates. */

void titleScreenTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((MtxPtr)gTitleScreenMtx, GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    GXWGFifo.s16 = x0;
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = x0;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
    Camera_RebuildProjectionMatrix();
}

int TitleScreen_getExtraSize(void)
{
    return 56;
}

/* Returns 74 if romDefNo is in [1917, 1920], else returns 0. */
int TitleScreen_getObjectTypeId(GameObject* obj)
{
    s16 v = obj->anim.romDefNo;
    if (v >= 1917 && v < 1921)
        return 74;
    return 0;
}

/* If romDefNo == FRONT_SEQID_FOX, trigger Music_Trigger(MUSICTRIG_lose_ice_race, 0)
 * and clear showCredits. */

void TitleScreen_free(GameObject* obj)
{
    if (obj->anim.romDefNo == FRONT_SEQID_FOX)
    {
        Music_Trigger(MUSICTRIG_lose_ice_race, 0);
        showCredits = 0;
    }
}


/* When visible and ready, render via objRenderFn; once the credits flag
 * fires, set the one-shot trigger 0x57 and release the attract-mode movie
 * buffers. */
void TitleScreen_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v == 0)
        return;
    if (gTitleScreenActorsEnabled == 0)
        return;
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    if (showCredits == 0)
        return;
    if (gTitleScreenCreditsStarted != 0)
        return;
    mainSetBits(GAMEBIT_CreditsRelated0DF6, 1);
    gTitleScreenCreditsStarted = 1;
    (*gObjectTriggerInterface)->setCamVars(CAMERA_MODE_TITLE_RESOURCE_ID, 0, 0, 0);
    n_attractmode_releaseMovieBuffers();
    gTitleScreenCreditsEndTriggered = 0;
}

void TitleScreen_hitDetect(void)
{
}


/* Drive the copyright/title text fade and push text box 0x3d9. */

/* Drive the title screen actor anim state machine, the per-actor
 * footstep/voice sfx flag grid at gTitleScreenSfxFlagGrid, the random blink
 * blend, and the one-shot envfx/sky setup. */
void TitleScreen_update(GameObject* obj)
{
    TitlescreenState* state = (TitlescreenState*)obj->extra;
    GameObject* objHandle = obj;
    u8* p;
    u8 phase;
    int evt;
    f32 progress;
    ObjModel* model;
    ObjModelBlendChannel* blend;
    int morphTarget;
    int phaseSel;
    u8* row;
    s16 t;
    u8 buf[0x1c];

    if (gTitleScreenActorsEnabled != 0)
    {
        if (state->poseIndex != gTitleScreenMenuSelection && gTitleScreenMenuActive == 0 &&
            (phase = state->animPhase) != 0 && phase != 4 && phase != 3)
        {
            if (obj->anim.romDefNo == FRONT_SEQID_FOX || obj->anim.romDefNo == FRONT_SEQID_ROB)
            {
                state->animPhase = 3;
                ObjAnim_SetCurrentMove(objHandle, 1, 1.0f, 0);
                state->moveProgress =
                    gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[3];
            }
            else
            {
                state->animPhase = 0;
                ObjAnim_SetCurrentMove(objHandle, 0, 0.0f, 0);
                state->moveProgress =
                    gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[0];
            }
        }
        if (state->poseIndex == gTitleScreenMenuSelection && gTitleScreenMenuActive != 0 &&
            (phase = state->animPhase) != 1 && phase != 2 && phase != 5)
        {
            state->animPhase = 1;
            ObjAnim_SetCurrentMove(objHandle, 1, 0.0f, 0);
            state->moveProgress =
                gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[1];
            if (obj->anim.romDefNo == FRONT_SEQID_PEPPY)
            {
                Sfx_StopFromObject(obj, SFXTRIG_fend_pep_snoreout);
                Sfx_StopFromObject(obj, SFXTRIG_fend_pep_snorein);
                Sfx_PlayFromObject(obj, SFXTRIG_fend_pep_wakeup);
            }
        }
        t = obj->anim.romDefNo;
        if (t == 0x7a7)
        {
            obj->anim.rotX = 10.0f * timeDelta + (f32)obj->anim.rotX;
        }
        else if (t != FRONT_SEQID_PILOTS_ATTRACT)
        {
            buf[0x1b] = 0;
            if (t == FRONT_SEQID_FOX && state->animPhase == 2)
            {
                if (obj->anim.currentMoveProgress < 0.1f)
                {
                    gTitleScreenFoxTypeMoveRate = progress = 0.0001f * (f32)randomGetRange(0x32, 0x96);
                }
                else
                {
                    progress = gTitleScreenFoxTypeMoveRate;
                }
            }
            else
            {
                progress = state->moveProgress;
            }
            evt = ObjAnim_AdvanceCurrentMove(objHandle, progress, timeDelta, (ObjAnimEventList*)buf);
            if (evt != 0)
            {
                if (state->poseIndex == gTitleScreenMenuSelection && state->animPhase == 1)
                {
                    state->animPhase = 2;
                    ObjAnim_SetCurrentMove(objHandle, 2, 0.0f, 0);
                    state->moveProgress =
                        gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[2];
                }
                else if (state->animPhase == 3)
                {
                    state->animPhase = 0;
                    ObjAnim_SetCurrentMove(objHandle, 0, 0.0f, 0);
                    state->moveProgress =
                        gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[0];
                }
                else if (obj->anim.romDefNo >= FRONT_SEQID_FOX && obj->anim.romDefNo < FRONT_SEQID_PILOTS)
                {
                    if (randomGetRange(0, 4) == 0)
                    {
                        if ((phase = state->animPhase) == 0 || phase == 4)
                        {
                            state->animPhase = 4;
                            ObjAnim_SetCurrentMove(objHandle, randomGetRange(3, 4), 0.0f, 0);
                            state->moveProgress =
                                gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX]
                                    .moves[1 + obj->anim.currentMove];
                        }
                        else
                        {
                            state->animPhase = 5;
                            ObjAnim_SetCurrentMove(objHandle, randomGetRange(5, 6), 0.0f, 0);
                            state->moveProgress =
                                gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX]
                                    .moves[1 + obj->anim.currentMove];
                        }
                    }
                    else
                    {
                        phase = state->animPhase;
                        if (phase == 4)
                        {
                            state->animPhase = 0;
                            ObjAnim_SetCurrentMove(objHandle, 0, 0.0f, 0);
                            state->moveProgress =
                                gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[0];
                        }
                        else if (phase == 5)
                        {
                            state->animPhase = 2;
                            ObjAnim_SetCurrentMove(objHandle, 2, 0.0f, 0);
                            state->moveProgress =
                                gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[2];
                        }
                    }
                }
            }
            titleScreenPlayActorSfx(obj, buf);
        }
        t = obj->anim.romDefNo;
        if (t == FRONT_SEQID_PEPPY && ((phase = state->animPhase) == 0 || phase == 4))
        {
            characterCloseEyes(obj, state);
        }
        else if (t >= FRONT_SEQID_FOX && t < FRONT_SEQID_PILOTS)
        {
            characterDoEyeAnims(obj, state);
        }
        model = Obj_GetActiveModel(obj);
        if (model->file->morphTargetCount != 0 && ObjModel_HasActiveBlendChannels(model) == 0 &&
            randomGetRange(0xf0, 0x168) == 0xf0)
        {
            blend = model->blendChannels;
            morphTarget = randomGetRange(0, model->file->morphTargetCount);
            ObjModel_SetBlendChannelTargets(model, 0, blend->morphTargetB, morphTarget - 1, 0.025f, 0);
        }
        gTitleScreenPrevMenuSelection = -1;
        gTitleScreenPrevMenuActive = -1;
        phaseSel = state->animPhase;
        t = obj->anim.romDefNo;
        switch (t)
        {
        case FRONT_SEQID_FOX:
            break;
        case FRONT_SEQID_PEPPY:
            switch (phaseSel)
            {
            case 5:
                row = gTitleScreenSfxFlagGrid + (t - FRONT_SEQID_FOX) * 0x12;
                if (row[phaseSel * 3] != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.4f)
                        row[phaseSel * 3] = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.4f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fened_pep_yawn);
                    row[phaseSel * 3] = 1;
                }
                break;
            }
            break;
        case FRONT_SEQID_SLIPPY:
            switch (phaseSel)
            {
            case 4:
            case 5:
                if (obj->anim.currentMove == 3 || obj->anim.currentMove == 5)
                {
                    row = gTitleScreenSfxFlagGrid + (t - FRONT_SEQID_FOX) * 0x12;
                    if (row[phaseSel * 3] != 0)
                    {
                        if (obj->anim.currentMoveProgress < 0.3f)
                            row[phaseSel * 3] = 0;
                    }
                    else if (obj->anim.currentMoveProgress > 0.3f)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_fingersnap);
                        row[phaseSel * 3] = 1;
                    }
                    p = gTitleScreenSfxFlagGrid + (obj->anim.romDefNo - FRONT_SEQID_FOX) * 0x12 + phaseSel * 3 + 1;
                    if (*p != 0)
                    {
                        if (obj->anim.currentMoveProgress < 0.65f)
                            *p = 0;
                    }
                    else if (obj->anim.currentMoveProgress > 0.65f)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_fingersnap);
                        *p = 1;
                    }
                }
                break;
            }
            break;
        case FRONT_SEQID_ROB:
            switch (phaseSel)
            {
            case 4:
                row = gTitleScreenSfxFlagGrid + (t - FRONT_SEQID_FOX) * 0x12;
                if (row[phaseSel * 3] != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.5f)
                        row[phaseSel * 3] = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.5f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_wave);
                    row[phaseSel * 3] = 1;
                }
                break;
            case 5:
                row = gTitleScreenSfxFlagGrid + (t - FRONT_SEQID_FOX) * 0x12;
                if (row[phaseSel * 3] != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.25f)
                        row[phaseSel * 3] = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.25f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_armout);
                    row[phaseSel * 3] = 1;
                }
                p = gTitleScreenSfxFlagGrid + (obj->anim.romDefNo - FRONT_SEQID_FOX) * 0x12 + phaseSel * 3 + 1;
                if (*p != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.7f)
                        *p = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.7f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    *p = 1;
                }
                p = gTitleScreenSfxFlagGrid + (obj->anim.romDefNo - FRONT_SEQID_FOX) * 0x12 + phaseSel * 3 + 2;
                if (*p != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.8f)
                        *p = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.8f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_armin);
                    *p = 1;
                }
                break;
            case 2:
                row = gTitleScreenSfxFlagGrid + (t - FRONT_SEQID_FOX) * 0x12;
                if (row[phaseSel * 3] != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.3f)
                        row[phaseSel * 3] = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.3f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    row[phaseSel * 3] = 1;
                }
                p = gTitleScreenSfxFlagGrid + (obj->anim.romDefNo - FRONT_SEQID_FOX) * 0x12 + phaseSel * 3 + 1;
                if (*p != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.6f)
                        *p = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.6f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    *p = 1;
                }
                p = gTitleScreenSfxFlagGrid + (obj->anim.romDefNo - FRONT_SEQID_FOX) * 0x12 + phaseSel * 3 + 2;
                if (*p != 0)
                {
                    if (obj->anim.currentMoveProgress < 0.9f)
                        *p = 0;
                }
                else if (obj->anim.currentMoveProgress > 0.9f)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    *p = 1;
                }
                break;
            }
            break;
        }
        if (gTitleScreenSetupDone == 0)
        {
            getEnvfxAct(0, 0, FRONT_ENVFX_TITLE, 0);
            skySetLightsEnabled(7, 1, 0);
            skySetBaseColor(7, 0x4b, 0x64, 0x78, 0, 0);
            skySetLightDirection(7, 1.0f, -1.0f, -1.0f);
            (*gCameraInterface)->setFocus(obj, 0);
            gTitleScreenSetupDone = 1;
            TitleMenuItem_loadTextures();
        }
    }
}


/* Seed the object's state from its romDefNo, pick the anim move and blend
 * float per id range, and for the attract id install the movie draw
 * callback. */
void TitleScreen_init(GameObject* obj, u8* def)
{
    TitlescreenState* state = (TitlescreenState*)obj->extra;
    s16 romDefNo;
    state->animPhase = 0;
    obj->anim.rotX = (s16)(((TitlescreenPlacement*)def)->spawnRot << 8);
    romDefNo = obj->anim.romDefNo;
    if (romDefNo >= FRONT_SEQID_FOX && romDefNo < FRONT_SEQID_PILOTS)
    {
        state->poseIndex = (s8)(romDefNo - FRONT_SEQID_FOX);
        state->moveProgress = gTitleScreenAnimMoves[obj->anim.romDefNo - FRONT_SEQID_FOX].moves[0];
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
    }
    else
    {
        f32 blendFloat = 0.0f;
        state->moveProgress = blendFloat;
        state->poseIndex = -2;
        romDefNo = obj->anim.romDefNo;
        if (romDefNo == FRONT_SEQID_PILOTS_ATTRACT)
        {
            ObjAnim_SetCurrentMove(obj, 1, blendFloat, 0);
        }
        else if (romDefNo == FRONT_SEQID_PILOTS)
        {
            ObjAnim_SetCurrentMove(obj, 0, 1.0f, 0);
            ObjModel_SetRenderCallback((u8*)obj->anim.banks[0], AttractMovie_DrawTextureCallback);
        }
    }
}

/* Two-byte state push: if arg differs from gTitleScreenMenuActive, save old to
 * gTitleScreenPrevMenuActive and set new. */
void titleScreenSetMenuActive(s8 arg)
{
    s8 cur;
    if (arg == (cur = gTitleScreenMenuActive))
        return;
    gTitleScreenPrevMenuActive = cur;
    gTitleScreenMenuActive = arg;
}

/* Two-byte state push (no equality check): copy gTitleScreenMenuSelection to
 * gTitleScreenPrevMenuSelection and write new value. */
void titleScreenSetMenuSelection(s8 arg)
{
    gTitleScreenPrevMenuSelection = gTitleScreenMenuSelection;
    gTitleScreenMenuSelection = arg;
}

void titleScreenDisableActors(void)
{
    gTitleScreenActorsEnabled = 0;
}


/* Free the main buffer at gTitleScreenMainTex and walk the 19-slot table at
 * gTitleScreenTextures releasing each non-null entry, then clear the busy
 * byte at gTitleScreenSetupDone. */
void TitleScreen_release(void)
{
    int i;
    textureFree((Texture*)(gTitleScreenMainTex));
    gTitleScreenMainTex = NULL;
    i = 0;
    do
    {
        if (gTitleScreenTextures[i] != NULL)
        {
            textureFree((Texture*)(gTitleScreenTextures[i]));
            gTitleScreenTextures[i] = NULL;
        }
        i++;
    } while (i < TITLE_SCREEN_TEXTURE_COUNT);
    gTitleScreenSetupDone = 0;
}


extern s16 gTitleScreenTextureIds[];
/* Main title-screen texture asset ids (docblock: "the main texture (asset 0x647 or 0xC5)"). */
#define FRONT_MAIN_TEXTURE_ID_A 0x647
#define FRONT_MAIN_TEXTURE_ID_B 0xC5

/* Copyright/title text box shown by titleScreenShowCopyright (docblock: "push text box 0x3d9"). */

/* Reset state bytes, load the main texture (asset 0x647 or 0xC5 depending on
 * gGameTextFontIsSjis), identity the matrix, then load the 19-entry texture table
 * from the id list at gTitleScreenTextureIds into gTitleScreenTextures. */
void TitleScreen_initialise(void)
{
    int i;
    gTitleScreenPrevMenuSelection = -1;
    gTitleScreenMenuSelection = 0;
    gTitleScreenPrevMenuActive = -1;
    gTitleScreenMenuActive = 0;
    if (gGameTextFontIsSjis != 0)
    {
        gTitleScreenMainTex = textureLoadAsset(FRONT_MAIN_TEXTURE_ID_A);
    }
    else
    {
        gTitleScreenMainTex = textureLoadAsset(FRONT_MAIN_TEXTURE_ID_B);
    }
    lbl_803DD9D0 = 1.0f;
    lbl_803DD9CC = 1.0f;
    PSMTXIdentity((MtxPtr)gTitleScreenMtx);
    for (i = 0; i < TITLE_SCREEN_TEXTURE_COUNT; i++)
    {
        gTitleScreenTextures[i] = textureLoadAsset(gTitleScreenTextureIds[i]);
    }
    gTitleScreenPulseTimer = 0.0f;
    gTitleScreenSetupDone = 0;
    gTitleScreenCopyrightBaseY = 0;
    gTitleScreenSlideProgressX = 1.0f;
    gTitleScreenCursorX = 1.0f;
    gTitleScreenActorsEnabled = 1;
}


s16 gTitleScreenTextureIds[20] = {0x60B, 0x60C, 0x60D, 0x60E, 0x60F, 0x610, 0x611, 0x612, 0x619, 0x61A,
                                  0x61B, 0x61C, 0x61D, 0x620, 0x621, 0x622, 0x61E, 0x61F, 0x618, 0x000};

TitleAnimMoves gTitleScreenAnimMoves[] = {
    {{0.01f, 0.01f, 0.01f, -0.01f, 0.01f, 0.01f, 0.01f, 0.01f}},
    {{0.003f, 0.01f, 0.01f, -0.01f, 0.007f, 0.007f, 0.003f, 0.003f}},
    {{0.01f, 0.01f, 0.01f, -0.01f, 0.01f, 0.004f, 0.01f, 0.004f}},
    {{0.01f, 0.01f, 0.0075f, -0.01f, 0.01f, 0.01f, 0.01f, 0.01f}},
};

CreditEntry gCreditEntries[] = {
    {0x1FD, 0x78},  {0x4CB, 0xB4}, {0x4CC, 0xB4},  {0x4CD, 0xB4},  {0x4CE, 0xB4}, {0x4CF, 0xB4}, {0x4D0, 0xB4},
    {0x4D1, 0xB4},  {0x4F4, 0xB4}, {0x4D2, 0x168}, {0x4D3, 0x12C}, {0x4D4, 0xB4}, {0x4D5, 0xB4}, {0x4D6, 0xB4},
    {0x4D8, 0xB4},  {0x4D9, 0xB4}, {0x4D7, 0xB4},  {0x4EF, 0xB4},  {0x517, 0xB4}, {0x518, 0xB4}, {0x519, 0xB4},
    {0x52A, 0xB4},  {0x54A, 0xB4}, {0x54B, 0xB4},  {0x54C, 0xB4},  {0x4DA, 0xB4}, {0x4DB, 0xB4}, {0x4DC, 0xB4},
    {0x4DD, 0xB4},  {0x4DE, 0xB4}, {0x4DF, 0xB4},  {0x4E0, 0xB4},  {0x4E1, 0xB4}, {0x4E2, 0xB4}, {0x4E3, 0xB4},
    {0x4E4, 0xB4},  {0x4E5, 0xB4}, {0x4E6, 0xB4},  {0x4E7, 0xB4},  {0x4E8, 0xB4}, {0x4E9, 0xB4}, {0x4EA, 0xB4},
    {0x4EB, 0x168}, {0x4F3, 0xB4}, {0x4EC, 0xB4},  {0x52B, 0xB4},  {0x4ED, 0xB4}, {0x4EE, 0xB4}, {0x4F0, 0xB4},
    {0x4F1, 0xB4},  {0x4F2, 0xB4}, {0x56D, 0xB4},  {0x526, 0xB4},
};

ObjectDescriptor10WithPadding gTitleScreenObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)TitleScreen_initialise,
        (ObjectDescriptorCallback)TitleScreen_release,
        0,
        (ObjectDescriptorCallback)TitleScreen_init,
        (ObjectDescriptorCallback)TitleScreen_update,
        (ObjectDescriptorCallback)TitleScreen_hitDetect,
        (ObjectDescriptorCallback)TitleScreen_render,
        (ObjectDescriptorCallback)TitleScreen_free,
        (ObjectDescriptorCallback)TitleScreen_getObjectTypeId,
        TitleScreen_getExtraSize,
    },
    0,
};

u8 gTitleScreenMtx[0x34];
void* gTitleScreenTextures[TITLE_SCREEN_TEXTURE_COUNT];
u8 gTitleScreenSfxFlagGrid[0x48];
