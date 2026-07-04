/*
 * tricky (GameUI DLL) - the in-game HUD / heads-up display and pause-menu
 * resource layer.
 *
 * gameUiLoadResources spawns the persistent HUD objects (button icons,
 * magic/health/spirit/scarab/key/tricky counters, the air/breath meter and
 * the viewfinder reticle models) and gameUiResetMenuState tears them down.
 * The bulk of the file is GX immediate-mode drawing: pauseMenuDrawElement /
 * pauseMenuTextDrawFn / drawFn_* push textured quads into the write-gather
 * pipe (GXWGFifo at 0xCC008000); pauseMenuMapFn_8011de20 programs the TEV
 * pipeline shared by those draws.
 *
 * Functional HUD pieces: the breath/air meter (GameUI_initAirMeter,
 * GameUI_airMeterRun, hudDrawAirMeter - two layouts selected by m[0x10]),
 * the fear-test meter (fearTestMeterDraw), the main status HUD with magic
 * bar and item counters (hudDrawFn_80121440, gated by various game bits),
 * and the photo-mode viewfinder overlay with its angle ticks and distance
 * readout (drawViewFinderHud). A/B button prompt icons, the death menu and
 * input-override state round it out.
 */
#include "main/dll/ppcwgpipe_struct.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/camera_interface.h"
#include "main/mapEventTypes.h"
#include "main/texture.h"
#include "main/gameplay_runtime.h"
#include "main/mm.h"
#include "main/dll/tricky.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/rcp_dolphin.h"
#include "main/lightmap.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "sfa_light_decls.h"

#define TRICKY_OBJFLAG_PARENT_SLACK 0x1000

typedef struct GameUIWork10
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    s16 unkC;
    u8 padE[0x10 - 0xE];
} GameUIWork10;

typedef struct TrickyAirMeter
{
    u8 pad0[0x18 - 0x0];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    u8 pad28[0x2C - 0x28];
    u16 unk2C;
    u8 pad2E[0x48 - 0x2E];
} TrickyAirMeter;

extern int ObjGroup_FindNearestObject();
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);

extern void GXSetBlendMode(int mode, int srcFactor, int dstFactor, int logicOp);
extern f32 gViewFinderFadeLevel;
extern u8 gameUiResourcesLoaded;
extern char lbl_803A87F0[];
extern char* lbl_803DD85C;
extern char* lbl_803DD860[2];
extern char* lbl_803DD868[];
extern int lbl_8031BF90[];
extern const f32 lbl_803E1E3C;
extern f32 lbl_803E1E40, lbl_803E1E44, lbl_803E1E48, lbl_803E1E4C;
extern f32 lbl_803E1E50, lbl_803E1E54, lbl_803E1E58, lbl_803E1E5C;
extern void* Obj_AllocObjectSetup(int size, int b);
extern char* Obj_SetupObject(char* obj, int a, int b, int c, int d);
extern void* Obj_GetActiveModel(char* obj);
extern void ObjModel_SetRenderCallback(u8* model, void* callback);
extern u8 cMenuRingModelRenderFn[];
extern u8 cMenuRingIconRenderFn[];
extern int fn_8011E0D8();

void gameUiLoadResources(void)
{
    char* base = lbl_803A87F0;
    if (gameUiResourcesLoaded == 0)
    {
        char** arrA;
        char** arrB;
        int i;
        int val;
        u32 limit;
        char** arrC;
        int* ids;
        char* p;
        u32* cnt;
        f32 fb, fc, fa;
        f32 gb, ga;

        val = 0;
        i = 0;
        arrA = (char**)(base + 0xbfc);
        arrB = (char**)(base + 0xbf0);
        fa = lbl_803E1E3C;
        fb = lbl_803E1E40;
        fc = lbl_803E1E44;
        for (; i < 3; i++)
        {
            *arrA = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x65e), 4, -1, -1, 0);
            ((GameObject*)(*arrA))->anim.localPosX = fa;
            ((GameObject*)(*arrA))->anim.localPosY = fb;
            ((GameObject*)(*arrA))->anim.localPosZ = fc;
            ((GameObject*)(*arrA))->anim.rotX = val;
            *(s8*)(*arrA + 0xad) = i;
            ObjModel_SetRenderCallback(Obj_GetActiveModel(*arrA), cMenuRingModelRenderFn);
            *arrB = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x65f), 4, -1, -1, 0);
            ((GameObject*)(*arrB))->anim.localPosX = fa;
            ((GameObject*)(*arrB))->anim.localPosY = fb;
            ((GameObject*)(*arrB))->anim.localPosZ = fc;
            ((GameObject*)(*arrB))->anim.rotX = val;
            ObjModel_SetRenderCallback(Obj_GetActiveModel(*arrB), cMenuRingIconRenderFn);
            val += 0x5555;
            arrA++;
            arrB++;
        }

        lbl_803DD868[0] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x6e9), 4, -1, -1, 0);
        ((GameObject*)lbl_803DD868[0])->anim.localPosX = lbl_803E1E3C;
        ((GameObject*)lbl_803DD868[0])->anim.localPosY = lbl_803E1E48;
        ((GameObject*)lbl_803DD868[0])->anim.localPosZ = lbl_803E1E4C;
        ((GameObject*)lbl_803DD868[0])->anim.rotX = 0x7447;
        *(f32*)(lbl_803DD868[0] + 0x8) = lbl_803E1E50;

        lbl_803DD868[1] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x602), 4, -1, -1, 0);
        ((GameObject*)lbl_803DD868[1])->anim.localPosX = lbl_803E1E3C;
        ((GameObject*)lbl_803DD868[1])->anim.localPosY = lbl_803E1E54;
        ((GameObject*)lbl_803DD868[1])->anim.localPosZ = lbl_803E1E4C;
        ((GameObject*)lbl_803DD868[1])->anim.rotX = 0x7447;
        *(f32*)(lbl_803DD868[1] + 0x8) = lbl_803E1E58;

        p = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x755), 4, -1, -1, 0);
        lbl_803DD860[0] = p;
        ObjModel_SetRenderCallback(*(void**)*(int*)(p + 0x7c), fn_8011E0D8);

        lbl_803DD860[1] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x756), 4, -1, -1, 0);
        ObjModel_SetRenderCallback(*(void**)*(int*)(lbl_803DD860[1] + 0x7c), fn_8011E0D8);

        i = 4;
        ids = &lbl_8031BF90[4];
        arrC = (char**)(base + 0xc30);
        ga = lbl_803E1E3C;
        gb = lbl_803E1E5C;
        limit = 0x90000000;
        for (; i < 6; i++)
        {
            *arrC = Obj_SetupObject(Obj_AllocObjectSetup(0x20, *ids), 4, -1, -1, 0);
            ((GameObject*)(*arrC))->anim.localPosX = ga;
            ((GameObject*)(*arrC))->anim.localPosY = gb;
            ((GameObject*)(*arrC))->anim.localPosZ = gb;
            ((GameObject*)(*arrC))->anim.rotX = 0x7447;
            *(f32*)(*arrC + 0x8) = ga;
            cnt = (u32*)(*arrC + 0x4c);
            if (*cnt > limit)
            {
                *cnt = 0;
            }
            ids++;
            arrC++;
        }

        p = Obj_AllocObjectSetup(0x24, 0x14b);
        *(s16*)(p + 0x1c) = 1;
        lbl_803DD85C = Obj_SetupObject(p, 4, -1, -1, 0);
        gameUiResourcesLoaded = 1;
    }
}

#pragma scheduling on
#pragma peephole on
extern u8 pauseMenuState;
extern u8 lbl_803DD7B3;
extern u8 lbl_803DD792;
extern u8 gTrickyHudShowNearestInfo;
extern u8 lbl_803DBA88;
u8 pauseMenuGetState(void) { return pauseMenuState; }
void fn_8011F34C(u8 x) { lbl_803DD7B3 = x; }
void hudFn_8011f38c(u8 x) { lbl_803DD792 = x; }
void hudFn_8011f6f0(u8 x) { gTrickyHudShowNearestInfo = x; }
void GameUI_func0E(u8 x) { lbl_803DBA88 = x; }

extern s16 gFearTestMeterFadeIn;

void fn_8011F6D4(u32 x)
{
    gFearTestMeterFadeIn = (s16)(u8)x;
}

extern s16 aButtonIcon;
#pragma scheduling reset
#pragma peephole reset
void forceAButtonIcon(int x)
{
    aButtonIcon = x;
}

extern s16 yButtonItemTextureId;
extern u16 yButtonState;

void resetYbutton(void)
{
    yButtonState = 0;
    yButtonItemTextureId = -1;
}

extern u8 bButtonIcon;

void setBButtonIcon(int x)
{
    if (bButtonIcon == 0)
    {
        bButtonIcon = x;
    }
}

void setAButtonIcon(int x)
{
    if (aButtonIcon == 0)
    {
        aButtonIcon = x;
    }
}

extern u8 fearTestMeterOuterHalfWidth;
extern u8 fearTestMeterInnerHalfWidth;
extern s16 fearTestMeterMarkerX;
#pragma scheduling on
void fearTestMeterSetRange(u8 a, u8 b, s16 c)
{
    fearTestMeterOuterHalfWidth = a;
    fearTestMeterInnerHalfWidth = b;
    fearTestMeterMarkerX = c;
}

extern void* airMeter;

void GameUI_airMeterSetField24(float v)
{
    void* p = airMeter;
    if (p == 0) return;
    *(f32*)((char*)p + 0x24) = v;
}

extern void cutsceneFadeInOut(int a);
extern void setTimeStop(int v);


extern void gameTextLoadDir(int dirId);
extern f32 lbl_803E1E60;
extern f32 lbl_803DD764;
extern int lbl_803DD8DC;
extern int lbl_803DD7D8;
#pragma scheduling off
void cutSceneFn_8011dd30(void)
{
    cutsceneFadeInOut(1);
    setTimeStop(0xff);
    pauseMenuInit();
    pauseMenuState = 0xb;
    lbl_803DD8DC = getCurGameText();
    gameTextLoadDir(0xb);
    lbl_803DD764 = lbl_803E1E60;
    lbl_803DD7D8 = 1;
}

extern int gCMenuScriptedButtons;
extern s16 lbl_803DD89E;
extern s16 gCMenuScriptedStickY;
extern u8 gCMenuScriptedInput;

void GameUI_setInputOverride(int x, s16 a, s16 b)
{
    if (x == -1)
    {
        gCMenuScriptedButtons = 0;
        lbl_803DD89E = 0;
        gCMenuScriptedStickY = 0;
        gCMenuScriptedInput = 0;
        return;
    }
    gCMenuScriptedButtons = x;
    lbl_803DD89E = a;
    gCMenuScriptedStickY = b;
    gCMenuScriptedInput = 1;
}

extern u8 arwingHudVisible;
extern s16 arwingHudAlpha;

void arwingHudSetVisible(u32 x)
{
    u32 v = x & 0xff;
    arwingHudVisible = (u8)(v & 1);
    if ((s32)v != 3)
    {
        if ((s32)v >= 3) return;
        if ((s32)v < 2) return;
        arwingHudAlpha = 0;
        return;
    }
    arwingHudAlpha = 0xff;
}

extern u16 yButtonItem;
#pragma scheduling on
u16 getYButtonItem(s16* out)
{
    s32 t;
    if (yButtonState != 0)
    {
        t = yButtonItem;
        *out = t;
    }
    return yButtonState;
}

/* GameUI_airMeterSetShutdown: set bit 7 of (*p)+0x44 if p non-null */
typedef struct
{
    char pad[0x44];
    u8 bit7 : 1;
    u8 bits_0to6 : 7;
} AirMeterFlags;
#pragma scheduling off
void GameUI_airMeterSetShutdown(void)
{
    AirMeterFlags* p = (AirMeterFlags*)airMeter;
    if (p == 0) return;
    p->bit7 = 1;
}

extern int lbl_803A9398[];

#pragma dont_inline on
void GameUI_airMeterShutdown(void)
{
    int* m = airMeter;
    if (m == NULL) return;
    ((TrickyAirMeter*)m)->unk18 = 0;
    switch (m[0x10])
    {
    case 0:
        textureFree((u8*)m[0xb]);
        textureFree((u8*)m[0xc]);
        break;
    case 1:
        textureFree((u8*)m[0xc]);
        textureFree((u8*)m[0xd]);
        textureFree((u8*)m[0xe]);
        textureFree((u8*)m[0xf]);
        break;
    }
    mm_free(airMeter);
    airMeter = NULL;
}
#pragma dont_inline reset

extern void* memset(void* p, int v, int n);
extern const f32 lbl_803E1E68;

void GameUI_initAirMeter(int a, int b)
{
    int* m;
    if (airMeter == NULL)
    {
    }
    else if ((((AirMeterFlags*)airMeter)->bit7) != 0)
    {
        GameUI_airMeterShutdown();
    }
    else
    {
        return;
    }
    m = mmAlloc(0x48, 0x19, 0);
    memset(m, 0, 0x48);
    m[0] = 0;
    m[1] = a;
    m[2] = 0;
    m[0xc] = (int)textureLoadAsset(b);
    ((TrickyAirMeter*)m)->unk2C = b;
    m[0xd] = (int)textureLoadAsset(0x5d4);
    m[0xe] = (int)textureLoadAsset(0x5d3);
    m[0xf] = (int)textureLoadAsset(0x5d2);
    airMeter = m;
    ((TrickyAirMeter*)m)->unk18 = 0;
    ((TrickyAirMeter*)m)->unk24 = lbl_803E1E68;
    m[0x10] = 1;
}

extern u8 lbl_803DB424;

void showDeathMenu(void)
{
    MapEventInterface* mapEvents = *gMapEventInterface;
    int* r = mapEvents->getCurCharacterState();
    pauseMenuInit();
    if (*((u8*)r + 9) != 0)
    {
        pauseMenuState = 8;
    }
    else if (lbl_803DB424 != 0)
    {
        pauseMenuState = 9;
    }
    else
    {
        pauseMenuState = 0xa;
    }
    lbl_803DD8DC = getCurGameText();
    gameTextLoadDir(0xb);
    lbl_803DD764 = lbl_803E1E60;
    lbl_803DD7D8 = 1;
}

void GameUI_func15(s16 a, int b, int c)
{
    void* t = textureLoadAsset(a);
    lbl_803A9398[0] = (int)t;
    if (t == NULL) return;
    lbl_803A9398[1] = b;
    ((GameUIWork10*)lbl_803A9398)->unkC = c;
    ((GameUIWork10*)lbl_803A9398)->unk8 = lbl_803E1E3C;
}

void GameUI_airMeterRun(int v)
{
    int clamped;
    if (airMeter == NULL) return;
    clamped = (v < 0) ? 0 : ((v > ((int*)airMeter)[1]) ? ((int*)airMeter)[1] : v);
    v = clamped;
    if (((int*)airMeter)[0x10] == 1)
    {
        v = clamped * 0x9e / ((int*)airMeter)[1];
    }
    ((int*)airMeter)[3] = v;
}

extern u8 cMenuEnabled;
extern u16 curGameText;
extern s16 lbl_803DD8D0;
extern u8 lbl_803DD7A8;
extern s16 lbl_803DD778;
extern int lbl_803DD730;
extern s16 lbl_803DD770;
extern f32 lbl_803DD760;
extern int lbl_803A9410[];
extern u8 lbl_803DD75B;
extern s16 lbl_803DD772;
extern u8 pauseMenuFrameCounter;
extern void Obj_FreeObject(int* obj);

void gameUiResetMenuState(void)
{
    int z[2];
    cMenuEnabled = 0;
    curGameText = 0xffff;
    lbl_803DD8D0 = 0;
    lbl_803DD7A8 = 0;
    GameUI_airMeterShutdown();
    z[0] = 0;
    pauseMenuState = z[0];
    lbl_803DD778 = z[0];
    lbl_803DD730 = z[0];
    lbl_803DD770 = z[0];
    lbl_803DD760 = lbl_803E1E3C;
    z[1] = z[0];
    {
        int** arr = (int**)lbl_803A9410;
        for (; z[1] < 4; z[1]++)
        {
            if (arr[z[1]] != NULL)
            {
                ((int*)arr[z[1]][0x19])[1] = 0;
                ((int*)arr[z[1]][0x19])[2] = 0;
                if ((u32)arr[z[1]][0x13] > 0x90000000) arr[z[1]][0x13] = 0;
                Obj_FreeObject(arr[z[1]]);
                arr[z[1]] = NULL;
            }
        }
    }
    gTrickyHudShowNearestInfo = 0;
    lbl_803DD75B = 0;
    lbl_803DD772 = 0;
    pauseMenuFrameCounter = 0x3c;
    lbl_803DD792 = 0;
}

void GameUI_airMeterInitType0(int a, int b, int c)
{
    int* m;
    if (airMeter != NULL) return;
    m = mmAlloc(0x48, 0x19, 0);
    memset(m, 0, 0x48);
    m[0] = 0;
    m[1] = a;
    m[0xb] = (int)textureLoadAsset(b);
    m[0xc] = (int)textureLoadAsset(c);
    m[4] = *(u16*)((char*)m[0xb] + 0xa);
    m[5] = *(u16*)((char*)m[0xb] + 0xc);
    airMeter = m;
    ((TrickyAirMeter*)m)->unk18 = 0;
    ((TrickyAirMeter*)m)->unk24 = lbl_803E1E68;
    m[0x10] = 0;
}

extern int gCMenuSections[];

void GameUI_func14(s16 a, int b, int c)
{
    int* entry = gCMenuSections;
    lbl_803A9398[0] = 0;
    while ((void*)*entry != NULL)
    {
        s16* row = (s16*)*entry;
        while (row[0] != -1)
        {
            if (row[0] == a)
            {
                lbl_803A9398[0] = (int)textureLoadAsset(row[3]);
                break;
            }
            row += 8;
        }
        entry = (int*)((char*)entry + 0x10);
    }
    if (*(void**)lbl_803A9398 != NULL)
    {
        lbl_803A9398[1] = b;
        ((GameUIWork10*)lbl_803A9398)->unkC = c;
        ((GameUIWork10*)lbl_803A9398)->unk8 = lbl_803E1E3C;
    }
}

extern u8 framesThisStep;
extern const f32 hudElementOpacity;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E1FA0;
extern f32 lbl_803E1FA4;
extern int lbl_803DD740;
extern int lbl_803A9428[];
extern void drawTexture(void* p, f32 a, f32 b, int c, int d);

void hudDrawTimedElement(int unused, int* e)
{
    if (e[1] < 0) return;
    e[1] = e[1] - framesThisStep;
    if (e[1] < 0)
    {
        textureFree((u8*)e[0]);
        e[0] = 0;
        return;
    }
    if ((f32)e[1] < lbl_803E1F9C)
    {
        *(f32*)((char*)e + 0x8) = hudElementOpacity * (f32)e[1] / *(f32*)&lbl_803E1F9C;
    }
    else
    {
        f32 op = hudElementOpacity;
        if (op != *(f32*)((char*)e + 0x8))
        {
            *(f32*)((char*)e + 0x8) = lbl_803E1FA0 * (f32)(u32)
            framesThisStep + *(f32*)((char*)e + 0x8);
            if (*(f32*)((char*)e + 0x8) > op)
            {
                *(f32*)((char*)e + 0x8) = op;
            }
        }
    }
    memset(lbl_803A9428, 0, 0xc);
    lbl_803A9428[0] = e[0];
    lbl_803A9428[3] = 0;
    drawTexture(lbl_803A9428, lbl_803E1FA4, (f32)(lbl_803DD740 + 0xaf),
                (int)*(f32*)((char*)e + 0x8), 0x100);
}

volatile PPCWGPipe GXWGFifo : (0xCC008000);

extern void GXBegin(int type, int fmt, int n);
extern f32 lbl_803E1E80;


void pauseMenuDrawElement(void *element, f32 fx, f32 fy, int depthZ, u8 paletteIndex, int scalePercent, int flags)
{
    int dx, dy;
    f32 c0, c1;
    pauseMenuMapFn_8011de20(element, paletteIndex, depthZ, flags & 4);
    dx = (*(u16*)((char*)element + 0xa) << 2) * (u16)scalePercent / 256;
    dy = (*(u16*)((char*)element + 0xc) << 2) * (u16)scalePercent / 256;
    fx = lbl_803E1E80 * fx;
    fy = lbl_803E1E80 * fy;
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = fx;
    GXWGFifo.s16 = fy;
    GXWGFifo.s16 = (s16)(depthZ << 2);
    c0 = lbl_803E1E3C;
    GXWGFifo.f32 = c0;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = fy;
    GXWGFifo.s16 = (s16)(depthZ << 2);
    c1 = lbl_803E1E68;
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(depthZ << 2);
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c1;
    GXWGFifo.s16 = fx;
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(depthZ << 2);
    GXWGFifo.f32 = c0;
    GXWGFifo.f32 = c1;
}

typedef struct
{
    u8 r, g, b, a;
} GXColor;

extern void GXSetTevColor(int id, GXColor c);
extern void GXSetTevKColor(int id, GXColor c);
extern void GXLoadPosMtxImm(void* m, int id);
extern void GXLoadNrmMtxImm(void* m, int id);
extern void GXSetCurrentMtx(u32 id);
extern void GXSetNumTexGens(u8 nTexGens);
extern void GXSetNumIndStages(u8 nIndStages);
extern void GXSetNumChans(u8 nChans);
extern void textureFn_8004c264(void *this, int x);
extern void GXSetTexCoordGen2(int a, int b, int c, int d, int e, int f);
extern void GXSetTevKColorSel(int stage, int sel);
extern void GXSetTevDirect(int stage);
extern void GXSetTevOrder(int stage, int a, int b, int c);
extern void GXSetTevColorIn(int stage, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
extern void GXSetTevSwapMode(int stage, int a, int b);
extern void GXSetTevColorOp(int stage, int a, int b, int c, int d, int e);
extern void GXSetTevAlphaOp(int stage, int a, int b, int c, int d, int e);
extern void GXSetNumTevStages(u8 nStages);
extern void GXSetCullMode(int m);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);

extern void GXSetVtxDesc(int a, int b);
extern int lbl_803E1E34;
extern int lbl_803E1E38;
char lbl_803A8830[0x120];

void pauseMenuMapFn_8011de20(void *this, u8 a, s16 b, int c)
{
    GXColor colA = *(GXColor*)&lbl_803E1E34;
    GXColor colB = *(GXColor*)&lbl_803E1E38;
    colA.a = a;
    GXSetTevColor(1, colA);
    GXLoadPosMtxImm(lbl_803A8830, 0);
    GXLoadNrmMtxImm(lbl_803A8830, 0);
    GXSetCurrentMtx(0);
    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetNumChans(0);
    textureFn_8004c264(this, 0);
    GXSetTexCoordGen2(0, 1, 4, 0x3c, 0, 0x7d);
    GXSetTevKColorSel(0, 0xc);
    GXSetTevKColor(0, colB);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 2, 8, 0xe, 0xf);
    GXSetTevAlphaIn(0, 7, 1, 4, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (*(void**)((char*)this + 0x50) != NULL)
    {
        GXSetTevDirect(1);
        GXSetTevOrder(1, 0, 1, 0xff);
        GXSetTevColorIn(1, 0xf, 0xf, 0xf, 0);
        GXSetTevAlphaIn(1, 7, 1, 4, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    }
    else
    {
        GXSetNumTevStages(1);
    }
    GXSetCullMode(0);
    if ((u8)c != 0)
    {
        GXSetBlendMode(1, 4, 1, 5);
    }
    else
    {
        GXSetBlendMode(1, 4, 5, 5);
    }
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
}

extern volatile s16 lbl_803DBA8A;
extern f32 lbl_803DBA8C;

#pragma opt_propagation off
void pauseMenuTextDrawFn(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    s16 z;
    GXLoadPosMtxImm(lbl_803A8830, 0);
    GXLoadNrmMtxImm(lbl_803A8830, 0);
    GXSetCurrentMtx(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCullMode(0);
    x0 -= 0x500;
    y0 -= 0x3c0;
    x1 -= 0x500;
    y1 -= 0x3c0;
    x0 = (f32)x0 * lbl_803DBA8C;
    y0 = (f32)y0 * lbl_803DBA8C;
    x1 = (f32)x1 * lbl_803DBA8C;
    y1 = (f32)y1 * lbl_803DBA8C;
    GXBegin(0x80, 1, 4);
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x0 + 0x500);
    GXWGFifo.s16 = (s16)(y0 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x1 + 0x500);
    GXWGFifo.s16 = (s16)(y0 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x1 + 0x500);
    GXWGFifo.s16 = (s16)(y1 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x0 + 0x500);
    GXWGFifo.s16 = (s16)(y1 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
}
#pragma opt_propagation reset

void drawFn_8011e8d8(void *this, f32 f1, f32 f2, int p4, u8 p5, int p6, int p7, int p8, int p9)
{
    f32 u1, u0, v0, v1;
    pauseMenuMapFn_8011de20(this, p5, p4, 0);
    f1 = lbl_803E1E80 * f1;
    f2 = lbl_803E1E80 * f2;
    u0 = (f32)(u32)
    p8 / *(u16*)((char*)this + 0xa);
    v0 = (f32)(u32)
    p9 / *(u16*)((char*)this + 0xc);
    u1 = (f32)(u32)(p6 + p8) / *(u16*)((char*)this + 0xa);
    v1 = (f32)(u32)(p7 + p9) / *(u16*)((char*)this + 0xc);
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = f1;
    GXWGFifo.s16 = f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = (s16)(f2 + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = f1;
    GXWGFifo.s16 = (s16)(f2 + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
}

void drawFn_8011eb3c(void *this, f32 f1, f32 f2, int p4, u8 p5, int p6, int p7, int p8, int p9)
{
    f32 ua, ub, va, vb, tu, tv;
    u32 dx, dy;
    u8 flags = p9;
    pauseMenuMapFn_8011de20(this, p5, p4, flags & 4);
    dx = ((u32)(p7 << 2) * (u16)p6) >> 8;
    dy = ((u32)(p8 << 2) * (u16)p6) >> 8;
    f1 = lbl_803E1E80 * f1;
    f2 = lbl_803E1E80 * f2;
    tu = (f32)(u32)p7 / (f32)(u32)*(u16*)((char*)this + 0xa);
    tv = (f32)(u32)p8 / (f32)(u32)*(u16*)((char*)this + 0xc);
    if (flags & 1)
    {
        ua = tu;
        ub = lbl_803E1E3C;
    }
    else
    {
        ua = lbl_803E1E3C;
        ub = tu;
    }
    if (flags & 2)
    {
        va = tv;
        vb = lbl_803E1E3C;
    }
    else
    {
        va = lbl_803E1E3C;
        vb = tv;
    }
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = f1;
    GXWGFifo.s16 = f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ua;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)dx);
    GXWGFifo.s16 = f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)(f2 + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = vb;
    GXWGFifo.s16 = f1;
    GXWGFifo.s16 = (s16)(f2 + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ua;
    GXWGFifo.f32 = vb;
}

extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void C_MTXPerspective(f32* m, f32 fovY, f32 aspect, f32 nearP, f32 farP);

extern void Camera_SetFovY(f32 fovY);

extern void Camera_SetCurrentViewIndex(int index);
extern void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
extern void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll);

extern f32 gTrickyHudIconPosX, gTrickyHudIconPosY, gTrickyHudIconPosZ, gTrickyHudIconScale;
extern f32 gTrickyHudIconRotZ, gTrickyHudIconRotX, gTrickyHudIconRotY, lbl_803DD7FC;
extern const f32 lbl_803E1E94;
extern f32 gTrickyHudPi, lbl_803E1E98;
extern f32 gTrickyHudTexScaleX, gTrickyHudTexScaleY, gTrickyHudTexScaleZ;
extern f32 gTrickyHudIconFovY, gTrickyHudIconAspect, gTrickyHudIconNearPlane, gTrickyHudIconFarPlane;

#pragma opt_propagation off
void fn_8011EF50(f32 f1, f32 f2, f32 f3, f32 f4, u16 a, u16 b, u16 c)
{
    char* base = lbl_803A87F0;
    char** objs;
    s16 sa, sb, sc;
    f32 mA[12];
    f32 mB[12];
    gTrickyHudIconPosX = f1;
    gTrickyHudIconPosY = f2;
    gTrickyHudIconPosZ = f3;
    gTrickyHudIconScale = f4;
    gTrickyHudIconRotZ = gTrickyHudPi * (f32)(u32)
    a / lbl_803E1E94;
    gTrickyHudIconRotX = gTrickyHudPi * (f32)(u32)
    b / lbl_803E1E94;
    gTrickyHudIconRotY = gTrickyHudPi * (f32)(u32)
    c / lbl_803E1E94;
    PSMTXRotRad(mA, 0x79, gTrickyHudIconRotY);
    PSMTXRotRad(mB, 0x78, gTrickyHudIconRotX);
    PSMTXConcat(mB, mA, mA);
    PSMTXRotRad(mB, 0x7a, gTrickyHudIconRotZ);
    PSMTXConcat(mB, mA, mA);
    PSMTXScale(mB, gTrickyHudIconScale, gTrickyHudIconScale, gTrickyHudIconScale);
    PSMTXConcat(mB, mA, mA);
    PSMTXTrans(mB, gTrickyHudIconPosX, gTrickyHudIconPosY, gTrickyHudIconPosZ);
    PSMTXConcat(mB, mA, (f32*)(base + 0x160));
    PSMTXScale(mA, gTrickyHudTexScaleX, -gTrickyHudTexScaleY, gTrickyHudTexScaleZ);
    PSMTXTrans(mB, lbl_803E1E98, lbl_803E1E68, lbl_803E1E3C);
    PSMTXConcat(mB, mA, mB);
    PSMTXConcat((f32*)(base + 0x160), mB, (f32*)(base + 0x40));
    C_MTXPerspective((f32*)base, gTrickyHudIconFovY, gTrickyHudIconAspect, gTrickyHudIconNearPlane, gTrickyHudIconFarPlane);
    lbl_803DD7FC = Camera_GetFovY();
    Camera_SetFovY(gTrickyHudIconFovY);
    Camera_RebuildProjectionMatrix();
    Camera_SetCurrentViewIndex(1);
    Camera_SetCurrentViewPosition(lbl_803E1E3C, lbl_803E1E3C, lbl_803E1E3C);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    objs = lbl_803DD860;
    sa = a;
    sb = b;
    sc = c;
    ((GameObject*)objs[0])->anim.localPosX = gTrickyHudIconPosX;
    ((GameObject*)objs[0])->anim.localPosY = gTrickyHudIconPosY;
    ((GameObject*)objs[0])->anim.localPosZ = gTrickyHudIconPosZ;
    ((GameObject*)objs[0])->anim.worldPosX = gTrickyHudIconPosX;
    ((GameObject*)objs[0])->anim.worldPosY = gTrickyHudIconPosY;
    ((GameObject*)objs[0])->anim.worldPosZ = gTrickyHudIconPosZ;
    *(f32*)(objs[0] + 0x8) = f4;
    ((GameObject*)objs[0])->anim.rotZ = sa;
    ((GameObject*)objs[0])->anim.rotY = sb;
    ((GameObject*)objs[0])->anim.rotX = sc;
    ((GameObject*)objs[1])->anim.localPosX = gTrickyHudIconPosX;
    ((GameObject*)objs[1])->anim.localPosY = gTrickyHudIconPosY;
    ((GameObject*)objs[1])->anim.localPosZ = gTrickyHudIconPosZ;
    ((GameObject*)objs[1])->anim.worldPosX = gTrickyHudIconPosX;
    ((GameObject*)objs[1])->anim.worldPosY = gTrickyHudIconPosY;
    ((GameObject*)objs[1])->anim.worldPosZ = gTrickyHudIconPosZ;
    *(f32*)(objs[1] + 0x8) = f4;
    ((GameObject*)objs[1])->anim.rotZ = sa;
    ((GameObject*)objs[1])->anim.rotY = sb;
    ((GameObject*)objs[1])->anim.rotX = sc;
}
#pragma opt_propagation reset

extern char hudTextures[];
extern s16 gFearTestMeterAlpha;
extern u8 gFearTestMeterFadeSpeed;
extern f32 lbl_803E1E9C;
extern u8 lbl_803DBAEE;
extern u8 gFearTestMeterMarkerHalfWidth;
extern void drawScaledTexture(void* tex, f32 x, f32 y, int alpha, int p5, int p6, int p7, int p8);
extern void GXGetScissor(int* a, int* b, int* c, int* d);
extern void GXSetScissor(u32 left, u32 top, u32 wd, u32 ht);
extern void hudDrawRect(int x0, int y0, int x1, int y1, GXColor col);

void fearTestMeterDraw(void)
{
    GXColor col;
    int sc0, sc1, sc2, sc3;
    int a;
    void* texB = *(void**)(hudTextures + 0x180);
    u16 hgt = ((Texture*)texB)->height;
    int gap = fearTestMeterOuterHalfWidth - fearTestMeterInnerHalfWidth;
    void* texA = *(void**)(hudTextures + 0x17c);
    int wid = *(u16*)((char*)texA + 0xa) & 0xff;
    if (gFearTestMeterFadeIn != 0)
    {
        gFearTestMeterAlpha = gFearTestMeterAlpha + gFearTestMeterFadeSpeed * framesThisStep;
    }
    else
    {
        gFearTestMeterAlpha = gFearTestMeterAlpha - gFearTestMeterFadeSpeed * framesThisStep;
    }
    a = gFearTestMeterAlpha;
    if (a < 0)
    {
        a = 0;
    }
    else if (a > 0xff)
    {
        a = 0xff;
    }
    gFearTestMeterAlpha = a;
    if (gFearTestMeterAlpha == 0) return;
    GXGetScissor(&sc0, &sc1, &sc2, &sc3);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    drawScaledTexture(*(void**)(hudTextures + 0x17c),
                      (f32)(int)(0x140 - fearTestMeterOuterHalfWidth - wid), lbl_803E1E9C,
                      (u8)gFearTestMeterAlpha, 0x100, wid, hgt, 1);
    drawScaledTexture(*(void**)(hudTextures + 0x180),
                      (f32)(int)(0x140 - fearTestMeterInnerHalfWidth), lbl_803E1E9C,
                      (u8)gFearTestMeterAlpha, 0x100, fearTestMeterInnerHalfWidth << 1, hgt, 0);
    drawScaledTexture(*(void**)(hudTextures + 0x184),
                      (f32)(int)(0x140 - fearTestMeterOuterHalfWidth), lbl_803E1E9C,
                      (u8)gFearTestMeterAlpha, 0x100, gap, hgt, 0);
    drawScaledTexture(*(void**)(hudTextures + 0x184),
                      (f32)(int)((u8)fearTestMeterInnerHalfWidth + 0x140), lbl_803E1E9C,
                      (u8)gFearTestMeterAlpha, 0x100, gap, hgt, 0);
    drawTexture(*(void**)(hudTextures + 0x17c),
                (f32)(int)((u8)fearTestMeterOuterHalfWidth + 0x140), lbl_803E1E9C,
                (u8)gFearTestMeterAlpha, 0x100);
    col.r = 0xff;
    col.g = 0;
    col.b = 0;
    col.a = gFearTestMeterAlpha;
    {
        int half = gFearTestMeterMarkerHalfWidth;
        hudDrawRect((fearTestMeterMarkerX + 0x140) - half,
                    lbl_803DBAEE + 0x32,
                    half + (fearTestMeterMarkerX + 0x140),
                    (hgt + 0x32) - lbl_803DBAEE,
                    col);
    }
    GXSetScissor(sc0, sc1, sc2, sc3);
}


extern s8 lbl_803DBAEC;
extern u8 gTrickyAirMeterFillSpeed;
extern s8 lbl_803DD7F8;
extern s8 lbl_803DD7F9;

void hudDrawAirMeter(void)
{
    int sc0, sc1, sc2, sc3;
    int* player = Obj_GetPlayerObject();
    int* m = airMeter;
    AirMeterFlags* p = (AirMeterFlags*)airMeter;
    s16 alpha;
    if (m == NULL) return;
    alpha = ((TrickyAirMeter*)m)->unk18;
    if (p->bit7 || pauseMenuState != 0 || getHudHiddenFrameCount() != 0 ||
        (player != NULL && (((GameObject*)player)->objectFlags & TRICKY_OBJFLAG_PARENT_SLACK) != 0 &&
            ((TrickyAirMeter*)m)->unk2C != 0x5d5))
    {
        s16 clamped;
        alpha -= framesThisStep << 2;
        clamped = (alpha < 0) ? 0 : alpha;
        ((TrickyAirMeter*)m)->unk18 = clamped;
        if (((TrickyAirMeter*)m)->unk18 == 0 && p->bit7)
        {
            p->bit7 = 0;
            GameUI_airMeterShutdown();
            return;
        }
    }
    else
    {
        s16 clamped;
        alpha += framesThisStep << 2;
        clamped = (alpha > 0xff) ? 0xff : alpha;
        ((TrickyAirMeter*)m)->unk18 = clamped;
    }
    GXGetScissor(&sc0, &sc1, &sc2, &sc3);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    switch (m[0x10])
    {
    case 0:
        {
            int x = 0x140 - ((u32)(m[4] * m[1]) >> 1);
            int i;
            for (i = 0; i < m[1]; i++)
            {
                void* tex = (i < m[3]) ? m[0xb] : (void*)m[0xc];
                drawTexture(tex, (f32)(int)x, (f32)(u32)(0x1a4 - m[5]),
                            ((TrickyAirMeter*)m)->unk18, 0x100);
                x += m[4];
            }
            break;
        }
    case 1:
        {
            int base;
            int off;
            int by;
            int cy;
            int clampVal;
            s16 clampedC;
            switch (((TrickyAirMeter*)m)->unk2C)
            {
            case 0x63e:
                off = -0xa;
                break;
            case 0x643:
                off = -0xc;
                break;
            default:
                off = 0;
                break;
            }
            {
                base = 0x1a4 - ((u32)*(u16*)((char*)m[0xc] + 0xc) >> 1);
                base += lbl_803DBAEC;
                drawTexture((void*)m[0xc], (f32)(int)(lbl_803DD7F9 + 0xb5),
                            (f32)(int)(base + (lbl_803DD7F8 + (s8)off)),
                            ((TrickyAirMeter*)m)->unk18, 0x100);
            }
            by = *(u16*)((char*)m[0xc] + 0xa) + 0xb4;
            cy = 0x1a4 - ((u32)*(u16*)((char*)m[0xd] + 0xc) >> 1);
            if (m[2] < 0x9e)
            {
                m[2] = m[2] + framesThisStep * gTrickyAirMeterFillSpeed;
            }
            clampVal = (m[3] < 0) ? 0 : ((m[3] > m[2]) ? m[2] : m[3]);
            m[3] = clampVal;
            clampedC = clampVal;
            drawScaledTexture((void*)m[0xf], (f32)(int)(by + clampedC), (f32)(int)cy,
                              ((TrickyAirMeter*)m)->unk18, 0x100, m[2] - clampedC, 0x1a, 0);
            drawScaledTexture((void*)m[0xe], (f32)(int)by, (f32)(int)cy,
                              ((TrickyAirMeter*)m)->unk18, 0x100, clampedC, 0x1a, 0);
            drawTexture((void*)m[0xd], (f32)(int)(by + m[2]),
                        (f32)(int)cy,
                        ((TrickyAirMeter*)m)->unk18, 0x100);
            break;
        }
    }
    GXSetScissor(sc0, sc1, sc2, sc3);
}

extern void PSMTXCopy(f32 * src, f32 * dst);
extern void GXLoadTexMtxImm(f32* m, int id, int type);
extern void GXSetIndTexOrder(int stage, int a, int b);
extern void GXSetIndTexCoordScale(int stage, int a, int b);
extern void GXSetIndTexMtx(int id, f32* m, int scale);
extern void GXSetTevIndirect(int stage, int a, int b, int c, int d, int e, int f, int g, int h, int i);
extern void GXSetChanCtrl(int chan, int a, int b, int c, int d, int e, int f);
extern void GXSetChanMatColor(int chan, GXColor c);
extern void GXSetTevKAlphaSel(int stage, int sel);
extern void* ObjModel_GetRenderOp(int op, int x);
extern void* Shader_getLayer(char* base, int idx);
extern void selectTexture(u8* tex, int mapId);
extern void fn_8006C5CC(int* out);
extern int lbl_803E1E30;
extern int lbl_802C21AC[];
f32 lbl_803A8950[0x18];
extern f32 lbl_803E1E64, lbl_803E1E6C, lbl_803E1E70;
extern f32 lbl_803DD850;
extern f32 lbl_80396820[];
extern f32 gTrickyHudTexMtxScale;
extern int gTrickyHudIconKColor;

typedef struct
{
    int w[6];
} _IndMtx;

int fn_8011E0D8(int *this, int *p2, int p3)
{
    f32 m1[12];
    f32 m2[12];
    f32 mtex[12];
    f32 m3[12];
    _IndMtx indmtx;
    int tex2;
    GXColor chanCol;
    void *op, *layer, *tex0;
    f32 sval;

    chanCol = *(GXColor*)&lbl_803E1E30;
    indmtx = *(_IndMtx*)lbl_802C21AC;
    op = ObjModel_GetRenderOp(*p2, p3);
    layer = Shader_getLayer(op, 0);
    tex0 = textureIdxToPtr(*(int*)layer);

    PSMTXCopy(lbl_803A8950, m1);
    m1[3] = lbl_803E1E3C;
    m1[7] = lbl_803E1E3C;
    m1[11] = lbl_803E1E3C;
    PSMTXScale(m2, lbl_803E1E64 / gTrickyHudIconScale, lbl_803E1E64 / gTrickyHudIconScale, lbl_803E1E68 / gTrickyHudIconScale);
    m2[2] = lbl_803E1E6C / gTrickyHudIconScale;
    m2[6] = lbl_803E1E6C / gTrickyHudIconScale;
    PSMTXConcat(m2, m1, m1);
    GXLoadTexMtxImm(m1, 0x1e, 1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(3);
    GXSetNumIndStages(2);
    GXSetNumChans(1);
    GXSetIndTexOrder(0, 0, 2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32*)&indmtx, 0);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    selectTexture(tex0, 0);
    GXSetTexCoordGen2(0, 1, 1, 0x1e, 0, 0x7d);
    GXSetTevOrder(0, 0, 0, 4);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xa);
    GXSetTevAlphaIn(0, 7, 7, 7, 5);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanMatColor(4, chanCol);
    GXSetIndTexOrder(1, 0, 2);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetTevIndirect(1, 1, 0, 7, 1, 0, 0, 1, 0, 0);
    PSMTXConcat(lbl_80396820, lbl_803A8950, m1);
    sval = lbl_803E1E70 * (lbl_803DD850 * lbl_803DD850);
    PSMTXScale(m3, sval, sval, lbl_803E1E68);
    PSMTXConcat(m3, m1, m1);
    PSMTXTrans(m3, lbl_803E1E70 * (lbl_803E1E68 - sval), lbl_803E1E70 * (lbl_803E1E68 - sval), lbl_803E1E3C);
    PSMTXConcat(m3, m1, m1);
    GXLoadTexMtxImm(m1, 0x21, 0);
    GXSetTexCoordGen2(1, 0, 0, 0x21, 0, 0x7d);
    GXSetTevOrder(1, 1, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    mtex[0] = gTrickyHudTexMtxScale;
    mtex[1] = 0.0f;
    mtex[2] = 0.0f;
    mtex[3] = 0.5f;
    mtex[4] = 0.0f;
    mtex[5] = gTrickyHudTexMtxScale;
    mtex[6] = 0.0f;
    mtex[7] = 0.5f;
    mtex[8] = 0.0f;
    mtex[9] = 0.0f;
    mtex[10] = 0.0f;
    mtex[11] = 1.0f;
    GXLoadTexMtxImm(mtex, 0x24, 1);
    GXSetTexCoordGen2(2, 1, 1, 0x24, 0, 0x7d);
    fn_8006C5CC(&tex2);
    selectTexture((void*)tex2, 1);
    GXSetTevKAlphaSel(2, 0x1c);
    GXSetTevKColor(0, *(GXColor*)&gTrickyHudIconKColor);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 2, 1, 0xff);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 7, 4, 6, 0);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 1, 0, 0, 1, 0);
    if (((GameObject*)this)->anim.seqId == 0x755)
    {
        GXSetCullMode(1);
    }
    else
    {
        GXSetCullMode(2);
    }
    GXSetBlendMode(1, 4, 5, 5);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xa, 1);
    return 1;
}

extern int objIsCurModelNotZero(void* obj);

extern int fn_802972A8(int* player);
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int p5, int p6, int p7, int p8, int p9);
extern void hudDrawCounter(int id, int a, int b, int c, int d, int* e, int f);
extern s16 cMenuFadeCounter;
extern f32 lbl_803DD844, lbl_803DD83C;
extern const f32 gTrickyHudNearestObjMaxDist;
extern f32 lbl_803E1FA8, lbl_803E1FAC, lbl_803E1FB0, lbl_803E1FB4;
extern f32 timeDelta;

/* overlay for lbl_803A87F0; offsets verified against maybetemplate.c */
typedef struct TrickyHud
{
    u8 _pad0[0x1c0];
    void* icons[0x55];   /* 0x1c0 */
    void* icon314;       /* 0x314 */
    void* icon318;       /* 0x318 */
    void* icon31c;       /* 0x31c */
    u8 _pad320[0x348 - 0x320];
    void* icon348;       /* 0x348 */
    u8 _pad34c[0x354 - 0x34c];
    void* icon354;       /* 0x354 */
    u8 _pad358[0xACC - 0x358];
    f32 magicAnim;       /* 0xacc */
    u8 _padAD0[0xAD4 - 0xAD0];
    f32 spiritAnim;      /* 0xad4 */
    f32 healthAnim;      /* 0xad8 */
    u8 _padADC[0xAF0 - 0xADC];
    f32 keyAnim;         /* 0xaf0 */
    f32 scarabAnim;      /* 0xaf4 */
    f32 trickyAnim;      /* 0xaf8 */
    f32 magicCur;        /* 0xafc */
    f32 healthCur;       /* 0xb00 */
    u8 _padB04[0xB08 - 0xB04];
    f32 spiritCur;       /* 0xb08 */
    f32 moneyCur;        /* 0xb0c */
    f32 keyCur;          /* 0xb10 */
    u8 _padB14[0xB18 - 0xB14];
    f32 scarabCur;       /* 0xb18 */
    u8 _padB1C[0xB20 - 0xB1C];
    f32 trickyCur;       /* 0xb20 */
    f32 magicFlash;      /* 0xb24 */
    f32 scarabFlash;     /* 0xb28 */
    f32 trickyFlash;     /* 0xb2c */
    u8 _padB30[0xB74 - 0xB30];
    int magicValue;      /* 0xb74 */
    int healthValue;     /* 0xb78 */
    u8 _padB7C[0xB80 - 0xB7C];
    int moneyValue;      /* 0xb80 */
    int spiritValue;     /* 0xb84 */
    u8 _padB88[0xB90 - 0xB88];
    int magicCount;      /* 0xb90 */
    u8 _padB94[0xB98 - 0xB94];
    int scarabCount;     /* 0xb98 */
    int keyValue;        /* 0xb9c */
    int scarabValue;     /* 0xba0 */
    int trickyValue;     /* 0xba4 */
} TrickyHud;

STATIC_ASSERT(offsetof(TrickyHud, icon314) == 0x314);
STATIC_ASSERT(offsetof(TrickyHud, icon348) == 0x348);
STATIC_ASSERT(offsetof(TrickyHud, icon354) == 0x354);
STATIC_ASSERT(offsetof(TrickyHud, magicAnim) == 0xACC);
STATIC_ASSERT(offsetof(TrickyHud, magicCur) == 0xAFC);
STATIC_ASSERT(offsetof(TrickyHud, healthCur) == 0xB00);
STATIC_ASSERT(offsetof(TrickyHud, spiritCur) == 0xB08);
STATIC_ASSERT(offsetof(TrickyHud, keyCur) == 0xB10);
STATIC_ASSERT(offsetof(TrickyHud, scarabCur) == 0xB18);
STATIC_ASSERT(offsetof(TrickyHud, trickyCur) == 0xB20);
STATIC_ASSERT(offsetof(TrickyHud, trickyFlash) == 0xB2C);
STATIC_ASSERT(offsetof(TrickyHud, magicValue) == 0xB74);
STATIC_ASSERT(offsetof(TrickyHud, moneyValue) == 0xB80);
STATIC_ASSERT(offsetof(TrickyHud, magicCount) == 0xB90);
STATIC_ASSERT(offsetof(TrickyHud, scarabCount) == 0xB98);
STATIC_ASSERT(offsetof(TrickyHud, trickyValue) == 0xBA4);

void hudDrawFn_80121440(void)
{
    TrickyHud* base = (TrickyHud*)lbl_803A87F0;
    int i;
    void *tricky;
    int alpha;
    int itemTex = 0;
    int hcArg = 0;
    int krazoa = 0;
    int magicId;
    int *player;
    f32 op;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (base->magicCur >= lbl_803E1E3C || base->scarabCur >= lbl_803E1E3C ||
        base->keyCur >= lbl_803E1E3C || cMenuFadeCounter != 0)
        op = hudElementOpacity;
    else
        op = lbl_803E1E3C;
    if (op > lbl_803DD844)
    {
        f32 t = lbl_803E1FA0 * timeDelta + lbl_803DD844;
        lbl_803DD844 = t;
        if (t > hudElementOpacity) lbl_803DD844 = hudElementOpacity;
    }
    else if (op < lbl_803DD844)
    {
        f32 t = lbl_803DD844 - lbl_803E1FA0 * timeDelta;
        lbl_803DD844 = t;
        if (t < *(f32 *)&lbl_803E1E3C) lbl_803DD844 = lbl_803E1E3C;
    }
    alpha = lbl_803DD83C;
    if ((u8)alpha != 0)
    {
        int cell = coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
        if (!(base->magicCur > lbl_803E1F9C && base->magicCur < lbl_803E1FA8 &&
                ((int)base->magicCur & 8)) &&
            !(base->scarabCur > *(f32*)&lbl_803E1F9C && base->scarabCur < lbl_803E1FA8 &&
                ((int)base->scarabCur & 8)) &&
            !(cell == 0 && (void*)fn_802972A8(player) != NULL))
        {
            for (i = 0; (int)(u8)i < (base->magicCount >> 2); i++)
            {
                int b74 = base->magicValue;
                u8 sel;
                if ((int)(u8)i < (b74 >> 2)) sel = 0x16;
                else if ((int)(u8)i > (b74 >> 2)) sel = 0x12;
                else sel = (b74 & 3) + 0x12;
                drawTexture(*(void**)((u8*)&base->icons[0] + sel * 4),
                            (f32)(int)((u8)i * 0x21 + 0x1e), lbl_803E1FAC, alpha, 0x100);
            }
        }
    }
    if ((u8)alpha != 0 && objIsCurModelNotZero(player) != 0 && GameBit_Get(0xeb1) != 0)
    {
        hudDrawMagicBar(alpha, 0x100, 0);
    }
    magicId = 0;
    if (playerHasKrazoaSpirit(1, 0) != 0) krazoa = 1;
    if (GameBit_Get(0x123) != 0 || GameBit_Get(0x83b) != 0) magicId = 0x63;
    else if (GameBit_Get(0x2e8) != 0 || GameBit_Get(0x83c) != 0) magicId = 0x64;
    if ((u8)magicId != 0)
    {
        drawTexture(base->icons[(u8)magicId],
                    (f32)(int)(s16)((u8)krazoa ? 0x104 : 0x122), lbl_803E1FAC, alpha, 0x100);
    }
    if ((u8)krazoa != 0)
    {
        drawTexture(base->icon348,
                    (f32)(int)(s16)((u8)magicId ? 0x140 : 0x122), lbl_803E1FAC, alpha, 0x100);
    }
    if ((u8)alpha != 0 && tricky != NULL)
    {
        itemTex = 0x16;
        if (!(base->trickyCur > lbl_803E1F9C && base->trickyCur < lbl_803E1FA8 &&
            ((int)base->trickyCur & 8)))
        {
            drawTexture(base->icon314, *(f32*)&lbl_803E1F9C, lbl_803E1FB0, alpha, 0x100);
        }
        for (i = 0; (u8)i < 0x14u; i += 4)
        {
            int b98 = base->scarabCount;
            if ((b98 & 0xfc) == (int)(u8)i && (b98 & 2) != 0)
            {
                drawScaledTexture(base->icon31c, (f32)(int)(((u8)i * 0xf) / 4 + 0x40), lbl_803E1FB4,
                                  alpha, 0x100, 6, 0x12, 0);
                drawPartialTexture(base->icon318, (f32)(int)(((u8)i * 0xf) / 4 + 0x46), lbl_803E1FB4,
                                   alpha, 0x100, 7, 0x12, 6, 0);
            }
            else
            {
                int sel = (b98 > (int)(u8)i) ? 0x57 : 0x56;
                int yo = ((u8)i * 0xf) / 4;
                drawTexture(*(void**)((u8*)&base->icons[0] + sel * 4), (f32)(int)(yo + 0x40),
                            lbl_803E1FB4, alpha, 0x100);
            }
        }
    }
    {
        int camMode = (*gCameraInterface)->getMode();
        if (camMode < 0x49 && camMode >= 0x47)
        {
            drawTexture(base->icon354, lbl_803E1F9C,
                        (f32)(int)((s8)itemTex + 0x5f), alpha, 0x100);
        }
    }
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (gTrickyHudShowNearestInfo != 0)
    {
        int c2 = 0, c1 = 0, c0 = 0;
        f32 radius = gTrickyHudNearestObjMaxDist;
        int* near;
        near = (int*)ObjGroup_FindNearestObject(9, Obj_GetPlayerObject(), &radius);
        if (near != NULL && pauseMenuState == 0)
        {
            (*(void (*)(int*, int*, int*, int*))*(int*)((char*)*(int*)(*(int*)&((GameObject*)near)->anim.dll) + 0x54))(near, &c2, &c1, &c0);
            hcArg = 0x118;
            hudDrawCounter(0x1e, (s16)(c1 - c2), (s16)c0, 0xff, 0, &hcArg, 1);
        }
    }
    else
    {
        int style;
        if (GameBit_Get(0x91b) != 0) style = 0xc8;
        else if (GameBit_Get(0x91a) != 0) style = 0x64;
        else if (GameBit_Get(0x919) != 0) style = 0x32;
        else style = 0xa;
        hudDrawCounter(0x1e, (s16) base->moneyValue, (s16)style, (int)base->spiritAnim,
                       (int)base->spiritCur, &hcArg, 0);
        hudDrawCounter(0x19, (s16) base->spiritValue, 7, (int)base->healthAnim, (int)base->moneyCur,
                       &hcArg, 0);
        hudDrawCounter(0x1a, (s16) base->healthValue, 0xf, (int)base->magicAnim, (int)base->healthCur,
                       &hcArg, 0);
        hudDrawCounter(0x18, (s16) base->keyValue, 0x1f, (int)base->keyAnim, (int)base->magicFlash,
                       &hcArg, 0);
        hudDrawCounter(0x1b, (s16) base->scarabValue, 7, (int)base->scarabAnim, (int)base->scarabFlash,
                       &hcArg, 0);
        hudDrawCounter(0x1c, (s16) base->trickyValue, 0xff, (int)base->trickyAnim, (int)base->trickyFlash,
                       &hcArg, 0);
    }
}

extern int Camera_GetCurrentViewSlot(void);

extern int getAngle(float y, float x);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern void drawViewFinderLine(f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4, u8* color);
extern f32 fn_8029454C(f32);
extern const f64 lbl_803E1EA0, lbl_803E1EA8, lbl_803E1EB0, lbl_803E1EB8;
extern const f64 lbl_803E1EF0, lbl_803E1EF8, lbl_803E1F00, lbl_803E1F20, lbl_803E1F28;
extern const f32 lbl_803E1EC4, lbl_803E1EC8, lbl_803E1ECC, lbl_803E1ED0;
extern f32 gViewFinderFadeLevel, gViewFinderBaseY;
extern const f32 lbl_803E1ED4, lbl_803E1ED8, lbl_803E1EDC, lbl_803E1EE0, lbl_803E1EE4, lbl_803E1EE8, lbl_803E1E94;
extern const f32 lbl_803E1F08, lbl_803E1F0C, lbl_803E1F10, lbl_803E1F14, lbl_803E1F18;
extern const f32 lbl_803E1F30, lbl_803E1F34, lbl_803E1F48, lbl_803E1F4C;
extern f32 lbl_803DBAE0, lbl_803DBAE4;
extern const double lbl_803E1F38, lbl_803E1F40;
extern const f32 gViewFinderDepthMax;
extern char lbl_803DBB40;
extern const f32 gViewFinderBamToDeg, lbl_803E1F90;
extern const double lbl_803E1F50, lbl_803E1F58, lbl_803E1F60, lbl_803E1F68, lbl_803E1F78, lbl_803E1F80, lbl_803E1F88;
extern int lbl_803DBAE8;
extern char sViewFinderDirN, sViewFinderDirE, sViewFinderDirS, sViewFinderDirW, sViewFinderDirNE, sViewFinderDirSE, sViewFinderDirSW,
            sViewFinderDirNW, lbl_803DBB38;


extern int depthReadRequestPoll(int x, int y, void* fn);
extern u16 gViewFinderCamAngle;
extern int lbl_803E1E2C;
extern char sTrickyDebugXCoordFormat[];
extern void gameTextSetColor(int, int, int, int);


#define VFTICK(gA1, gA2, A, B, C, AL) do { \
    GXColor _c2; \
    GXColor _c; \
    s16 _a; \
    f32 _r, _cs, _sn, _cx, _sx, _u, _d, _bu, _bd; \
    *(int *)&_c = lbl_803E1E2C; \
    _c.a = hudElementOpacity * (AL); \
    _a = getAngle(gA1, gA2); \
    _r = lbl_803E1EC8 * _a / lbl_803E1E94; \
    _cs = mathSinf(_r); \
    _sn = mathCosf(_r); \
    _c2 = _c; \
    _cx = lbl_803E1E68 * _cs; \
    _sx = lbl_803E1E68 * _sn; \
    _u = (A) + _cx; \
    _d = (A) - _cx; \
    _bu = (B) + _sx; \
    _bd = (B) - _sx; \
    drawViewFinderLine(_bu, _d, _bd, _u, (C) - _sx, _u, (C) + _sx, _d, (u8 *)&_c2); \
} while (0)

#define VBLK(gA1, gA2, A, B, C, AL) do { \
    GXColor _c2; \
    GXColor _c; \
    s16 _a; \
    f32 _r, _cs, _sn, _cx, _sx, _d, _u, _bd, _bu; \
    *(int *)&_c = lbl_803E1E2C; \
    _c.a = hudElementOpacity * (AL); \
    _a = getAngle(gA1, gA2); \
    _r = lbl_803E1EC8 * _a / lbl_803E1E94; \
    _cs = mathSinf(_r); \
    _sn = mathCosf(_r); \
    _c2 = _c; \
    _cx = lbl_803E1E68 * _cs; \
    _sx = lbl_803E1E68 * _sn; \
    _d = (A) - _sx; \
    _u = (A) + _sx; \
    _bd = (B) - _cx; \
    _bu = (B) + _cx; \
    drawViewFinderLine(_u, _bd, _d, _bu, _d, (C) + _cx, _u, (C) - _cx, (u8 *)&_c2); \
} while (0)

#pragma opt_propagation off
void drawViewFinderHud(void)
{
    f32 fovY;
    int slot;
    f32 v;

    fovY = Camera_GetFovY();
    slot = Camera_GetCurrentViewSlot();
    if (Rcp_GetViewFinderHudEnabled() && pauseMenuState == 0)
    {
        gViewFinderFadeLevel = (f32)(lbl_803E1EA0 * timeDelta + gViewFinderFadeLevel);
    }
    else
    {
        gViewFinderFadeLevel = (f32)(gViewFinderFadeLevel - lbl_803E1EA8 * timeDelta);
    }
    v = gViewFinderFadeLevel;
    v = (v < lbl_803E1E3C)
            ? lbl_803E1E3C
            : ((v > lbl_803E1E68) ? lbl_803E1E68 : v);
    gViewFinderFadeLevel = v;
    if (v == *(f32 *)&lbl_803E1E3C) return;
    gViewFinderBaseY = (f32)(lbl_803E1EB0 - lbl_803E1EB8 * v);
    gViewFinderCamAngle = -*(s16*)slot;

    VFTICK(lbl_803E1EC4, lbl_803E1E3C, lbl_803E1ECC, lbl_803E1ED0, lbl_803E1ED4, v);
    VFTICK(lbl_803E1ED8, lbl_803E1E3C, lbl_803E1ECC, lbl_803E1EDC, lbl_803E1EE0, gViewFinderFadeLevel);
    VFTICK(lbl_803E1EC4, lbl_803E1E3C, lbl_803E1EE4, lbl_803E1ED0, lbl_803E1ED4, gViewFinderFadeLevel);
    VFTICK(lbl_803E1ED8, lbl_803E1E3C, lbl_803E1EE4, lbl_803E1EDC, lbl_803E1EE0, gViewFinderFadeLevel);
    VBLK(lbl_803E1E3C, lbl_803E1EC4, lbl_803E1ED0, lbl_803E1ECC, lbl_803E1EE8, gViewFinderFadeLevel);
    VBLK(lbl_803E1E3C, lbl_803E1ED8, lbl_803E1ED0, lbl_803E1EE4, lbl_803E1ED4, gViewFinderFadeLevel);
    VBLK(lbl_803E1E3C, lbl_803E1EC4, lbl_803E1EDC, lbl_803E1ECC, lbl_803E1EE8, gViewFinderFadeLevel);
    VBLK(lbl_803E1E3C, lbl_803E1ED8, lbl_803E1EDC, lbl_803E1EE4, lbl_803E1ED4, gViewFinderFadeLevel);

    {
        char buf[56];
        f32 f15v = (f32)(lbl_803E1EF0 * ((fovY - lbl_803E1EF8) / lbl_803E1F00) + lbl_803E1EB0);
        f32 f18v = -(lbl_803E1F0C * gViewFinderFadeLevel) + lbl_803E1F08;
        f32 f19v;
        f32 xc;
        {
            GXColor _c2;
            GXColor _c;
            s16 _a;
            f32 _r, _cs, _sn, _cx, _sx;
            *(int*)&_c = lbl_803E1E2C;
            _c.a = hudElementOpacity * gViewFinderFadeLevel;
            _a = getAngle(lbl_803E1E3C, lbl_803E1F08 - f18v);
            _r = lbl_803E1EC8 * _a / lbl_803E1E94;
            _cs = mathSinf(_r);
            _sn = mathCosf(_r);
            _c2 = _c;
            _cx = lbl_803E1E68 * _cs;
            _sx = lbl_803E1E68 * _sn;
            drawViewFinderLine(lbl_803E1F10 + _sx, f18v - _cx, lbl_803E1F10 - _sx, f18v + _cx,
                               lbl_803E1F10 - _sx, lbl_803E1F08 + _cx, lbl_803E1F10 + _sx, lbl_803E1F08 - _cx, (u8*)&_c2);
        }
        {
            GXColor _c2;
            GXColor _c;
            s16 _a;
            f32 _r, _cs, _sn, _cx, _sx;
            *(int*)&_c = lbl_803E1E2C;
            _c.a = hudElementOpacity * gViewFinderFadeLevel;
            _a = getAngle(lbl_803E1E3C, (f19v = lbl_803E1F14 + f15v) - f15v);
            _r = lbl_803E1EC8 * _a / lbl_803E1E94;
            _cs = mathSinf(_r);
            _sn = mathCosf(_r);
            _c2 = _c;
            _cx = lbl_803E1F18 * _cs;
            _sx = lbl_803E1F18 * _sn;
            drawViewFinderLine(lbl_803E1F10 + _sx, f15v - _cx, lbl_803E1F10 - _sx, f15v + _cx,
                               lbl_803E1F10 - _sx, f19v + _cx, lbl_803E1F10 + _sx, f19v - _cx, (u8*)&_c2);
        }
        xc = lbl_803E1F20 / fn_8029454C((f32)(lbl_803E1EC8 * fovY / lbl_803E1F28));
        xc = xc;
        sprintf(buf, sTrickyDebugXCoordFormat, xc);
        gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * gViewFinderFadeLevel));
        gameTextShowStr(buf, 0x93, 0x21c, 0x46);

        {
            f32 f31, f30, f29, fdx, f27;
            f32 kE68;
            f64 kF40;
            f32 kF48;
            f64 kF38;
            f32 kE94, kEC4, kF34, kEC8, kF30;
            f64 kOpac, kF4C;
            f27 = lbl_803E1E3C;
            kF30 = lbl_803E1F30;
            kEC8 = lbl_803E1EC8;
            kF34 = lbl_803E1F34;
            kEC4 = lbl_803E1EC4;
            kE94 = lbl_803E1E94;
            kF38 = lbl_803E1F38;
            kE68 = lbl_803E1E68;
            kF40 = lbl_803E1F40;
            kOpac = hudElementOpacity;
            kF48 = lbl_803E1F48;
            kF4C = lbl_803E1F4C;
            for (; f27 < kF4C; f27 += kEC4)
            {
                {
                    GXColor _c2;
                    GXColor _c;
                    s16 _a;
                    f32 _r, _cs, _sn, _cx, _sx;
                    f32 f16, f15;
                    u8 alpha = kF30 * gViewFinderFadeLevel;
                    f31 = kEC4 + f27;
                    f30 = kF34 - f31;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f15 = (f32)(gViewFinderBaseY + (kF38 + _sn));
                    f29 = kF34 - f27;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f16 = (f32)(gViewFinderBaseY + (kF38 + _sn));
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    fdx = f31 - f27;
                    _a = getAngle(fdx, f15 - f16);
                    _r = kEC8 * _a / kE94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine(f27 + _sx, f16 - _cx, f27 - _sx, f16 + _cx, f31 - _sx, f15 + _cx,
                                       f31 + _sx, f15 - _cx, (u8*)&_c2);
                }
                {
                    GXColor _c2;
                    GXColor _c;
                    s16 _a;
                    f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = kF30 * gViewFinderFadeLevel;
                    f32 f15, f16;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f16 = (f32)(gViewFinderBaseY + (kF40 + _sn));
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f15 = (f32)(gViewFinderBaseY + (kF40 + _sn));
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    _a = getAngle(fdx, f16 - f15);
                    _r = kEC8 * _a / kE94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine(f27 + _sx, f15 - _cx, f27 - _sx, f15 + _cx, f31 - _sx, f16 + _cx,
                                       f31 + _sx, f16 - _cx, (u8*)&_c2);
                }
                {
                    GXColor _c2;
                    GXColor _c;
                    s16 _a;
                    f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = (f32)kOpac * gViewFinderFadeLevel;
                    f32 f15, f16;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f16 = gViewFinderBaseY + (kF48 + _sn);
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f15 = gViewFinderBaseY + (kF48 + _sn);
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    _a = getAngle(fdx, f16 - f15);
                    _r = kEC8 * _a / kE94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine(f27 + _sx, f15 - _cx, f27 - _sx, f15 + _cx, f31 - _sx, f16 + _cx,
                                       f31 + _sx, f16 - _cx, (u8*)&_c2);
                }
            }
        }
        {
            int r30v, r29v, r5v, r28v;
            int t;
            f32 f18, f19, num;
            t = (int)((xc - lbl_803E1F50) * lbl_803E1F58);
            r30v = (t < 0) ? 0 : ((t > 0x8c) ? 0x8c : t);
            t = (int)((xc - lbl_803E1F60) * lbl_803E1F68);
            r29v = (t < 0) ? 0 : ((t > 0xc8) ? 0xc8 : t);
            r5v = (int)((f32)gViewFinderCamAngle / gViewFinderBamToDeg);
            num = gViewFinderCamAngle - r5v * gViewFinderBamToDeg;
            f19 = xc * (gViewFinderBamToDeg / lbl_803DBAE8);
            f18 = (f32)(lbl_803E1F78 + (num / lbl_803DBAE8) * xc);
            r28v = -r5v;
            while (f18 > lbl_803E1E3C)
            {
                f18 -= f19;
                r28v--;
            }
            f18 += f19;
            r28v++;
            if (r28v < 0) r28v += 0x168;
            for (; f18 < lbl_803E1F4C; f18 += f19)
            {
                u8 r27v = 0xff;
                int r26v = 0xff;
                int r25v = 0xf;
                f64 q;
                if (r28v >= 0x168) r28v -= 0x168;
                q = r28v / lbl_803E1F80;
                if (q != (int)q)
                {
                    r26v = 0xc8;
                    q = r28v / lbl_803E1EF8;
                    if (q != (int)q)
                    {
                        r27v = r30v;
                        r25v = 7;
                    }
                    else
                    {
                        r27v = r29v;
                        r25v = 0xa;
                    }
                }
                switch (r28v)
                {
                case 0: sprintf(buf, &sViewFinderDirN, r28v);
                    break;
                case 0x5a: sprintf(buf, &sViewFinderDirE, r28v);
                    break;
                case 0xb4: sprintf(buf, &sViewFinderDirS, r28v);
                    break;
                case 0x10e: sprintf(buf, &sViewFinderDirW, r28v);
                    break;
                case 0x2d: sprintf(buf, &sViewFinderDirNE, r28v);
                    break;
                case 0x87: sprintf(buf, &sViewFinderDirSE, r28v);
                    break;
                case 0xe1: sprintf(buf, &sViewFinderDirSW, r28v);
                    break;
                case 0x13b: sprintf(buf, &sViewFinderDirNW, r28v);
                    break;
                default: sprintf(buf, &lbl_803DBB38, r28v);
                    break;
                }
                r28v++;
                if ((u8)r27v != 0)
                {
                    f32 sn;
                    gameTextSetColor(0, 0xff, 0, (int)((f32)(u8)r27v * gViewFinderFadeLevel)
                    )
                    ;
                    sn = lbl_803DBAE4 * mathCosf(lbl_803E1EC8 * ((lbl_803E1F34 - f18) * lbl_803DBAE0) / lbl_803E1E94);
                    gameTextShowStr(buf, 0x93,
                                    (int)(lbl_803E1F88 * (f18 - lbl_803E1F78) + lbl_803E1F78),
                                    (int)(gViewFinderBaseY + (lbl_803E1F90 + sn)));
                }
                {
                    GXColor _c2;
                    GXColor _c;
                    s16 _a;
                    f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = (f32)(u8)r26v *gViewFinderFadeLevel;
                    f32 f15 = lbl_803E1F34 - f18;
                    f32 f16;
                    f64 fx;
                    _sn = lbl_803DBAE4 * mathCosf(lbl_803E1EC8 * (f15 * lbl_803DBAE0) / lbl_803E1E94);
                    f16 = gViewFinderBaseY + ((f32)((u8)r25v + 0x1e0) + _sn);
                    _sn = lbl_803DBAE4 * mathCosf(lbl_803E1EC8 * (f15 * lbl_803DBAE0) / lbl_803E1E94);
                    f15 = gViewFinderBaseY + (lbl_803E1F48 + _sn);
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    fx = lbl_803E1F88 * (f18 - lbl_803E1F78) + lbl_803E1F78;
                    _a = getAngle((f32)fx - f18, f16 - f15);
                    _r = lbl_803E1EC8 * _a / lbl_803E1E94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = lbl_803E1E68 * _cs;
                    _sx = lbl_803E1E68 * _sn;
                    drawViewFinderLine(f18 + _sx, f15 - _cx, f18 - _sx, f15 + _cx, (f32)fx - _sx, f16 + _cx,
                                       (f32)fx + _sx, f16 - _cx, (u8*)&_c2);
                }
            }
        }
        {
            f32 farP = Camera_GetFarPlane();
            f32 nearP = Camera_GetNearPlane();
            int depth = depthReadRequestPoll(0x140, 0xf0, drawViewFinderHud);
            f32 dist = (-farP * nearP) / (((f32)(u32)
            depth / gViewFinderDepthMax - lbl_803E1E68
            )
            *(farP - nearP) - nearP
            )
            ;
            if (dist > lbl_803E1E3C && dist < gTrickyHudNearestObjMaxDist)
            {
                sprintf(buf, &lbl_803DBB40, dist / lbl_803E1EC4);
                gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * gViewFinderFadeLevel));
                gameTextShowStr(buf, 0x93, 0x32, 0x46);
            }
        }
    }
}
#pragma opt_propagation reset
