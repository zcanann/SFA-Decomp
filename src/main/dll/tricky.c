#include "main/dll/ppcwgpipe_struct.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/camera_interface.h"
#include "main/mapEventTypes.h"
#include "main/texture.h"

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

extern undefined4 FUN_80017488();
extern undefined4 FUN_80017498();
extern int ObjGroup_FindNearestObject();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern int playerHasKrazoaSpirit();
extern undefined4 hudDrawMagicBar();
extern undefined8 FUN_8012c894();
extern undefined4 GXSetBlendMode();

extern undefined4 DAT_803dc084;
extern undefined4 DAT_803de3ee;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de412;
extern undefined4 DAT_803de42a;
extern undefined4 DAT_803de42c;
extern undefined4 DAT_803de458;
extern undefined4 DAT_803de55c;
extern f32 lbl_803DE3E4;
extern f32 gViewFinderFadeLevel; /* ramped/clamped fade for the viewfinder HUD; the drift
 * import wrongly referenced 803DE4C4 here - target asm shows 803DD7F0 */
extern f32 lbl_803E2AE0;

extern u8 gameUiResourcesLoaded;
extern char lbl_803A87F0[];
extern char* lbl_803DD85C;
extern char* lbl_803DD860[];
extern char* lbl_803DD868[];
extern int lbl_8031BF90[];
extern const f32 lbl_803E1E3C;
extern f32 lbl_803E1E40, lbl_803E1E44, lbl_803E1E48, lbl_803E1E4C;
extern f32 lbl_803E1E50, lbl_803E1E54, lbl_803E1E58, lbl_803E1E5C;
extern char* Obj_AllocObjectSetup(int size, int id);
extern char* Obj_SetupObject(char* obj, int a, int b, int c, int d);
extern void* Obj_GetActiveModel(char* obj);
extern void ObjModel_SetRenderCallback(void* model, void* cb);
extern u8 modelFn_80124794[];
extern u8 cMenuRenderFn_80124854[];
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
        f32 ga, gb;

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
            ((GameObject*)(*arrA))->anim.rotX = (s16)val;
            *(s8*)(*arrA + 0xad) = (s8)i;
            ObjModel_SetRenderCallback(Obj_GetActiveModel(*arrA), modelFn_80124794);
            *arrB = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x65f), 4, -1, -1, 0);
            ((GameObject*)(*arrB))->anim.localPosX = fa;
            ((GameObject*)(*arrB))->anim.localPosY = fb;
            ((GameObject*)(*arrB))->anim.localPosZ = fc;
            ((GameObject*)(*arrB))->anim.rotX = (s16)val;
            ObjModel_SetRenderCallback(Obj_GetActiveModel(*arrB), cMenuRenderFn_80124854);
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
void FUN_8011daf8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    int iVar1;
    double extraout_f1;
    undefined8 uVar2;

    iVar1 = (int)(*gMapEventInterface)->getCurCharacterState();
    uVar2 = FUN_8012c894(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    if (*(char*)(iVar1 + 9) == '\0')
    {
        if (DAT_803dc084 == '\0')
        {
            DAT_803de400 = 10;
        }
        else
        {
            DAT_803de400 = 9;
        }
    }
    else
    {
        DAT_803de400 = 8;
    }
    DAT_803de55c = FUN_80017498();
    FUN_80017488(uVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
    lbl_803DE3E4 = lbl_803E2AE0;
    DAT_803de458 = 1;
    return;
}

void FUN_8011e460(double param_1, double param_2, int param_3, int param_4, undefined param_5,
                  uint param_6, byte param_7)
{
}

void FUN_8011e7ac(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
}

void FUN_8011e800(undefined param_1)
{
    DAT_803de412 = param_1;
    return;
}

void FUN_8011e844(undefined param_1)
{
    if (DAT_803de42c != '\0')
    {
        return;
    }
    DAT_803de42c = param_1;
    return;
}

void FUN_8011e868(undefined2 param_1)
{
    if (DAT_803de42a != 0)
    {
        return;
    }
    DAT_803de42a = param_1;
    return;
}

void FUN_8011eb10(ushort param_1)
{
    DAT_803de3ee = param_1 & 0xff;
    return;
}

extern u8 pauseMenuState;
extern u8 lbl_803DD7B3;
extern u8 lbl_803DD792;
extern u8 lbl_803DD75A;
extern u8 lbl_803DBA88;
u8 pauseMenuGetState(void) { return pauseMenuState; }
void fn_8011F34C(u8 x) { lbl_803DD7B3 = x; }
void hudFn_8011f38c(u8 x) { lbl_803DD792 = x; }
void hudFn_8011f6f0(u8 x) { lbl_803DD75A = x; }
void GameUI_func0E(u8 x) { lbl_803DBA88 = x; }

extern s16 lbl_803DD76E;

void fn_8011F6D4(u32 x)
{
    lbl_803DD76E = (s16)(u8)
    x;
}

extern s16 aButtonIcon;
#pragma scheduling off
#pragma peephole off
void forceAButtonIcon(int x)
{
    aButtonIcon = (s16)x;
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
        bButtonIcon = (u8)x;
    }
}

void setAButtonIcon(int x)
{
    if (aButtonIcon == 0)
    {
        aButtonIcon = (s16)x;
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

extern void cutsceneFadeInOut(int x);
extern void setTimeStop(int x);
extern void pauseMenuInit(void);
extern int getCurGameText(void);
extern void gameTextLoadDir(int x);
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

extern int lbl_803DD8A0;
extern s16 lbl_803DD89E;
extern s16 lbl_803DD89C;
extern u8 lbl_803DD8AC;

void GameUI_setInputOverride(int x, s16 a, s16 b)
{
    if (x == -1)
    {
        lbl_803DD8A0 = 0;
        lbl_803DD89E = 0;
        lbl_803DD89C = 0;
        lbl_803DD8AC = 0;
        return;
    }
    lbl_803DD8A0 = x;
    lbl_803DD89E = a;
    lbl_803DD89C = b;
    lbl_803DD8AC = 1;
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
    arwingHudAlpha = (s16)0xff;
}

extern u16 yButtonItem;
#pragma scheduling on
u16 getYButtonItem(s16* out)
{
    s32 t;
    if (yButtonState != 0)
    {
        t = (s16)yButtonItem;
        *out = (s16)t;
    }
    return yButtonState;
}

/* GameUI_airMeterSetShutdown: set bit 7 of (*p)+0x44 if p non-null -- uses bitfield insert (rlwimi) */
typedef struct
{
    char pad[0x44];
    u8 bit7 : 1;
    u8 bits_0to6 : 7;
} _Obj8011F70C;
#pragma scheduling off
void GameUI_airMeterSetShutdown(void)
{
    _Obj8011F70C* p = (_Obj8011F70C*)airMeter;
    if (p == 0) return;
    p->bit7 = 1;
}

extern int lbl_803A9398[];
extern void mm_free(void* p);
#pragma dont_inline on
void GameUI_airMeterShutdown(void)
{
    int* m = (int*)airMeter;
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

extern void* mmAlloc(int size, int type, int x);
extern void* memset(void* p, int v, int n);
extern const f32 lbl_803E1E68;

void GameUI_initAirMeter(int a, int b)
{
    int* m;
    if (airMeter == NULL)
    {
    }
    else if ((((_Obj8011F70C*)airMeter)->bit7) != 0)
    {
        GameUI_airMeterShutdown();
    }
    else
    {
        return;
    }
    m = (int*)mmAlloc(0x48, 0x19, 0);
    memset(m, 0, 0x48);
    m[0] = 0;
    m[1] = a;
    m[2] = 0;
    m[0xc] = (int)textureLoadAsset(b);
    ((TrickyAirMeter*)m)->unk2C = (u16)b;
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
    int* r = (int*)mapEvents->getCurCharacterState();
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
    ((GameUIWork10*)lbl_803A9398)->unkC = (s16)c;
    ((GameUIWork10*)lbl_803A9398)->unk8 = lbl_803E1E3C;
}

void GameUI_airMeterRun(int v)
{
    int* m = (int*)airMeter;
    int clamped;
    if (m == NULL) return;
    clamped = (v < 0) ? 0 : ((v > m[1]) ? m[1] : v);
    v = clamped;
    if (m[0x10] == 1)
    {
        v = clamped * 0x9e / m[1];
    }
    m[3] = v;
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
    cMenuEnabled = 0;
    curGameText = 0xffff;
    lbl_803DD8D0 = 0;
    lbl_803DD7A8 = 0;
    GameUI_airMeterShutdown();
    pauseMenuState = 0;
    lbl_803DD778 = 0;
    lbl_803DD730 = 0;
    lbl_803DD770 = 0;
    lbl_803DD760 = lbl_803E1E3C;
    {
        int** arr = (int**)lbl_803A9410;
        int j;
        for (j = 0; j < 4; j++)
        {
            if (arr[j] != NULL)
            {
                ((int*)arr[j][0x19])[1] = 0;
                ((int*)arr[j][0x19])[2] = 0;
                if ((u32)arr[j][0x13] > 0x90000000) arr[j][0x13] = 0;
                Obj_FreeObject(arr[j]);
                arr[j] = NULL;
            }
        }
    }
    lbl_803DD75A = 0;
    lbl_803DD75B = 0;
    lbl_803DD772 = 0;
    pauseMenuFrameCounter = 0x3c;
    lbl_803DD792 = 0;
}

void GameUI_airMeterInitType0(int a, int b, int c)
{
    int* m;
    if (airMeter != NULL) return;
    m = (int*)mmAlloc(0x48, 0x19, 0);
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

extern int lbl_8031B5D8[];

void GameUI_func14(s16 a, int b, int c)
{
    int* entry = lbl_8031B5D8;
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
        ((GameUIWork10*)lbl_803A9398)->unkC = (s16)c;
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
extern void pauseMenuMapFn_8011de20(void *this, int a, s16 b, int c);

void pauseMenuDrawElement(void *this, f32 fx, f32 fy, int p4, int p5, int p6, int p7)
{
    int dx, dy;
    f32 c0, c1;
    pauseMenuMapFn_8011de20(this, p5, (s16)p4, p7 & 4);
    dx = (*(u16*)((char*)this + 0xa) << 2) * (u16)p6 / 256;
    dy = (*(u16*)((char*)this + 0xc) << 2) * (u16)p6 / 256;
    fx = lbl_803E1E80 * fx;
    fy = lbl_803E1E80 * fy;
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)fx;
    GXWGFifo.s16 = (s16)fy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    c0 = lbl_803E1E3C;
    GXWGFifo.f32 = c0;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)fy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    c1 = lbl_803E1E68;
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c1;
    GXWGFifo.s16 = (s16)fx;
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
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
extern void GXSetCurrentMtx(int id);
extern void GXSetNumTexGens(int n);
extern void GXSetNumIndStages(int n);
extern void GXSetNumChans(int n);
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
extern void GXSetNumTevStages(int n);
extern void GXSetCullMode(int m);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int a, int b);
extern int lbl_803E1E34;
extern int lbl_803E1E38;
extern char lbl_803A8830[];

void pauseMenuMapFn_8011de20(void *this, int a, s16 b, int c)
{
    GXColor colA = *(GXColor*)&lbl_803E1E34;
    GXColor colB = *(GXColor*)&lbl_803E1E38;
    colA.a = (u8)a;
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

extern s16 lbl_803DBA8A;
extern f32 lbl_803DBA8C;

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

void drawFn_8011e8d8(void *this, f32 f1, f32 f2, int p4, int p5, int p6, int p7, int p8, int p9)
{
    f32 u1, u0, v0, sy, sx, v1;
    u32 w, h;
    pauseMenuMapFn_8011de20(this, p5, (s16)p4, 0);
    sx = lbl_803E1E80 * f1;
    sy = lbl_803E1E80 * f2;
    w = *(u16*)((char*)this + 0xa);
    h = *(u16*)((char*)this + 0xc);
    u0 = (f32)(u32)
    p8 / (f32)w;
    v0 = (f32)(u32)
    p9 / (f32)h;
    u1 = (f32)(u32)(p6 + p8) / (f32)w;
    v1 = (f32)(u32)(p7 + p9) / (f32)h;
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
}

void drawFn_8011eb3c(void *this, f32 f1, f32 f2, int p4, int p5, int p6, int p7, int p8, int p9)
{
    f32 ua, ub, va, vb, tu, tv;
    u32 dx, dy;
    u8 flags = (u8)p9;
    pauseMenuMapFn_8011de20(this, p5, (s16)p4, flags & 4);
    dx = ((u32)(p7 << 2) * (u16)p6) >> 8;
    dy = ((u32)(p8 << 2) * (u16)p6) >> 8;
    f1 = lbl_803E1E80 * f1;
    f2 = lbl_803E1E80 * f2;
    tu = (f32)(u32)
    p7 / (f32)(u32) * (u16*)((char*)this + 0xa);
    tv = (f32)(u32)
    p8 / (f32)(u32) * (u16*)((char*)this + 0xc);
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
    GXWGFifo.s16 = (s16)f1;
    GXWGFifo.s16 = (s16)f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ua;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)(f2 + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = vb;
    GXWGFifo.s16 = (s16)f1;
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
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32);
extern void Camera_RebuildProjectionMatrix(void);
extern void Camera_SetCurrentViewIndex(s32);
extern void Camera_SetCurrentViewPosition(f32, f32, f32);
extern void Camera_SetCurrentViewRotation(s32, s32, s32);
extern void Camera_UpdateViewMatrices(void);
extern f32 lbl_803DD818, lbl_803DD814, lbl_803DD810, lbl_803DD80C;
extern f32 lbl_803DD808, lbl_803DD804, lbl_803DD800, lbl_803DD7FC;
extern const f32 lbl_803E1E94;
extern f32 lbl_803E1E90, lbl_803E1E98;
extern f32 lbl_803DBB04, lbl_803DBB08, lbl_803DBB0C;
extern f32 lbl_803DBAF4, lbl_803DBAF8, lbl_803DBAFC, lbl_803DBB00;

#pragma opt_propagation off
void fn_8011EF50(u16 a, u16 b, u16 c, f32 f1, f32 f2, f32 f3, f32 f4)
{
    char* base = lbl_803A87F0;
    f32 mA[12];
    f32 mB[12];
    lbl_803DD818 = f1;
    lbl_803DD814 = f2;
    lbl_803DD810 = f3;
    lbl_803DD80C = f4;
    lbl_803DD808 = lbl_803E1E90 * (f32)(u32)
    a / lbl_803E1E94;
    lbl_803DD804 = lbl_803E1E90 * (f32)(u32)
    b / lbl_803E1E94;
    lbl_803DD800 = lbl_803E1E90 * (f32)(u32)
    c / lbl_803E1E94;
    PSMTXRotRad(mA, 0x79, lbl_803DD800);
    PSMTXRotRad(mB, 0x78, lbl_803DD804);
    PSMTXConcat(mB, mA, mA);
    PSMTXRotRad(mB, 0x7a, lbl_803DD808);
    PSMTXConcat(mB, mA, mA);
    PSMTXScale(mB, lbl_803DD80C, lbl_803DD80C, lbl_803DD80C);
    PSMTXConcat(mB, mA, mA);
    PSMTXTrans(mB, lbl_803DD818, lbl_803DD814, lbl_803DD810);
    PSMTXConcat(mB, mA, (f32*)(base + 0x160));
    PSMTXScale(mA, lbl_803DBB04, -lbl_803DBB08, lbl_803DBB0C);
    PSMTXTrans(mB, lbl_803E1E98, lbl_803E1E68, lbl_803E1E3C);
    PSMTXConcat(mB, mA, mB);
    PSMTXConcat((f32*)(base + 0x160), mB, (f32*)(base + 0x40));
    C_MTXPerspective((f32*)base, lbl_803DBAF4, lbl_803DBAF8, lbl_803DBAFC, lbl_803DBB00);
    lbl_803DD7FC = Camera_GetFovY();
    Camera_SetFovY(lbl_803DBAF4);
    Camera_RebuildProjectionMatrix();
    Camera_SetCurrentViewIndex(1);
    Camera_SetCurrentViewPosition(lbl_803E1E3C, lbl_803E1E3C, lbl_803E1E3C);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    ((GameObject*)lbl_803DD860[0])->anim.localPosX = lbl_803DD818;
    ((GameObject*)lbl_803DD860[0])->anim.localPosY = lbl_803DD814;
    ((GameObject*)lbl_803DD860[0])->anim.localPosZ = lbl_803DD810;
    ((GameObject*)lbl_803DD860[0])->anim.worldPosX = lbl_803DD818;
    ((GameObject*)lbl_803DD860[0])->anim.worldPosY = lbl_803DD814;
    ((GameObject*)lbl_803DD860[0])->anim.worldPosZ = lbl_803DD810;
    *(f32*)(lbl_803DD860[0] + 0x8) = f4;
    ((GameObject*)lbl_803DD860[0])->anim.rotZ = (s16)a;
    ((GameObject*)lbl_803DD860[0])->anim.rotY = (s16)b;
    ((GameObject*)lbl_803DD860[0])->anim.rotX = (s16)c;
    ((GameObject*)lbl_803DD860[1])->anim.localPosX = lbl_803DD818;
    ((GameObject*)lbl_803DD860[1])->anim.localPosY = lbl_803DD814;
    ((GameObject*)lbl_803DD860[1])->anim.localPosZ = lbl_803DD810;
    ((GameObject*)lbl_803DD860[1])->anim.worldPosX = lbl_803DD818;
    ((GameObject*)lbl_803DD860[1])->anim.worldPosY = lbl_803DD814;
    ((GameObject*)lbl_803DD860[1])->anim.worldPosZ = lbl_803DD810;
    *(f32*)(lbl_803DD860[1] + 0x8) = f4;
    ((GameObject*)lbl_803DD860[1])->anim.rotZ = (s16)a;
    ((GameObject*)lbl_803DD860[1])->anim.rotY = (s16)b;
    ((GameObject*)lbl_803DD860[1])->anim.rotX = (s16)c;
}
#pragma opt_propagation reset

extern char hudTextures[];
extern s16 lbl_803DD76C;
extern u8 lbl_803DBAF0;
extern f32 lbl_803E1E9C;
extern u8 lbl_803DBAEE;
extern u8 lbl_803DBAEF;
extern void drawScaledTexture(void* tex, f32 x, f32 y, int alpha, int p5, int p6, int p7, int p8);
extern void GXGetScissor(int* a, int* b, int* c, int* d);
extern void GXSetScissor(int a, int b, int c, int d);
extern void hudDrawRect(int x0, int y0, int x1, int y1, GXColor col);

void fearTestMeterDraw(void)
{
    GXColor col;
    int sc0, sc1, sc2, sc3;
    void* texB = *(void**)(hudTextures + 0x180);
    u16 hgt = ((Texture*)texB)->height;
    int gap = (u8)fearTestMeterOuterHalfWidth - (u8)fearTestMeterInnerHalfWidth;
    void* texA = *(void**)(hudTextures + 0x17c);
    int wid = (u8)((Texture*)texA)->width;
    if (lbl_803DD76E != 0)
    {
        lbl_803DD76C = lbl_803DD76C + lbl_803DBAF0 * framesThisStep;
    }
    else
    {
        lbl_803DD76C = lbl_803DD76C - lbl_803DBAF0 * framesThisStep;
    }
    if (lbl_803DD76C < 0)
    {
        lbl_803DD76C = 0;
    }
    else if (lbl_803DD76C > 0xff)
    {
        lbl_803DD76C = 0xff;
    }
    if (lbl_803DD76C == 0) return;
    GXGetScissor(&sc0, &sc1, &sc2, &sc3);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    drawScaledTexture(*(void**)(hudTextures + 0x17c),
                      (f32)(int)(0x140 - (u8)fearTestMeterOuterHalfWidth - wid), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, wid, hgt, 1);
    drawScaledTexture(*(void**)(hudTextures + 0x180),
                      (f32)(int)(0x140 - (u8)fearTestMeterInnerHalfWidth), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, (u8)fearTestMeterInnerHalfWidth << 1, hgt, 0);
    drawScaledTexture(*(void**)(hudTextures + 0x184),
                      (f32)(int)(0x140 - (u8)fearTestMeterOuterHalfWidth), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, gap, hgt, 0);
    drawScaledTexture(*(void**)(hudTextures + 0x184),
                      (f32)(int)((u8)fearTestMeterInnerHalfWidth + 0x140), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, gap, hgt, 0);
    drawTexture(*(void**)(hudTextures + 0x17c),
                (f32)(int)((u8)fearTestMeterOuterHalfWidth + 0x140), lbl_803E1E9C,
                (u8)lbl_803DD76C, 0x100);
    col.r = 0xff;
    col.g = 0;
    col.b = 0;
    col.a = (u8)lbl_803DD76C;
    {
        int half = (u8)lbl_803DBAEF;
        hudDrawRect((fearTestMeterMarkerX + 0x140) - half,
                    (u8)lbl_803DBAEE + 0x32,
                    half + (fearTestMeterMarkerX + 0x140),
                    (hgt + 0x32) - (u8)lbl_803DBAEE,
                    col);
    }
    GXSetScissor(sc0, sc1, sc2, sc3);
}

extern int* Obj_GetPlayerObject(void);
extern int getHudHiddenFrameCount(void);
extern s8 lbl_803DBAEC;
extern u8 lbl_803DBAED;
extern s8 lbl_803DD7F8;
extern s8 lbl_803DD7F9;

void hudDrawAirMeter(void)
{
    int sc0, sc1, sc2, sc3;
    int* player = Obj_GetPlayerObject();
    int* m = (int*)airMeter;
    _Obj8011F70C* p = (_Obj8011F70C*)airMeter;
    s16 alpha;
    s16 clamped;
    if (m == NULL) return;
    alpha = ((TrickyAirMeter*)m)->unk18;
    if (p->bit7 || pauseMenuState != 0 || getHudHiddenFrameCount() != 0 ||
        (player != NULL && (((GameObject*)player)->objectFlags & 0x1000) != 0 &&
            ((TrickyAirMeter*)m)->unk2C != 0x5d5))
    {
        alpha = (s16)(alpha - (framesThisStep << 2));
        clamped = (alpha < 0) ? 0 : alpha;
        ((TrickyAirMeter*)m)->unk18 = (u8)clamped;
        if (((TrickyAirMeter*)m)->unk18 == 0 && p->bit7)
        {
            p->bit7 = 0;
            GameUI_airMeterShutdown();
            return;
        }
    }
    else
    {
        alpha = (s16)(alpha + (framesThisStep << 2));
        clamped = (alpha > 0xff) ? 0xff : alpha;
        ((TrickyAirMeter*)m)->unk18 = (u8)clamped;
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
                void* tex = (i < m[3]) ? (void*)m[0xb] : (void*)m[0xc];
                drawTexture(tex, (f32)(int)x, (f32)(u32)(0x1a4 - m[5]),
                            ((TrickyAirMeter*)m)->unk18, 0x100);
                x += m[4];
            }
            break;
        }
    case 1:
        {
            int off;
            int by;
            int cy;
            int clampedC;
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
                int base = (0x1a4 - (*(u16*)((char*)m[0xc] + 0xc) >> 1)) + lbl_803DBAEC;
                drawTexture((void*)m[0xc], (f32)(int)(lbl_803DD7F9 + 0xb5),
                            (f32)(int)(base + ((s8)off + lbl_803DD7F8)),
                            ((TrickyAirMeter*)m)->unk18, 0x100);
            }
            by = *(u16*)((char*)m[0xc] + 0xa) + 0xb4;
            cy = 0x1a4 - (*(u16*)((char*)m[0xd] + 0xc) >> 1);
            if (m[2] < 0x9e)
            {
                m[2] = m[2] + framesThisStep * lbl_803DBAED;
            }
            clampedC = (m[3] < 0) ? 0 : ((m[3] > m[2]) ? m[2] : m[3]);
            m[3] = clampedC;
            clampedC = (s16)clampedC;
            drawScaledTexture((void*)m[0xf], (f32)(int)(by + clampedC), (f32)(int)cy,
                              ((TrickyAirMeter*)m)->unk18, 0x100, m[2] - clampedC, 0x1a, 0);
            drawScaledTexture((void*)m[0xe], (f32)(int)by, (f32)(int)cy,
                              ((TrickyAirMeter*)m)->unk18, 0x100, clampedC, 0x1a, 0);
            drawTexture((void*)m[0xd], (f32)(int)(by + m[2]),
                        (f32)(int)(0x1a4 - (*(u16*)((char*)m[0xd] + 0xc) >> 1)),
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
extern void* Shader_getLayer(void* op, int idx);
extern void* textureIdxToPtr(int idx);
extern void selectTexture(void* tex, int x);
extern void fn_8006C5CC(int* out);
extern int lbl_803E1E30;
extern int lbl_802C21AC[];
extern f32 lbl_803A8950[];
extern f32 lbl_803E1E64, lbl_803E1E6C, lbl_803E1E70;
extern f32 lbl_803DD850;
extern f32 lbl_80396820[];
extern f32 lbl_803DBB14;
extern int lbl_803DBB10;

typedef struct
{
    int w[6];
} _IndMtx;

int fn_8011E0D8(int *this, int *p2, int p3)
{
    f32 m1[12];
    f32 m2[12];
    f32 m3[12];
    f32 mtex[12];
    _IndMtx indmtx;
    GXColor chanCol;
    int kcolor;
    int tex2;
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
    PSMTXScale(m2, lbl_803E1E64 / lbl_803DD80C, lbl_803E1E64 / lbl_803DD80C, lbl_803E1E68 / lbl_803DD80C);
    m2[2] = lbl_803E1E6C / lbl_803DD80C;
    m2[6] = lbl_803E1E6C / lbl_803DD80C;
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
    GXSetTexCoordGen2(1, 1, 0, 0x21, 0, 0x7d);
    GXSetTevOrder(1, 1, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    mtex[0] = lbl_803DBB14;
    mtex[1] = lbl_803E1E3C;
    mtex[2] = lbl_803E1E3C;
    mtex[3] = lbl_803E1E70;
    mtex[4] = lbl_803E1E3C;
    mtex[5] = lbl_803DBB14;
    mtex[6] = lbl_803E1E3C;
    mtex[7] = lbl_803E1E70;
    mtex[8] = lbl_803E1E3C;
    mtex[9] = lbl_803E1E3C;
    mtex[10] = lbl_803E1E3C;
    mtex[11] = lbl_803E1E68;
    GXLoadTexMtxImm(mtex, 0x24, 1);
    GXSetTexCoordGen2(2, 1, 1, 0x24, 0, 0x7d);
    fn_8006C5CC(&tex2);
    selectTexture((void*)tex2, 1);
    GXSetTevKAlphaSel(2, 0x1c);
    kcolor = lbl_803DBB10;
    GXSetTevKColor(0, *(GXColor*)&kcolor);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 2, 1, 0xff);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 7, 4, 6, 0);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 1, 0, 0, 1, 0);
    if (*(s16*)((char*)this + 0x46) == 0x755)
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

extern void* getTrickyObject(void);
extern int objIsCurModelNotZero(int* obj);
extern int coordsToMapCell(f32 x, f32 z);
extern int fn_802972A8(int* player);
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int p5, int p6, int p7, int p8, int p9);
extern void hudDrawCounter(int id, int a, int b, int c, int d, int* e, int f);
extern s16 cMenuFadeCounter;
extern f32 lbl_803DD844, lbl_803DD83C;
extern const f32 lbl_803E1F98;
extern f32 lbl_803E1FA8, lbl_803E1FAC, lbl_803E1FB0, lbl_803E1FB4;
extern f32 timeDelta;

/* File-local overlay for the pause/status HUD block at lbl_803A87F0 (used as a
 * raw char* base here). Only pure-constant scalar fields are named; indexed and
 * matrix-pointer accesses are left as raw casts to preserve register coloring
 * (byte-neutral). Offsets agree with PauseMenuHud in maybetemplate.c where they
 * overlap (0xB00/0xB08/0xB0C/0xB24/0xB28/0xB2C anim timers). */
typedef struct TrickyHud
{
    u8 _pad0[0x314];
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
    char* base = lbl_803A87F0;
    int *player, *tricky;
    int itemTex = 0;
    int hcArg = 0;
    int krazoa = 0;
    int alpha;
    int magicId;
    int i;
    f32 op;
    player = (int*)Obj_GetPlayerObject();
    tricky = (int*)getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (((TrickyHud*)base)->magicCur >= lbl_803E1E3C || ((TrickyHud*)base)->scarabCur >= lbl_803E1E3C ||
        ((TrickyHud*)base)->keyCur >= lbl_803E1E3C || cMenuFadeCounter != 0)
        op = hudElementOpacity;
    else
        op = lbl_803E1E3C;
    if (op > lbl_803DD844)
    {
        lbl_803DD844 = lbl_803E1FA0 * timeDelta + lbl_803DD844;
        if (lbl_803DD844 > hudElementOpacity) lbl_803DD844 = hudElementOpacity;
    }
    else if (op < lbl_803DD844)
    {
        lbl_803DD844 = lbl_803DD844 - lbl_803E1FA0 * timeDelta;
        if (lbl_803DD844 < *(f32 *)&lbl_803E1E3C) lbl_803DD844 = lbl_803E1E3C;
    }
    alpha = (int)lbl_803DD83C;
    if ((u8)alpha != 0)
    {
        int cell = coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
        if (!(((TrickyHud*)base)->magicCur > lbl_803E1F9C && ((TrickyHud*)base)->magicCur < lbl_803E1FA8 &&
                ((int)((TrickyHud*)base)->magicCur & 8)) &&
            !(((TrickyHud*)base)->scarabCur > lbl_803E1F9C && ((TrickyHud*)base)->scarabCur < lbl_803E1FA8 &&
                ((int)((TrickyHud*)base)->scarabCur & 8)) &&
            !(cell == 0 && fn_802972A8(player) != 0))
        {
            for (i = 0; (int)(u8)i < (((TrickyHud*)base)->magicCount >> 2); i++)
            {
                int b74 = ((TrickyHud*)base)->magicValue;
                int sel;
                if ((int)(u8)i < (b74 >> 2)) sel = 0x16;
                else if ((int)(u8)i > (b74 >> 2)) sel = 0x12;
                else sel = (b74 & 3) + 0x12;
                drawTexture(*(void**)(base + 0x1c0 + (u8)sel * 4),
                            (f32)(int)((u8)i * 0x21 + 0x1e), lbl_803E1FAC, alpha, 0x100);
            }
        }
    }
    if ((u8)alpha != 0 && objIsCurModelNotZero(player) != 0 && GameBit_Get(0xeb1) != 0)
    {
        hudDrawMagicBar(alpha, 0x100, 0);
    }
    krazoa = 0;
    if (playerHasKrazoaSpirit(1, 0) != 0) krazoa = 1;
    magicId = 0;
    if (GameBit_Get(0x123) != 0 || GameBit_Get(0x83b) != 0) magicId = 0x63;
    else if (GameBit_Get(0x2e8) != 0 || GameBit_Get(0x83c) != 0) magicId = 0x64;
    if ((u8)magicId != 0)
    {
        drawTexture(*(void**)(base + 0x1c0 + (u8)magicId * 4),
                    (f32)(int)(s16)(krazoa ? 0x104 : 0x122), lbl_803E1FAC, alpha, 0x100);
    }
    if ((u8)krazoa != 0)
    {
        drawTexture(((TrickyHud*)base)->icon348,
                    (f32)(int)(s16)((u8)magicId ? 0x140 : 0x122), lbl_803E1FAC, alpha, 0x100);
    }
    if ((u8)alpha != 0 && tricky != NULL)
    {
        itemTex = 0x16;
        if (!(((TrickyHud*)base)->trickyCur > lbl_803E1F9C && ((TrickyHud*)base)->trickyCur < lbl_803E1FA8 &&
            ((int)((TrickyHud*)base)->trickyCur & 8)))
        {
            drawTexture(((TrickyHud*)base)->icon314, lbl_803E1F9C, lbl_803E1FB0, alpha, 0x100);
        }
        for (i = 0; (int)(u8)i < 0x14; i += 4)
        {
            int b98 = ((TrickyHud*)base)->scarabCount;
            if ((b98 & 0xfc) == (int)(u8)i && (b98 & 2) != 0)
            {
                int yo = ((u8)i * 0xf) / 4;
                drawScaledTexture(((TrickyHud*)base)->icon31c, (f32)(int)(yo + 0x40), lbl_803E1FB4,
                                  alpha, 0x100, 6, 0x12, 0);
                drawPartialTexture(((TrickyHud*)base)->icon318, (f32)(int)(yo + 0x46), lbl_803E1FB4,
                                   alpha, 0x100, 7, 0x12, 6, 0);
            }
            else
            {
                int sel = (b98 > (int)(u8)i) ? 0x57 : 0x56;
                int yo = ((u8)i * 0xf) / 4;
                drawTexture(*(void**)(base + 0x1c0 + (u8)sel * 4), (f32)(int)(yo + 0x40),
                            lbl_803E1FB4, alpha, 0x100);
            }
        }
    }
    {
        int camMode = (*gCameraInterface)->getMode();
        if (camMode >= 0x47 && camMode < 0x49)
        {
            drawTexture(((TrickyHud*)base)->icon354, lbl_803E1F9C,
                        (f32)(int)((s8)itemTex + 0x5f), alpha, 0x100);
        }
    }
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (lbl_803DD75A != 0)
    {
        int c0 = 0, c1 = 0, c2 = 0;
        f32 radius = lbl_803E1F98;
        int* near;
        near = (int*)ObjGroup_FindNearestObject(9, Obj_GetPlayerObject(), &radius);
        if (near != NULL && pauseMenuState == 0)
        {
            (*(void (*)(int*, int*, int*))(*(int*)(*(int*)&((GameObject*)near)->anim.dll) + 0x54))(&c2, &c1, &c0);
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
        hudDrawCounter(0x1e, (s16) ((TrickyHud*)base)->moneyValue, (s16)style, (int)((TrickyHud*)base)->spiritAnim,
                       (int)((TrickyHud*)base)->spiritCur, &hcArg, 0);
        hudDrawCounter(0x19, (s16) ((TrickyHud*)base)->spiritValue, 7, (int)((TrickyHud*)base)->healthAnim, (int)((TrickyHud*)base)->moneyCur,
                       &hcArg, 0);
        hudDrawCounter(0x1a, (s16) ((TrickyHud*)base)->healthValue, 0xf, (int)((TrickyHud*)base)->magicAnim, (int)((TrickyHud*)base)->healthCur,
                       &hcArg, 0);
        hudDrawCounter(0x18, (s16) ((TrickyHud*)base)->keyValue, 0x1f, (int)((TrickyHud*)base)->keyAnim, (int)((TrickyHud*)base)->magicFlash,
                       &hcArg, 0);
        hudDrawCounter(0x1b, (s16) ((TrickyHud*)base)->scarabValue, 7, (int)((TrickyHud*)base)->scarabAnim, (int)((TrickyHud*)base)->scarabFlash,
                       &hcArg, 0);
        hudDrawCounter(0x1c, (s16) ((TrickyHud*)base)->trickyValue, 0xff, (int)((TrickyHud*)base)->trickyAnim, (int)((TrickyHud*)base)->trickyFlash,
                       &hcArg, 0);
    }
}

extern int Camera_GetCurrentViewSlot(void);
extern u8 Rcp_GetViewFinderHudEnabled(void);
extern int getAngle(f32, f32);
extern f32 mathSinf(f32);
extern f32 mathCosf(f32);
extern void drawViewFinderLine(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4);
extern f32 fn_8029454C(f32);
extern const f64 lbl_803E1EA0, lbl_803E1EA8, lbl_803E1EB0, lbl_803E1EB8;
extern const f64 lbl_803E1EF0, lbl_803E1EF8, lbl_803E1F00, lbl_803E1F20, lbl_803E1F28;
extern const f32 lbl_803E1EC4, lbl_803E1EC8, lbl_803E1ECC, lbl_803E1ED0;
extern f32 gViewFinderFadeLevel, lbl_803DD7F4;
extern const f32 lbl_803E1ED4, lbl_803E1ED8, lbl_803E1EDC, lbl_803E1EE0, lbl_803E1EE4, lbl_803E1EE8, lbl_803E1E94;
extern const f32 lbl_803E1F08, lbl_803E1F0C, lbl_803E1F10, lbl_803E1F14, lbl_803E1F18;
extern const f32 lbl_803E1F30, lbl_803E1F34, lbl_803E1F48, lbl_803E1F4C;
extern f32 lbl_803DBAE0, lbl_803DBAE4;
extern const double lbl_803E1F38, lbl_803E1F40;
extern const f32 lbl_803E1F94;
extern char lbl_803DBB40;
extern const f32 lbl_803E1F70, lbl_803E1F90;
extern const double lbl_803E1F50, lbl_803E1F58, lbl_803E1F60, lbl_803E1F68, lbl_803E1F78, lbl_803E1F80, lbl_803E1F88,
                    lbl_803E1EF8;
extern int lbl_803DBAE8;
extern char lbl_803DBB18, lbl_803DBB1C, lbl_803DBB20, lbl_803DBB24, lbl_803DBB28, lbl_803DBB2C, lbl_803DBB30,
            lbl_803DBB34, lbl_803DBB38;
extern f32 Camera_GetFarPlane(void);
extern f32 Camera_GetNearPlane(void);
extern int depthReadRequestPoll(int x, int y, void* fn);
extern u16 lbl_803DD7EC;
extern int lbl_803E1E2C;
extern char sTrickyDebugXCoordFormat[];
extern void gameTextSetColor(int, int, int, int);
extern int sprintf(char*, ...);

#define VFTICK(gA1, gA2, A, B, C) do { \
    GXColor _c2; \
    GXColor _c; \
    s16 _a; \
    f32 _r, _cs, _sn, _cx, _sx; \
    *(int *)&_c = lbl_803E1E2C; \
    _c.a = hudElementOpacity * gViewFinderFadeLevel; \
    _a = (s16)getAngle(gA1, gA2); \
    _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94; \
    _cs = mathSinf(_r); \
    _sn = mathCosf(_r); \
    _c2 = _c; \
    _cx = lbl_803E1E68 * _cs; \
    _sx = lbl_803E1E68 * _sn; \
    drawViewFinderLine((u8 *)&_c2, (B) + _sx, (A) - _cx, (B) - _sx, (A) + _cx, (C) - _sx, (A) + _cx, (C) + _sx, (A) - _cx); \
} while (0)

#define VBLK(gA1, gA2, A, B, C) do { \
    GXColor _c2; \
    GXColor _c; \
    s16 _a; \
    f32 _r, _cs, _sn, _cx, _sx; \
    *(int *)&_c = lbl_803E1E2C; \
    _c.a = hudElementOpacity * gViewFinderFadeLevel; \
    _a = (s16)getAngle(gA1, gA2); \
    _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94; \
    _cs = mathSinf(_r); \
    _sn = mathCosf(_r); \
    _c2 = _c; \
    _cx = lbl_803E1E68 * _cs; \
    _sx = lbl_803E1E68 * _sn; \
    drawViewFinderLine((u8 *)&_c2, (A) + _sx, (B) - _cx, (A) - _sx, (B) + _cx, (A) - _sx, (C) + _cx, (A) + _sx, (C) - _cx); \
} while (0)

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
    v = (gViewFinderFadeLevel < lbl_803E1E3C)
            ? lbl_803E1E3C
            : ((gViewFinderFadeLevel > lbl_803E1E68) ? lbl_803E1E68 : gViewFinderFadeLevel);
    gViewFinderFadeLevel = v;
    if (v == lbl_803E1E3C) return;
    lbl_803DD7F4 = (f32)(lbl_803E1EB0 - lbl_803E1EB8 * v);
    lbl_803DD7EC = -*(s16*)slot;

    VFTICK(lbl_803E1EC4, lbl_803E1E3C, lbl_803E1ECC, lbl_803E1ED0, lbl_803E1ED4);
    VFTICK(lbl_803E1ED8, lbl_803E1E3C, lbl_803E1ECC, lbl_803E1EDC, lbl_803E1EE0);
    VFTICK(lbl_803E1EC4, lbl_803E1E3C, lbl_803E1EE4, lbl_803E1ED0, lbl_803E1ED4);
    VFTICK(lbl_803E1ED8, lbl_803E1E3C, lbl_803E1EE4, lbl_803E1EDC, lbl_803E1EE0);
    VBLK(lbl_803E1E3C, lbl_803E1EC4, lbl_803E1ED0, lbl_803E1ECC, lbl_803E1EE8);
    VBLK(lbl_803E1E3C, lbl_803E1ED8, lbl_803E1ED0, lbl_803E1EE4, lbl_803E1ED4);
    VBLK(lbl_803E1E3C, lbl_803E1EC4, lbl_803E1EDC, lbl_803E1ECC, lbl_803E1EE8);
    VBLK(lbl_803E1E3C, lbl_803E1ED8, lbl_803E1EDC, lbl_803E1EE4, lbl_803E1ED4);

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
            _a = (s16)getAngle(lbl_803E1E3C, lbl_803E1F08 - f18v);
            _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94;
            _cs = mathSinf(_r);
            _sn = mathCosf(_r);
            _c2 = _c;
            _cx = lbl_803E1E68 * _cs;
            _sx = lbl_803E1E68 * _sn;
            drawViewFinderLine((u8*)&_c2, lbl_803E1F10 + _sx, f18v - _cx, lbl_803E1F10 - _sx, f18v + _cx,
                               lbl_803E1F10 - _sx, lbl_803E1F08 + _cx, lbl_803E1F10 + _sx, lbl_803E1F08 - _cx);
        }
        {
            GXColor _c2;
            GXColor _c;
            s16 _a;
            f32 _r, _cs, _sn, _cx, _sx;
            *(int*)&_c = lbl_803E1E2C;
            _c.a = hudElementOpacity * gViewFinderFadeLevel;
            _a = (s16)getAngle(lbl_803E1E3C, (f19v = lbl_803E1F14 + f15v) - f15v);
            _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94;
            _cs = mathSinf(_r);
            _sn = mathCosf(_r);
            _c2 = _c;
            _cx = lbl_803E1F18 * _cs;
            _sx = lbl_803E1F18 * _sn;
            drawViewFinderLine((u8*)&_c2, lbl_803E1F10 + _sx, f15v - _cx, lbl_803E1F10 - _sx, f15v + _cx,
                               lbl_803E1F10 - _sx, f19v + _cx, lbl_803E1F10 + _sx, f19v - _cx);
        }
        xc = lbl_803E1F20 / fn_8029454C((f32)(lbl_803E1EC8 * fovY / lbl_803E1F28));
        xc = (f32)xc;
        sprintf(buf, sTrickyDebugXCoordFormat, xc);
        gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * gViewFinderFadeLevel));
        gameTextShowStr(buf, 0x93, 0x21c, 0x46);

        {
            f32 kOpac, kF4C;
            f32 kF30, kEC8, kF34, kEC4, kE94;
            f64 kF38;
            f32 kF48;
            f64 kF40;
            f32 kE68;
            f32 f27;
            f32 fdx, f29, f30, f31;
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
                    f32 f15, f16;
                    u8 alpha = kF30 * gViewFinderFadeLevel;
                    f31 = kEC4 + f27;
                    f30 = kF34 - f31;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f15 = (f32)(lbl_803DD7F4 + (kF38 + _sn));
                    f29 = kF34 - f27;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f16 = (f32)(lbl_803DD7F4 + (kF38 + _sn));
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    fdx = f31 - f27;
                    _a = (s16)getAngle(fdx, f15 - f16);
                    _r = kEC8 * (f32)_a / kE94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine((u8*)&_c2, f27 + _sx, f16 - _cx, f27 - _sx, f16 + _cx, f31 - _sx, f15 + _cx,
                                       f31 + _sx, f15 - _cx);
                }
                {
                    GXColor _c2;
                    GXColor _c;
                    s16 _a;
                    f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = kF30 * gViewFinderFadeLevel;
                    f32 f16, f15;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f16 = (f32)(lbl_803DD7F4 + (kF40 + _sn));
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f15 = (f32)(lbl_803DD7F4 + (kF40 + _sn));
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    _a = (s16)getAngle(fdx, f16 - f15);
                    _r = kEC8 * (f32)_a / kE94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine((u8*)&_c2, f27 + _sx, f15 - _cx, f27 - _sx, f15 + _cx, f31 - _sx, f16 + _cx,
                                       f31 + _sx, f16 - _cx);
                }
                {
                    GXColor _c2;
                    GXColor _c;
                    s16 _a;
                    f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = kOpac * gViewFinderFadeLevel;
                    f32 f16, f15;
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f16 = lbl_803DD7F4 + (kF48 + _sn);
                    _sn = lbl_803DBAE4 * mathCosf(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f15 = lbl_803DD7F4 + (kF48 + _sn);
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    _a = (s16)getAngle(fdx, f16 - f15);
                    _r = kEC8 * (f32)_a / kE94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine((u8*)&_c2, f27 + _sx, f15 - _cx, f27 - _sx, f15 + _cx, f31 - _sx, f16 + _cx,
                                       f31 + _sx, f16 - _cx);
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
            r5v = (int)((f32)lbl_803DD7EC / lbl_803E1F70);
            num = (f32)lbl_803DD7EC - (f32)r5v * lbl_803E1F70;
            f19 = xc * (lbl_803E1F70 / (f32)lbl_803DBAE8);
            f18 = (f32)(lbl_803E1F78 + (num / (f32)lbl_803DBAE8) * xc);
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
                int r27v = 0xff;
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
                        r27v = (u8)r30v;
                        r25v = 7;
                    }
                    else
                    {
                        r27v = (u8)r29v;
                        r25v = 0xa;
                    }
                }
                switch (r28v)
                {
                case 0: sprintf(buf, &lbl_803DBB18, r28v);
                    break;
                case 0x5a: sprintf(buf, &lbl_803DBB1C, r28v);
                    break;
                case 0xb4: sprintf(buf, &lbl_803DBB20, r28v);
                    break;
                case 0x10e: sprintf(buf, &lbl_803DBB24, r28v);
                    break;
                case 0x2d: sprintf(buf, &lbl_803DBB28, r28v);
                    break;
                case 0x87: sprintf(buf, &lbl_803DBB2C, r28v);
                    break;
                case 0xe1: sprintf(buf, &lbl_803DBB30, r28v);
                    break;
                case 0x13b: sprintf(buf, &lbl_803DBB34, r28v);
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
                                    (int)(lbl_803DD7F4 + (lbl_803E1F90 + sn)));
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
                    f16 = lbl_803DD7F4 + ((f32)((u8)r25v + 0x1e0) + _sn);
                    _sn = lbl_803DBAE4 * mathCosf(lbl_803E1EC8 * (f15 * lbl_803DBAE0) / lbl_803E1E94);
                    f15 = lbl_803DD7F4 + (lbl_803E1F48 + _sn);
                    *(int*)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    fx = lbl_803E1F88 * (f18 - lbl_803E1F78) + lbl_803E1F78;
                    _a = (s16)getAngle((f32)fx - f18, f16 - f15);
                    _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94;
                    _cs = mathSinf(_r);
                    _sn = mathCosf(_r);
                    _c2 = _c;
                    _cx = lbl_803E1E68 * _cs;
                    _sx = lbl_803E1E68 * _sn;
                    drawViewFinderLine((u8*)&_c2, f18 + _sx, f15 - _cx, f18 - _sx, f15 + _cx, (f32)fx - _sx, f16 + _cx,
                                       (f32)fx + _sx, f16 - _cx);
                }
            }
        }
        {
            f32 farP = Camera_GetFarPlane();
            f32 nearP = Camera_GetNearPlane();
            int depth = depthReadRequestPoll(0x140, 0xf0, (void*)drawViewFinderHud);
            f32 dist = (-farP * nearP) / (((f32)(u32)
            depth / lbl_803E1F94 - lbl_803E1E68
            )
            *(farP - nearP) - nearP
            )
            ;
            if (dist > lbl_803E1E3C && dist < lbl_803E1F98)
            {
                sprintf(buf, &lbl_803DBB40, dist / lbl_803E1EC4);
                gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * gViewFinderFadeLevel));
                gameTextShowStr(buf, 0x93, 0x32, 0x46);
            }
        }
    }
}
