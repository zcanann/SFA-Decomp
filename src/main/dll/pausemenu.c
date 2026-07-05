/*
 * pausemenu - in-game pause-menu rendering (main panel + status overlay).
 *
 * Text span (EN v1.0): 0x801262CC..0x80128120 (3 functions, 7764 b)
 *  - pauseMenuDraw              @ 0x801262CC, 4564 b
 *  - pauseMenuDrawStatus_801274a0 @ 0x801274A0, 2692 b
 *  - fn_80127F24                @ 0x80127F24,  508 b
 */

#include "main/dll/hud_textures.h"
#include "ghidra_import.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/gameplay_runtime.h"
#include "dolphin/gx/GXCull.h"
#include "main/texture.h"
#include "main/audio/sfx_ids.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/model.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
extern float mathSinf(float x);
extern void pauseMenuDrawElement(void* tex, f32 a, f32 b, s32 x, u8 alpha, s32 mode, s32 flag);
extern u8 hudTextures[0x198];
extern void drawRect(f32 sx, f32 sy, int x, int y);
extern void boxDrawFn_8012975c(void* a, void* b, void* c);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextLoadDir(int dirId);
extern void gameTextFn_80016810(int a, int b, int c);

extern float mathCosf(float x);
extern float fn_802943F4(float x);
extern void fn_8011EF50(f32 f1, f32 f2, f32 f3, f32 f4, u16 a, u16 b, u16 c);
extern void* Obj_GetActiveModel(u8* obj);
extern void objRender(int a, int b, int c, int d, void* obj, int e);
extern void drawFn_8011e8d8(void *this, f32 f1, f32 f2, int p4, int p5, int p6, int p7, int p8, int p9);
extern void drawFn_8011eb3c(void *this, f32 f1, f32 f2, int p4, u8 p5, int p6, int p7, int p8, int p9);
extern void Camera_SetCurrentViewIndex(int index);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_SetFovY(f32 fovY);
extern void Camera_RebuildProjectionMatrix(void);
extern void Camera_ApplyFullViewport(void);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);
extern void gameTextMeasureFn_800163c4(void* text, s32 a, s32 b, s32 c, s32* o1, s32* o2, s32* o3, s32* o4);

extern void* gameTextGetBox(int box);
extern void gameTextFn_8001628c(int id, int a, int b, s32* o1, s32* o2, s32* o3, s32* o4);

extern u16 getNextTaskHintText(void);

extern void fn_80128120(void* obj, u8 v);
extern void fn_80128470(int v);
extern f32 hudElementOpacity;
extern f32 timeDelta;
extern u8 pauseMenuState;
extern u8 pauseMenuTextDrawFn[];
extern u8 lbl_8031AE20[];
extern u8 lbl_8031BB90[];
extern u8 lbl_8031BD90[];
extern u8 sLanguageNameTable[];
extern u8 lbl_802C8680[];
extern int lbl_803A9364[];
extern f32 lbl_803DD748;
extern f32 lbl_803DD74C;
extern s16 lbl_803DD750;
extern s16 lbl_803DD752;
extern s16 lbl_803DD754;
extern s16 lbl_803DD756;
extern u8 lbl_803DD758;
extern s16 lbl_803DD75C;
extern f32 lbl_803DD760;
extern f32 lbl_803DD7BC;
extern u8 lbl_803DD7C4;
extern void* lbl_803DD7C8;
extern u8 lbl_803DD7D6;
extern int lbl_803DD7D8;
extern f32 lbl_803DD7FC;
extern void* lbl_803DD824;
extern u8 lbl_803DD734;
extern void* lbl_803DD7A4;
extern int lbl_803DD8E0;
extern f32 lbl_803DD850;
extern void* lbl_803DD860[2];
extern f32 lbl_803DBA34;
extern f32 lbl_803DBA38;
extern f32 lbl_803DBA3C;
extern f32 lbl_803DBA40;
extern f32 lbl_803DBA44;
extern f32 lbl_803DBA48;
extern f32 lbl_803DBA4C;
extern f32 lbl_803DBA50;
extern f32 lbl_803DBA54;
extern s16 lbl_803DBA8A;
extern f32 lbl_803DBA8C;
extern int lbl_803DBAD0;
extern int lbl_803DBAD4;
extern char lbl_803DBB58;
extern char lbl_803DBB68;
extern char lbl_803DBB70;
extern char lbl_803DBB78;
extern char lbl_803DBB80;
extern char lbl_803DBB88;
extern char lbl_803DBB90;
extern char lbl_803DBB98;
extern int lbl_803E1E04;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E64;
extern f32 lbl_803E1E94;
extern f32 lbl_803E1E80;
extern f32 lbl_803E1EC8;
extern f32 lbl_803E1ECC;
extern const f32 lbl_803E1F30;
extern f32 lbl_803E1F34;
extern double lbl_803E1F60;
extern const f32 lbl_803E1FAC;
extern f32 lbl_803E2018;
extern f32 lbl_803E2020;
extern double lbl_803E2070;
extern double lbl_803E2078;
extern double lbl_803E2080;
extern double lbl_803E2088;
extern f32 lbl_803E2090;
extern f32 lbl_803E2094;
extern f32 lbl_803E2098;
extern f32 lbl_803E209C;
extern f32 lbl_803E20A0;
extern f32 lbl_803E20A4;
extern f32 lbl_803E20A8;
extern f32 lbl_803E20AC;
extern f32 gPauseMenuSecsPerHour;
extern f32 lbl_803E20B4;
extern const f32 lbl_803E20B8;
extern f32 lbl_803E1E6C;
extern f32 lbl_803E1EE4;
extern f32 lbl_803E1F18;
extern f32 lbl_803E201C;
extern f32 lbl_803E20BC;
extern f32 lbl_803E20C0;
extern f32 lbl_803E20C4;
extern f32 lbl_803E20CC;

void pauseMenuDrawStatus_801274a0(int* arg1);
void fn_80127F24(s32 alpha);

void pauseMenuDraw(int* arg1, int* arg2, int* arg3)
{
    int* player;
    ObjModel* model;
    s32 alpha;
    s32 x;
    s32 idx;
    s32 rnd1;
    s32 rnd2;
    s32 y;
    s32 i;
    s32 acc;
    s32 val;
    s32 h;
    u8* statusTable;
    s32 b38, b34, b30, b2c;
    s32 sp28, sp24, sp20, sp1c;
    char buf1[4];
    s32 b14, b10, bc, b8;
    char buf2[12];

    statusTable = lbl_8031AE20;
    player = Obj_GetPlayerObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (pauseMenuState != 0)
    {
        drawRect(lbl_803E1E3C, lbl_803E1E3C, 0x280, 0x1e0);
    }

    switch (pauseMenuState)
    {
    case 0:
        boxDrawFn_8012975c(arg1, arg2, arg3);
        break;
    case 1:
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextLoadDir(0xb);
        gameTextFn_80016810(0x3dd, 0xc8, 0x12c);
    case 2:
        pauseMenuDoSave();
        break;
    case 3:
        pauseMenuDoSave();
        alpha = (s32)(hudElementOpacity * lbl_803DD760);
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        y = (s32)((f32)(s16)alpha * lbl_803DD850);
        {
            f64 tmp = (double)(s16)y * (lbl_803E2080 - (double)lbl_803DD75C);
            x = (s32)(tmp * lbl_803E2088);
        }
        if (gameTextFn_80019c00() != lbl_803E1E3C)
        {
            rnd1 = randomGetRange(0, 0x1e) * 2;
            rnd2 = randomGetRange(0, 0x1e) * 2;
            drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094,
                            0xff, (u8)((s16)y / 2), 0x230, 0x190, rnd2, rnd1);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            if (lbl_803DD7C4 == 0)
            {
                if (lbl_803DD7C8 == 0)
                {
                    lbl_803DD7C8 = textureLoadAsset(0xbe7);
                }
                if (lbl_803DD7C8 != 0)
                {
                    pauseMenuDrawElement(lbl_803DD7C8, lbl_803E1E80, lbl_803E2098, 0x96 - lbl_803DD75C, x,
                                         lbl_803E209C, 0);
                }
            }
            fn_80127F24(x);
            lbl_803DD824 = lbl_803DD7C4 ? (void*)(statusTable + 0xbd0) : (void*)(statusTable + 0x9f8);
            fn_80128470(y);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
            GXSetScissor(0, 0, 0x280, 0x1e0);
        }
        break;
    case 5:
        pauseMenuDrawStatus_801274a0(player);
        break;
    case 4:
        pauseMenuDoSave();
        alpha = (s32)(hudElementOpacity * lbl_803DD760);
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        if (gameTextFn_80019c00() != lbl_803E1E3C)
        {
            rnd1 = randomGetRange(0, 0x1e) * 2;
            rnd2 = randomGetRange(0, 0x1e) * 2;
            drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094,
                            0xff, (u8)((s16)alpha / 2), 0x230, 0x190, rnd2, rnd1);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            gameTextSetDrawFunc(pauseMenuTextDrawFn);
            lbl_803DBA8A = 0xc0;
            lbl_803DBA8C = lbl_803E20A0;
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            if (lbl_803DD8E0 == lbl_803DD7D6)
            {
                if (lbl_803DD7A4 != 0 && *(u16*)((u8*)lbl_803DD7A4 + 2) >= 2)
                {
                    acc = 0x96;
                    i = 1;
                    idx = 4;
                    while (i < *(u16*)((u8*)lbl_803DD7A4 + 2))
                    {
                        gameTextShowStr(*(void**)((u8*)*(void**)((u8*)lbl_803DD7A4 + 8) + idx),
                                        0x79, 0xf0, acc);
                        gameTextMeasureFn_800163c4(*(void**)((u8*)*(void**)((u8*)lbl_803DD7A4 + 8) + idx),
                                                   0x79, 0, 0, &sp28, &sp24, &sp20, &sp1c);
                        h = *(u16*)(lbl_802C8680 + (u32)(u8)
                        sLanguageNameTable[getCurLanguage() * 8 + 4] * 16 + 0xa
                        )
                        ;
                        val = sp1c - sp20;
                        acc += (val > h) ? val : *(u16*)(lbl_802C8680 + (u32)(u8)
                        sLanguageNameTable[getCurLanguage() * 8 + 4] * 16 + 0xa
                        );
                        idx += 4;
                        i++;
                    }
                }
            }
            else
            {
                gameTextFn_80016810(0x515, 0xc8, 0x96);
            }
            gameTextFn_80016810(0x3de, 0xc8, 0x154);
            lbl_803DBA8A = 0x100;
            gameTextSetDrawFunc(0);
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        break;
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
        pauseMenuDoSave();
        alpha = (s32)(hudElementOpacity * lbl_803DD760);
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        if (gameTextFn_80019c00() != lbl_803E1E3C)
        {
            rnd1 = randomGetRange(0, 0x1e) * 2;
            rnd2 = randomGetRange(0, 0x1e) * 2;
            drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094,
                            0xff, (u8)((s16)alpha / 2), 0x230, 0x190, rnd2, rnd1);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            lbl_803DD824 = (void*)(statusTable + 0xf10);
            fn_80128470(alpha);
            gameTextSetDrawFunc(pauseMenuTextDrawFn);
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            lbl_803DBA8A = 0x100;
            lbl_803DBA8C = lbl_803E20A0;
            switch (pauseMenuState)
            {
            case 7:
            case 9:
                gameTextFn_80016810(0x3cf, 0xc8, 0x118);
                gameTextFn_80016810(0x3e1, 0xc8, 0x96);
                break;
            case 6:
            case 10:
                gameTextFn_80016810(0x3ce, 0xc8, 0x96);
                break;
            case 8:
                {
                    MapEventInterface* mapEvents = *gMapEventInterface;
                    int* info = mapEvents->getCurCharacterState();
                    *(int*)buf1 = lbl_803E1E04;
                    gameTextFn_80016810(0x3e0, 0xc8, 0x118);
                    sprintf(buf1, &lbl_803DBB68, *(u8*)((u8*)info + 9));
                    lbl_803DBA8C = lbl_803E1E64;
                    gameTextShowStr(buf1, 0x93, 0x14a, 0xdc);
                    lbl_803DBA8C = lbl_803E20A0;
                    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex134, lbl_803E1ECC, lbl_803E2018, 0x100,
                                         alpha,
                                         0x258, 0);
                    break;
                }
            }
            {
                int* box;
                lbl_803DBA8C = lbl_803E1E64;
                box = gameTextGetBox(0x7f);
                gameTextFn_8001628c(0x3cd, 0, 0, &b38, &b34, &b30, &b2c);
                val = b34 - b38;
                *(u8*)((u8*)lbl_803DD824 + 8) = val;
                *(s16*)((u8*)lbl_803DD824 + 2) = lbl_803DBA8C
                    * (f32)(s32)(*(s16*)((u8*)box + 0x14) + *(u16*)((u8*)box + 8) - (val >> 1) - 0x140)
                    + lbl_803E1F34;

                box = gameTextGetBox(0x80);
                gameTextFn_8001628c(0x3cc, 0, 0, &b38, &b34, &b30, &b2c);
                val = b34 - b38;
                *(u8*)((u8*)lbl_803DD824 + 0x28) = val;
                x = *(s16*)((u8*)box + 0x14) + (val >> 1) - 0x140;
                *(s16*)((u8*)lbl_803DD824 + 0x22) = lbl_803DBA8C * (f32)(s32)x + lbl_803E1F34;

                if (lbl_803DD7D8 != 0)
                {
                    gameTextSetColor(0x96, 0x96, 0x96, 0xff);
                }
                else
                {
                    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
                }
                gameTextFn_80016810(0x3cd, 0, 0xc8);
                if (lbl_803DD7D8 != 0)
                {
                    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
                }
                else
                {
                    gameTextSetColor(0x96, 0x96, 0x96, 0xff);
                }
                gameTextFn_80016810(0x3cc, 0, 0xc8);
                gameTextSetDrawFunc(0);
                model = Obj_GetActiveModel(lbl_803DD860[1]);
                objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
                model->bufferFlags &= ~0x8;
                Camera_SetCurrentViewIndex(0);
                Camera_UpdateViewMatrices();
                Camera_SetFovY(lbl_803DD7FC);
                Camera_RebuildProjectionMatrix();
                Camera_ApplyFullViewport();
            }
        }
        break;
    case 11:
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        gameTextSetDrawFunc(pauseMenuTextDrawFn);
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        lbl_803DBA8A = 0x100;
        lbl_803DBA8C = lbl_803E20A0;
        switch (lbl_803DD758)
        {
        case 0:
            gameTextFn_80016810(0x43a, 0, 0xb4);
            break;
        case 1:
            {
                u8* tbl216;
                gameTextFn_80016810(0x440, 0, 0x78);
                gameTextFn_8001628c(0x440, 0, 0, &b14, &b10, &bc, &b8);
                acc = (b8 - bc) + 5;
                {
                    u8* p214 = statusTable + 0x214;
                    sprintf(buf2, &lbl_803DBB58, (u8) * (u8*)(p214 + lbl_803DD756 * 8));
                }
                gameTextShowStr(buf2, 0x79, 0, acc + 0x78);
                gameTextMeasureFn_800163c4(buf2, 0x79, 0, 0, &b14, &b10, &bc, &b8);
                acc = (b8 - bc) + acc;
                acc += 5;
                gameTextFn_80016810(0x441, 0, acc + 0x78);
                gameTextFn_8001628c(0x441, 0, 0, &b14, &b10, &bc, &b8);
                acc = (b8 - bc) + acc;
                tbl216 = statusTable + 0x216;
                gameTextFn_80016810(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, acc + 0x78);
                gameTextFn_8001628c(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, 0, &b14, &b10, &bc, &b8);
                acc = (b8 - bc) + acc;
                acc += 0xa;
                gameTextFn_80016810(0x442, 0, acc + 0x78);
                gameTextFn_8001628c(0x442, 0, 0, &b14, &b10, &bc, &b8);
                acc = (b8 - bc) + acc;
                gameTextFn_80016810(0x43a, 0, acc + 0x82);
                break;
            }
        case 2:
            {
                u8* tbl216;
                gameTextFn_80016810(0x443, 0, 0xa0);
                gameTextFn_8001628c(0x443, 0, 0, &b14, &b10, &bc, &b8);
                x = (b8 - bc) + 5;
                tbl216 = statusTable + 0x216;
                gameTextFn_80016810(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, x + 0xa0);
                gameTextFn_8001628c(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, 0, &b14, &b10, &bc, &b8);
                x += b8 - bc;
                gameTextFn_80016810(0x444, 0, x + 0xaa);
                break;
            }
        }
        gameTextSetDrawFunc(0);
        model = Obj_GetActiveModel(lbl_803DD860[1]);
        objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
        model->bufferFlags &= ~0x8;
        Camera_SetCurrentViewIndex(0);
        Camera_UpdateViewMatrices();
        Camera_SetFovY(lbl_803DD7FC);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        break;
    }
}

void pauseMenuDrawStatus_801274a0(int* arg1)
{
    s8 i8;
    s32 ty1;
    s32 alpha;
    s32 ty;
    s32 i;
    s32 j;
    ObjModel* model;
    int* info;

    pauseMenuDoSave();
    alpha = (s32)(hudElementOpacity * lbl_803DD760);
    lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
    lbl_803DD748 = lbl_803DD748 + timeDelta;
    lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
    lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
    lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
    lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
    lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
    fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752, *(u16*)&lbl_803DD754);
    model = Obj_GetActiveModel(lbl_803DD860[0]);
    objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
    model->bufferFlags &= ~0x8;

    if (gameTextFn_80019c00() != lbl_803E1E3C)
    {
        s32 rnd1 = randomGetRange(0, 0x1e) * 2;
        s32 rnd2 = randomGetRange(0, 0x1e) * 2;
        drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094,
                        0xff, (u8)((s16)alpha / 2), 0x230, 0x190, rnd2, rnd1);
        model = Obj_GetActiveModel(lbl_803DD860[1]);
        objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
        model->bufferFlags &= ~0x8;
        Camera_SetCurrentViewIndex(0);
        Camera_UpdateViewMatrices();
        Camera_SetFovY(lbl_803DD7FC);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        return;
    }

    ty1 = (s32)((f32)(s16)alpha * lbl_803DD850);
    {
        f64 tmp = (double)(s16)ty1 * (lbl_803E2080 - (double)lbl_803DD75C);
        ty = (s32)(tmp * lbl_803E2088);
    }
    fn_80127F24(ty);
    if (lbl_803DD7C4 != 0)
    {
        for (i8 = 0x14; i8 >= 0; i8 -= 4)
        {
            s16 px = (s16)((0xf0 - i8) - lbl_803DD75C);
            drawFn_8011eb3c(((HudTextures*)hudTextures)->tex170, lbl_803E2094, lbl_803E20A4,
                            px, ty, 0x100, 0x190, 4, 0);
            drawFn_8011eb3c(((HudTextures*)hudTextures)->tex170, lbl_803E1ECC, lbl_803E20A8,
                            px, ty, 0x100, 0xf0, 4, 0);
            drawFn_8011eb3c(((HudTextures*)hudTextures)->tex170, lbl_803E1ECC, lbl_803E20AC,
                            px, ty, 0x100, 0xf0, 4, 0);
        }
        lbl_803DD824 = lbl_8031BD90;
        fn_80128470(ty1);
    }
    else
    {
        MapEventInterface* mapEvents = *gMapEventInterface;
        char buf[0x38];
        s32 hintCount;
        s32 gbCount;
        s32 h24;
        s32 mins25;
        f32 playRatio;
        u8 magicVal;
        info = mapEvents->getCurCharacterState();
        hintCount = ((u16)getNextTaskHintText() * 0x64 / 0xbb) & 0xff;
        playRatio = SaveGame_getPlayTime() / lbl_803E2020;
        ty1 = (s32)((f32)(s16)ty1 * lbl_803DD850);
        {
            f64 tmp = (double)(s16)ty1 * (lbl_803E2080 - (double)lbl_803DD75C);
            ty = (s32)(tmp * lbl_803E2088);
        }
        fn_80128120(arg1, ty);
        i = GameBit_Get(0x63c);
        j = GameBit_Get(0x4e9);
        i += GameBit_Get(0x5f3);
        gbCount = i + GameBit_Get(0x5f4);
        gbCount += j;
        {
            s8 k;
            u8* p;
            for (k = 0, p = lbl_8031BB90; k < 4; k++)
            {
                *(s16*)(p + 0xc0) = k < (u8)gbCount ? (u8)(0x22 + (k & 1)) : (u8)0x24;
                p += 0x20;
            }
        }
        if (GameBit_Get(0x91b) != 0)
        {
            magicVal = 0xc8;
        }
        else if (GameBit_Get(0x91a) != 0)
        {
            magicVal = 0x64;
        }
        else if (GameBit_Get(0x919) != 0)
        {
            magicVal = 0x32;
        }
        else
        {
            magicVal = 0xa;
        }
        lbl_803DD734 = magicVal;
        *(s16*)(lbl_8031BB90 + 0x160) = magicVal != 0 ? (u8)0x4e : (u8)0x25;
        gameTextSetDrawFunc(pauseMenuTextDrawFn);
        gameTextSetColor(0xff, 0xff, 0xff, ty);
        lbl_803DBA8A = (s16)(0xff - lbl_803DD75C);
        lbl_803DBA8C = lbl_803E20A0;
        sprintf(buf, &lbl_803DBB70, *(u8*)((u8*)info + 9), *(u8*)((u8*)info + 0xa));
        gameTextShowStr(buf, 0x93, 0x14a, 0xdc);
        if (lbl_803DD734 != 0)
        {
            sprintf(buf, &lbl_803DBB78, lbl_803A9364[3]);
            gameTextShowStr(buf, 0x93, 0x140, 0x10e);
        }
        sprintf(buf, &lbl_803DBB80, hintCount);
        gameTextShowStr(buf, 0x93, 0x130, 0x12c);
        h24 = (s32)(playRatio / gPauseMenuSecsPerHour);
        if (h24 > 0x63)
        {
            sprintf(buf, &lbl_803DBB88, h24);
        }
        else
        {
            sprintf(buf, &lbl_803DBB88, h24);
        }
        mins25 = (s32)(playRatio / lbl_803E2020) - h24 * 0x3c;
        sprintf(buf, &lbl_803DBB90, buf, mins25);
        sprintf(buf, &lbl_803DBB98, buf,
                (s32)(playRatio - (f32)(h24 * 0xe10) - (f32)(mins25 * 0x3c)));
        gameTextShowStr(buf, 0x93, 0x12c, 0x14a);
        gameTextSetDrawFunc(0);

        {
            s16 px = (s16)(0xe6 - lbl_803DD75C);
            u16 ii;
            for (ii = 0; ii < 7; ii++)
            {
                f32 fy = lbl_803E1FAC * (f32)(u32)(u16)ii
                +lbl_803E1F30;
                pauseMenuDrawElement(*(int**)&((HudTextures*)hudTextures)->unk5C, fy, lbl_803E20B4, px, ty,
                                     (s32)lbl_803E20B8, 0);
            }
        }
        {
            u16 jj;
            for (jj = 0; (s32)(u16)jj < (*(int*)((u8*)lbl_803A9364 + 0x1c) >> 2); jj++)
            {
                s32 v = *(int*)lbl_803A9364;
                u8 tex;
                f32 fyj;
                if ((s32)(u16)jj < (v >> 2)
                )
                {
                    tex = 0x16;
                }
                else
                if ((s32)(u16)jj > (v >> 2)
                )
                {
                    tex = 0x12;
                }
                else
                {
                    tex = (v & 3) + 0x12;
                }
                i8 = 0x14;
                fyj = lbl_803E1FAC * (f32)(u32)(jj & 0xffff) + lbl_803E1F30;
                for (; i8 >= 0; i8 -= 4)
                {
                    s16 px = (s16)((0xff - i8) - lbl_803DD75C);
                    pauseMenuDrawElement(*(int**)((u8*)hudTextures + tex * 4), fyj, lbl_803E20B4, px, ty,
                                         (s32)lbl_803E20B8, 0);
                }
            }
        }
        pauseMenuDrawElement(*(int**)&((HudTextures*)hudTextures)->unkBC, lbl_803DBAD0, lbl_803DBAD4,
                             0x100 - lbl_803DD75C, ty,
                             0x100, 0);
        drawFn_8011eb3c(((HudTextures*)hudTextures)->texB8, (f32)(lbl_803DBAD0 + 0x18), lbl_803DBAD4,
                        0x100 - lbl_803DD75C, ty, 0x100, 0x66, 0x12, 0);
        pauseMenuDrawElement(*(int**)&((HudTextures*)hudTextures)->unkC0, (f32)(lbl_803DBAD0 + 0x7e), lbl_803DBAD4,
                             0x100 - lbl_803DD75C, ty,
                             0x100, 0);
        hudDrawMagicBar((u8)ty, 0x100 - lbl_803DD75C, 1);
        lbl_803DD824 = lbl_8031BB90;
        fn_80128470(ty1);
    }

    model = Obj_GetActiveModel(lbl_803DD860[1]);
    objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
    model->bufferFlags &= ~0x8;
    Camera_SetCurrentViewIndex(0);
    Camera_UpdateViewMatrices();
    Camera_SetFovY(lbl_803DD7FC);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

void fn_80127F24(s32 alpha)
{
    f32 phase;
    f32 brightness;
    s16 x;
    s16 x2;
    s8 j;
    s8 i;

    phase = lbl_803E1F18 *
        mathSinf(lbl_803E1EC8 * (lbl_803DD748 * lbl_803E201C) /
            lbl_803E1E94);

    for (i = 10; i >= 0; i -= 2)
    {
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex11C,
                             lbl_803E20BC, lbl_803E1EE4,
                             x = (s16)((0xf5 - i) - lbl_803DD75C),
                             alpha, 0x200, 0);
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex11C,
                             lbl_803E20C0, lbl_803E1EE4,
                             x,
                             alpha, 0x200, 0);
    }

    j = 10;
    brightness = lbl_803E20C4 - phase * lbl_803E1E6C;
    for (; j >= 0; j -= 10)
    {
        f32 off = phase * (40.0f - (f32)(s32)(s8)j) / 40.0f;
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex118,
                             595.0f + off, lbl_803E20CC,
                             x2 = (s16)((0xff - j) - lbl_803DD75C),
                             alpha, (s32)(f64)brightness, 0);
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex118,
                             27.0f - off, lbl_803E20CC,
                             x2,
                             alpha, (s32)(f64)brightness, 0);
    }
}
