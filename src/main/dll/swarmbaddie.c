#include "main/game_ui_interface.h"
#include "main/dll/baddie/swarmBaddie.h"
#include "main/game_object.h"

extern u32 randomGetRange(int min, int max);

extern void AudioStream_StopCurrent(void);
extern void doNothing_8000CF54(int a);
extern void GXSetScissor(int x, int y, int w, int h);
extern void drawRect(f32 a, f32 b, int c, int d);
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32 fov);
extern void Camera_SetCurrentViewIndex(int idx);
extern int Camera_IsViewYOffsetEnabled(void);
extern void Camera_DisableViewYOffset(void);
extern void Camera_EnableViewYOffset(void);
extern void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
extern void Camera_SetCurrentViewRotation(int x, int y, int z);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_RebuildProjectionMatrix(void);
extern void Camera_ApplyFullViewport(void);
extern void GXSetViewport(f32 a, f32 b, f32 c, f32 d, f32 e, f32 f);
extern void objRender(int a, int b, int c, int d, int obj, int e);
extern int Obj_GetActiveModel(int obj);
extern f32 fsin16Approx(u16 angle);
extern void drawPartialTexture(int tex, f32 a, f32 b, int alpha, int scale, int c, int d, int e, int f);
extern void drawScaledTexture(int tex, f32 a, f32 b, int alpha, int scale, int c, int d, int e);
extern void drawTexture(int tex, f32 x, f32 y, int alpha, int scale);
extern u8 lbl_803DD85A;
extern u8 lbl_803DD85B;
extern u8 lbl_803DD7A8;
extern u16 lbl_803DD858;
extern u16 lbl_803DD856;
extern s16 lbl_803DD854;
extern u16 lbl_803DD77C;
extern int lbl_803DD7E0;
extern f32 lbl_803DBAA4;
extern u8* gRenderModeObj;
extern u8 framesThisStep;
extern u8 lbl_8031AF34[];
extern int lbl_803A93F8[];
extern f32 lbl_8031BFA8[];
extern int hudTextures[];
extern f32 timeDelta;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E68;
extern f32 lbl_803E2010;
extern f32 lbl_803E2024;
extern f32 lbl_803E2040;
extern f32 lbl_803E2044;
extern f32 lbl_803E2048;
extern f32 lbl_803E204C;
extern f32 lbl_803E2050;
extern f32 lbl_803E2054;
extern f32 lbl_803E2058;

extern void Obj_FreeObject(int* obj);
extern u8 lbl_803DD7A9;
extern u8 lbl_803DD8C8;
extern s16 lbl_803DD8CA;
extern f32 lbl_803DD8CC;
extern u16 lbl_803DD8D0;
extern u16 curGameText;
extern u8 lbl_803A9440[];
extern u8 AudioStream_IsPreparing(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int stream, void (*cb)(void));
extern void gameTextGetBox(int box);
extern void gameTextFreePhrase(u8 * phrase);
extern int lbl_8031BF90[];
extern u8* Obj_AllocObjectSetup(int size, int def);
extern int Obj_SetupObject(u8* def, int a, int b, int c, int d);
extern f32 lbl_803E1E5C;
extern f32 lbl_803E205C;
extern int* getArwing(void);
extern int arwarwing_getShield(int* arwing);
extern int arwarwing_getMaxShield(int* arwing);
extern int arwarwing_getBombCount(int* arwing);
extern int arwarwing_getCollectedRingCount(int* arwing);
extern int arwarwing_getRequiredRingCount(int* arwing);
extern int arwarwing_getScore(int* arwing);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShowStr(char* str, int x, int y, int z);
extern void sprintf(char* buf, char* fmt, ...);
extern u8 arwingHudVisible;
extern s16 arwingHudAlpha;
extern char lbl_803DBB60;
extern int lbl_803E1E08;
extern u8 lbl_803E1E0C;
extern f32 lbl_803E1FA0;
extern f32 lbl_803E1FAC;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E2060;
extern f32 lbl_803E2064;
extern f32 lbl_803E2068;

void drawFn_80125424(void)
{
    s16 alpha;
    u32 height;
    u32 width;
    int type;
    int ypos;
    int i;
    int a1;
    int rx;
    int ry;
    s16 sw;
    s16 sh;
    int x2;
    int x5;
    f32 wave;
    f32 zz;
    f32 k;
    f32 base1;
    f32 base2;

    if (lbl_803DD85A != 0)
    {
        if ((s8)lbl_803DD7A8 == 0)
        {
            lbl_803DD858 = lbl_803DD858 + framesThisStep * 5;
            if (lbl_803DD858 > 0x152)
            {
                lbl_803DD858 = 0x152;
                lbl_803DD85A = 0;
                if (*(int*)(lbl_8031AF34 + lbl_803DD85B * 0xc) != -1)
                {
                    AudioStream_StopCurrent();
                    doNothing_8000CF54(0);
                }
            }
            lbl_803DD856 = lbl_803DD856 - framesThisStep * 10;
            lbl_803DD854 = lbl_803DD854 - framesThisStep * 0x17;
        }
        else
        {
            lbl_803DD858 = lbl_803DD858 - framesThisStep * 5;
            if (lbl_803DD858 < 0x122)
            {
                lbl_803DD858 = 0x122;
            }
            lbl_803DD856 = lbl_803DD856 + framesThisStep * 10;
            lbl_803DD854 = lbl_803DD854 + framesThisStep * 0x17;
        }
        a1 = lbl_803DD854;
        if (a1 < 0)
        {
            a1 = 0;
        }
        else if (a1 > 0xff)
        {
            a1 = 0xff;
        }
        alpha = a1;
        lbl_803DD854 = alpha;
        height = lbl_803DD856;
        if (height > 0x6e)
        {
            height = 0x6e;
        }
        lbl_803DD856 = height;
        width = lbl_803DD858;
        type = *(u8*)(lbl_8031AF34 + lbl_803DD85B * 0xc + 6);
        switch (type)
        {
        default:
        case 1:
            ypos = 0x19a;
            break;
        case 3:
            ypos = 0x195;
            break;
        case 2:
            ypos = 0x186;
            break;
        }
        GXSetScissor(0x1ea, width, 0x78, height);
        drawRect(lbl_803E2040, (f32)(int)width, 0x78, height);
        lbl_803DBAA4 = Camera_GetFovY();
        Camera_SetFovY(lbl_803E2044);
        Camera_SetCurrentViewIndex(1);
        lbl_803DD7E0 = Camera_IsViewYOffsetEnabled();
        Camera_DisableViewYOffset();
        zz = lbl_803E1E3C;
        Camera_SetCurrentViewPosition(zz, zz, zz);
        Camera_SetCurrentViewRotation(0x8000, 0, 0);
        Camera_UpdateViewMatrices();
        Camera_RebuildProjectionMatrix();
        GXSetViewport(lbl_803E2048, (f32)ypos - lbl_803E2024,
                      (f32)(u32) * (u16*)(gRenderModeObj + 4), (f32)(u32) * (u16*)(gRenderModeObj + 8),
                      lbl_803E1E3C, lbl_803E1E68);
        if (*(u8**)&lbl_803A93F8[type] != NULL)
        {
            ObjAnim_AdvanceCurrentMove(lbl_8031BFA8[type], timeDelta, lbl_803A93F8[type], NULL);
            if (*(u32*)(lbl_803A93F8[type] + 0x4c) > 0x90000000u)
            {
                *(u32*)(lbl_803A93F8[type] + 0x4c) = 0;
            }
            *(u8*)(lbl_803A93F8[type] + 0x37) = 0xff;
            objRender(0, 0, 0, 0, lbl_803A93F8[type], 1);
            *(u16*)(Obj_GetActiveModel(lbl_803A93F8[type]) + 0x18) &= ~8;
        }
        Camera_SetCurrentViewIndex(0);
        if (lbl_803DD7E0 != 0)
        {
            Camera_EnableViewYOffset();
        }
        Camera_UpdateViewMatrices();
        Camera_SetFovY(lbl_803DBAA4);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        GXSetScissor(0, 0, 0x280, 0x1e0);
        lbl_803DD77C += 1;
        k = lbl_803E204C;
        base1 = lbl_803E2050;
        base2 = lbl_803E2010;
        for (i = 0; i < (int)height; i += 4)
        {
            wave = k * fsin16Approx((u16)(i * 0xd48 + lbl_803DD77C * 0x1838));
            wave = k * fsin16Approx((u16)(i * 0x7d0 + lbl_803DD77C * 0xfa0)) + wave;
            a1 = (int)((f32)alpha * (base1 + wave));
            if (a1 < 0)
            {
                a1 = 0;
            }
            rx = (int)randomGetRange(0, 0x1e) << 1;
            ry = (int)randomGetRange(0, 0x1e) << 1;
            if (a1 > 0xff)
            {
                a1 = 0xff;
            }
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i), a1 & 0xff, 0x100, 0x78, 2, ry, rx);
            a1 = (int)((f32)alpha * (base2 + wave));
            if (a1 < 0)
            {
                a1 = 0;
            }
            rx = (int)randomGetRange(0, 0x1e) << 1;
            ry = (int)randomGetRange(0, 0x1e) << 1;
            if (a1 > 0xff)
            {
                a1 = 0xff;
            }
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i + 2), a1 & 0xff, 0x100, 0x78, 2, ry,
                               rx);
        }
        sw = (s16)width;
        x5 = sw - 5;
        drawTexture(hudTextures[10], lbl_803E2054, (f32)x5, alpha & 0xff, 0x100);
        drawScaledTexture(hudTextures[13], lbl_803E2040, (f32)x5, alpha & 0xff, 0x100, 0x78, 5, 0);
        sh = (s16)height;
        drawScaledTexture(hudTextures[11], lbl_803E2054, (f32)sw, alpha & 0xff, 0x100, 5, sh, 0);
        x2 = sw + sh;
        drawScaledTexture(hudTextures[13], lbl_803E2040, (f32)x2, alpha & 0xff, 0x100, 0x78, 5, 2);
        drawScaledTexture(hudTextures[11], lbl_803E2058, (f32)sw, alpha & 0xff, 0x100, 5, sh, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2058, (f32)x2, alpha & 0xff, 0x100, 5, 5, 3);
        drawScaledTexture(hudTextures[10], lbl_803E2058, (f32)x5, alpha & 0xff, 0x100, 5, 5, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2054, (f32)x2, alpha & 0xff, 0x100, 5, 5, 2);
    }
}

void fn_80125D04(void)
{
    int* ptr;
    int i = 0;
    ptr = lbl_803A93F8;
    for (; i < 6; i++)
    {
        int* obj = (int*)ptr[0];
        if (obj != NULL)
        {
            if ((u32) * (int*)&((GameObject*)obj)->anim.placementData > 0x90000000u)
            {
                *(int*)&((GameObject*)obj)->anim.placementData = 0;
            }
            Obj_FreeObject((int*)ptr[0]);
            ptr[0] = 0;
        }
        ptr++;
    }
}

#pragma opt_common_subs off
void gameTextFn_80125ba4(int idx)
{
    int a;
    int b;

    if (lbl_803DD85A == 0)
    {
        if (idx < 0 || idx >= 0x15)
        {
            idx = 0x14;
        }
        lbl_803DD85A = 1;
        lbl_803DD85B = idx;
        {
        int off = idx * 0xc;
        u8* base = lbl_8031AF34;
        if (*(int*)(base + off) != -1 && AudioStream_IsPreparing() == 0)
        {
            AudioStream_Play(*(int*)(base + off), AudioStream_StartPrepared);
        }
        {
            u8* e = &lbl_8031AF34[off];
            if (e[7] != 0)
            {
                (*gGameUIInterface)->showNpcDialogue(*(u16*)(e + 4), 0, 0, 0);
            }
            else
            {
                b = *(u16*)(e + 8);
                a = *(u16*)(e + 4);
                if (a != -1 && curGameText == 0xffff)
                {
                    gameTextGetBox(0x7c);
                    lbl_803DD7A8 = 1;
                    lbl_803DD8D0 = 0;
                    curGameText = a;
                    lbl_803DD8C8 = 0;
                    lbl_803DD8CA = (s16)b;
                    lbl_803DD8CC = (f32)(s16)
                    b;
                    gameTextFreePhrase(lbl_803A9440);
                    lbl_803DD7A9 = 0;
                }
            }
        }
        }
        lbl_803DD858 = 0x159;
        lbl_803DD856 = 0;
        lbl_803DD854 = 0;
    }
}
#pragma opt_common_subs reset

void pauseMenuCreateHeads(void)
{
    int i;
    int* slots;
    int* defs;
    f32 f;

    i = 0;
    slots = lbl_803A93F8;
    defs = lbl_8031BF90;
    for (; i < 6; i++)
    {
        if (i != 3 && i != 2 && i != 1)
        {
            *slots = 0;
        }
        else
        {
            if (*(void**)slots == NULL)
            {
                *slots = Obj_SetupObject(Obj_AllocObjectSetup(0x20, *defs), 4, -1, -1, 0);
                f = lbl_803E1E3C;
                *(f32*)(*slots + 0xc) = f;
                *(f32*)(*slots + 0x10) = f;
                *(f32*)(*slots + 0x14) = lbl_803E1E5C;
                *(s16*)*slots = 0x7447;
                *(f32*)(*slots + 8) = lbl_803E205C;
                if (*(u32*)(*slots + 0x4c) > 0x90000000u)
                {
                    *(u32*)(*slots + 0x4c) = 0;
                }
                ObjAnim_SetCurrentMove(*slots, 1, lbl_803E1E3C, 0);
            }
        }
        slots = slots + 1;
        defs = defs + 1;
    }
}

void drawArwingHud(void)
{
    char buf[8];
    int* arwing;
    int shield;
    int maxShield;
    int bombs;
    int rings;
    int req;
    int t30;
    int t23;
    int t22;
    u32 i;
    u32 v;
    int t;
    u8 b;
    int pos;

    arwing = getArwing();
    *(int*)buf = lbl_803E1E08;
    buf[4] = lbl_803E1E0C;
    if (arwing != NULL)
    {
        if (arwingHudVisible != 0)
        {
            arwingHudAlpha = (int)
            (lbl_803E1FA0 * (f32)(u32)
            framesThisStep + (f32)arwingHudAlpha
            )
            ;
            if (arwingHudAlpha > 0xff)
            {
                arwingHudAlpha = 0xff;
            }
        }
        else
        {
            arwingHudAlpha = (int) - (lbl_803E1FA0 * (f32)(u32)
            framesThisStep - (f32)arwingHudAlpha
            )
            ;
            if (arwingHudAlpha < 0)
            {
                arwingHudAlpha = 0;
            }
        }
        shield = arwarwing_getShield(arwing);
        maxShield = arwarwing_getMaxShield(arwing);
        bombs = arwarwing_getBombCount(arwing);
        rings = arwarwing_getCollectedRingCount(arwing);
        req = arwarwing_getRequiredRingCount(arwing);
        if (rings > req)
        {
            rings = req;
        }
        t30 = shield >> 2;
        t23 = (shield & 3) + 0x12;
        t22 = maxShield >> 2;
        for (i = 0; (int)(v = i & 0xff) < t22; i++)
        {
            if ((int)v < t30)
            {
                t = 0x16;
            }
            else if (t30 < (int)v)
            {
                t = 0x12;
            }
            else
            {
                t = (u8)t23;
            }
            drawTexture(hudTextures[(u8)t], (f32)(int)(v * 0x21 + 0x1e), lbl_803E1FAC,
                        arwingHudAlpha & 0xff, 0x100);
        }
        for (b = 0; b < 3; b++)
        {
            pos = b * 0x1c;
            drawTexture(hudTextures[56], (f32)(pos + 0x1e), lbl_803E2060, arwingHudAlpha & 0xff, 0x100);
            if ((int)b < bombs)
            {
                drawTexture(hudTextures[57], (f32)(pos + 0x23), lbl_803E2064, arwingHudAlpha & 0xff, 0x100);
            }
        }
        if (((GameObject*)arwing)->anim.mapEventSlot != 0x26)
        {
            drawTexture(hudTextures[61], lbl_803E2068, lbl_803E1FAC, arwingHudAlpha & 0xff, 0x100);
            for (i = 0; (int)(i & 0xff) < rings; i++)
            {
                drawTexture(hudTextures[60], (f32)(int)(0x244 - (i & 0xff) * 0x14), lbl_803E1F9C,
                            arwingHudAlpha & 0xff, 0x100);
            }
            for (; (int)(v = i & 0xff) < req; i++)
            {
                drawTexture(hudTextures[59], (f32)(int)(0x244 - v * 0x14), lbl_803E1F9C,
                            arwingHudAlpha & 0xff, 0x100);
            }
            drawTexture(hudTextures[58], (f32)(int)(0x23c - v * 0x14), lbl_803E1FAC,
                        arwingHudAlpha & 0xff, 0x100);
            sprintf(buf, &lbl_803DBB60, arwarwing_getScore(arwing));
        }
        gameTextSetColor(0xff, 0xff, 0xff, arwingHudAlpha & 0xff);
        gameTextShowStr(buf, 0x93, 0x23a, 0x41);
        drawFn_80125424();
    }
}
