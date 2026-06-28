/*
 * headdisplay - HUD / overlay drawing for the in-cockpit pause-menu head
 * display (the NPC "comms" portrait box) and the Arwing flight HUD.
 *
 *  - drawFn_80125424: animates the active head-display panel (the NPC
 *    "comms" box). Scrolls the panel open/closed (gHeadDisplayPanelWidth width
 *    clamp 0x122..0x152), renders the selected character model into a
 *    side viewport, then composites the static-wave border texture and
 *    corner/edge frame tiles (hudTextures[10..13,84]).
 *  - fn_80125D04: frees the six cached head-display model objects.
 *  - gameTextFn_80125ba4: opens the head display for entry idx (clamped
 *    0..0x14), kicking off the matching audio stream (gHeadDisplayEntryTable
 *    table, 0xC-byte records: int streamId, u16 textId@+4, u16 box@+8,
 *    u8 npcDialogue@+7) and either an NPC dialogue bubble or a text box.
 *  - pauseMenuCreateHeads: lazily sets up the head model objects for
 *    slots 1..3 (the displayable characters); clears the rest.
 *  - drawArwingHud: draws the Arwing shield bar, bomb pips and ring
 *    counters; fades via arwingHudAlpha tied to arwingHudVisible.
 *
 * Most state lives in cross-TU lbl_803DD/lbl_803E globals; this TU only
 * drives the rendering.
 */
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "dolphin/gx/GXTransform.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "sfa_light_decls.h"

/* head-display panel scroll-width animation bounds */
#define HEADPANEL_WIDTH_MAX 0x152
#define HEADPANEL_WIDTH_MIN 0x122
#define HEADPANEL_WIDTH_OPEN 0x159

/* gHeadDisplayEntryTable head-display table: 0xC-byte records */
#define HEADREC_STRIDE 0xc
#define HEADREC_STREAM_ID 0    /* int  */
#define HEADREC_TEXT_ID 4      /* u16  */
#define HEADREC_PANEL_TYPE 6   /* u8   */
#define HEADREC_NPC_DIALOGUE 7 /* u8   */
#define HEADREC_BOX 8          /* u16  */


extern void doNothing_8000CF54(int a);
extern void GXSetScissor(int x, int y, int w, int h);
extern void drawRect(f32 sx, f32 sy, int x, int y);

extern void Camera_SetFovY(f32 fovY);
extern void Camera_SetCurrentViewIndex(int index);



extern void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
extern void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll);




extern void objRender(int a, int b, int c, int d, int obj, int flag);
extern int Obj_GetActiveModel(int obj);
extern float fsin16Approx(int angle);
extern void drawPartialTexture(int tex, f32 a, f32 b, u8 alpha, int scale, int c, int d, int e, int f);
extern void drawScaledTexture(int tex, f32 a, f32 b, u8 alpha, int scale, int c, int d, int e);
extern void drawTexture(int tex, f32 x, f32 y, u8 alpha, int scale);
extern u8 gHeadDisplayActive;
extern u8 gHeadDisplayEntryIdx;
extern u8 lbl_803DD7A8;
extern u16 gHeadDisplayPanelWidth;
extern u16 gHeadDisplayPanelHeight;
extern s16 gHeadDisplayFadeAlpha;
extern u16 lbl_803DD77C;
extern int lbl_803DD7E0;
extern f32 lbl_803DBAA4;
extern u8* gRenderModeObj;
extern u8 framesThisStep;
extern u8 gHeadDisplayEntryTable[];
extern int gHeadDisplayModelObjs[];
extern f32 lbl_8031BFA8[];
extern int hudTextures[];
extern f32 timeDelta;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E68;
extern const f32 lbl_803E2010;
extern f32 lbl_803E2024;
extern f32 lbl_803E2040;
extern f32 lbl_803E2044;
extern f32 lbl_803E2048;
extern const f32 lbl_803E204C;
extern const f32 lbl_803E2050;
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


extern int AudioStream_Play(int id, void (*preparedCallback)(void));
extern void* gameTextGetBox(int box);
extern void gameTextFreePhrase(u8 * phrase);
extern int lbl_8031BF90[];
extern void* Obj_AllocObjectSetup(int size, int b);
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
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);

extern u8 arwingHudVisible;
extern s16 arwingHudAlpha;
extern char sHeadDisplayScoreFmt;
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
    int i;
    s16 alpha;
    u32 height;
    u32 width;
    int type;
    int ypos;
    int alphaI;
    int alphaTmp;
    int randX;
    int randY;
    s16 panelW;
    s16 panelH;
    int xRight;
    int xLeft;
    f32 wave;
    f32 camPos;

    if (gHeadDisplayActive != 0)
    {
        if ((s8)lbl_803DD7A8 == 0)
        {
            gHeadDisplayPanelWidth = gHeadDisplayPanelWidth + framesThisStep * 5;
            if (gHeadDisplayPanelWidth > HEADPANEL_WIDTH_MAX)
            {
                gHeadDisplayPanelWidth = HEADPANEL_WIDTH_MAX;
                gHeadDisplayActive = 0;
                if (*(int*)(gHeadDisplayEntryTable + gHeadDisplayEntryIdx * HEADREC_STRIDE) != -1)
                {
                    AudioStream_StopCurrent();
                    doNothing_8000CF54(0);
                }
            }
            gHeadDisplayPanelHeight = gHeadDisplayPanelHeight - framesThisStep * 10;
            gHeadDisplayFadeAlpha = gHeadDisplayFadeAlpha - framesThisStep * 0x17;
        }
        else
        {
            gHeadDisplayPanelWidth = gHeadDisplayPanelWidth - framesThisStep * 5;
            if (gHeadDisplayPanelWidth < HEADPANEL_WIDTH_MIN)
            {
                gHeadDisplayPanelWidth = HEADPANEL_WIDTH_MIN;
            }
            gHeadDisplayPanelHeight = gHeadDisplayPanelHeight + framesThisStep * 10;
            gHeadDisplayFadeAlpha = gHeadDisplayFadeAlpha + framesThisStep * 0x17;
        }
        alphaI = gHeadDisplayFadeAlpha;
        if (alphaI < 0)
        {
            alphaI = 0;
        }
        else if (alphaI > 0xff)
        {
            alphaI = 0xff;
        }
        alpha = alphaI;
        gHeadDisplayFadeAlpha = alpha;
        height = gHeadDisplayPanelHeight;
        if (height > 0x6e)
        {
            height = 0x6e;
        }
        gHeadDisplayPanelHeight = height;
        width = gHeadDisplayPanelWidth;
        type = gHeadDisplayEntryTable[gHeadDisplayEntryIdx * HEADREC_STRIDE + HEADREC_PANEL_TYPE];
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
        camPos = lbl_803E1E3C;
        Camera_SetCurrentViewPosition(camPos, camPos, camPos);
        Camera_SetCurrentViewRotation(0x8000, 0, 0);
        Camera_UpdateViewMatrices();
        Camera_RebuildProjectionMatrix();
        GXSetViewport(lbl_803E2048, ypos - lbl_803E2024,
                      (f32)(u32) * (u16*)(gRenderModeObj + 4), (f32)(u32) * (u16*)(gRenderModeObj + 8),
                      lbl_803E1E3C, lbl_803E1E68);
        if (*(u8**)&gHeadDisplayModelObjs[type] != NULL)
        {
            ObjAnim_AdvanceCurrentMove(lbl_8031BFA8[type], timeDelta, gHeadDisplayModelObjs[type], NULL);
            if (*(u32*)(gHeadDisplayModelObjs[type] + 0x4c) > 0x90000000u)
            {
                *(u32*)(gHeadDisplayModelObjs[type] + 0x4c) = 0;
            }
            *(u8*)(gHeadDisplayModelObjs[type] + 0x37) = 0xff;
            objRender(0, 0, 0, 0, gHeadDisplayModelObjs[type], 1);
            *(u16*)(Obj_GetActiveModel(gHeadDisplayModelObjs[type]) + 0x18) &= ~8;
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
        for (i = 0; i < (int)height; i += 4)
        {
            wave = lbl_803E204C * fsin16Approx((u16)(i * 0xd48 + lbl_803DD77C * 0x1838));
            wave = lbl_803E204C * fsin16Approx((u16)(i * 0x7d0 + lbl_803DD77C * 0xfa0)) + wave;
            alphaTmp = (int)((f32)alpha * (lbl_803E2050 + wave));
            alphaI = alphaTmp < 0 ? 0 : alphaTmp;
            randX = randomGetRange(0, 0x1e) << 1;
            randY = randomGetRange(0, 0x1e) << 1;
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i),
                               (alphaI > 0xff ? 0xff : alphaI) & 0xff, 0x100, 0x78, 2, randY, randX);
            alphaI = (int)((f32)alpha * (lbl_803E2010 + wave));
            if (alphaI < 0)
            {
                alphaI = 0;
            }
            randX = randomGetRange(0, 0x1e) << 1;
            randY = randomGetRange(0, 0x1e) << 1;
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i + 2),
                               (alphaI > 0xff ? 0xff : alphaI) & 0xff, 0x100, 0x78, 2, randY, randX);
        }
        panelW = width;
        xLeft = panelW - 5;
        drawTexture(hudTextures[10], lbl_803E2054, xLeft, alpha, 0x100);
        drawScaledTexture(hudTextures[13], lbl_803E2040, xLeft, alpha, 0x100, 0x78, 5, 0);
        panelH = height;
        drawScaledTexture(hudTextures[11], lbl_803E2054, panelW, alpha, 0x100, 5, panelH, 0);
        xRight = panelW + panelH;
        drawScaledTexture(hudTextures[13], lbl_803E2040, xRight, alpha, 0x100, 0x78, 5, 2);
        drawScaledTexture(hudTextures[11], lbl_803E2058, panelW, alpha, 0x100, 5, panelH, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2058, xRight, alpha, 0x100, 5, 5, 3);
        drawScaledTexture(hudTextures[10], lbl_803E2058, xLeft, alpha, 0x100, 5, 5, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2054, xRight, alpha, 0x100, 5, 5, 2);
    }
}

void fn_80125D04(void)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        int* obj = (int*)gHeadDisplayModelObjs[i];
        if (obj != NULL)
        {
            if ((u32) * &((GameObject*)obj)->anim.placementData > 0x90000000u)
            {
                *(int*)&((GameObject*)obj)->anim.placementData = 0;
            }
            Obj_FreeObject((int*)gHeadDisplayModelObjs[i]);
            gHeadDisplayModelObjs[i] = 0;
        }
    }
}

#pragma opt_common_subs off
void gameTextFn_80125ba4(int idx)
{
    int textId;
    int boxId;

    if (gHeadDisplayActive == 0)
    {
        if (idx < 0 || idx >= 0x15)
        {
            idx = 0x14;
        }
        gHeadDisplayActive = 1;
        gHeadDisplayEntryIdx = idx;
        {
        int off = idx * HEADREC_STRIDE;
        u8* base = gHeadDisplayEntryTable;
        if (*(int*)(base + off) != -1 && AudioStream_IsPreparing() == 0)
        {
            AudioStream_Play(*(int*)(base + off), AudioStream_StartPrepared);
        }
        {
            u8* e = &gHeadDisplayEntryTable[off];
            if (e[HEADREC_NPC_DIALOGUE] != 0)
            {
                (*gGameUIInterface)->showNpcDialogue(*(u16*)(e + HEADREC_TEXT_ID), 0, 0, 0);
            }
            else
            {
                boxId = *(u16*)(e + HEADREC_BOX);
                textId = *(u16*)(e + HEADREC_TEXT_ID);
                if (textId != -1 && curGameText == 0xffff)
                {
                    gameTextGetBox(0x7c);
                    lbl_803DD7A8 = 1;
                    lbl_803DD8D0 = 0;
                    curGameText = textId;
                    lbl_803DD8C8 = 0;
                    lbl_803DD8CA = boxId;
                    lbl_803DD8CC = (f32)(s16)boxId;
                    gameTextFreePhrase(lbl_803A9440);
                    lbl_803DD7A9 = 0;
                }
            }
        }
        }
        gHeadDisplayPanelWidth = HEADPANEL_WIDTH_OPEN;
        gHeadDisplayPanelHeight = 0;
        gHeadDisplayFadeAlpha = 0;
    }
}
#pragma opt_common_subs reset

void pauseMenuCreateHeads(void)
{
    int i;
    f32 f;

    for (i = 0; i < 6; i++)
    {
        if (i != 3 && i != 2 && i != 1)
        {
            gHeadDisplayModelObjs[i] = 0;
        }
        else
        {
            if (*(void**)&gHeadDisplayModelObjs[i] == NULL)
            {
                gHeadDisplayModelObjs[i] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, lbl_8031BF90[i]), 4, -1, -1, 0);
                f = lbl_803E1E3C;
                *(f32*)(gHeadDisplayModelObjs[i] + 0xc) = f;
                *(f32*)(gHeadDisplayModelObjs[i] + 0x10) = f;
                *(f32*)(gHeadDisplayModelObjs[i] + 0x14) = lbl_803E1E5C;
                *(s16*)gHeadDisplayModelObjs[i] = 0x7447;
                *(f32*)(gHeadDisplayModelObjs[i] + 8) = lbl_803E205C;
                if (*(u32*)(gHeadDisplayModelObjs[i] + 0x4c) > 0x90000000u)
                {
                    *(u32*)(gHeadDisplayModelObjs[i] + 0x4c) = 0;
                }
                ObjAnim_SetCurrentMove(gHeadDisplayModelObjs[i], 1, lbl_803E1E3C, 0);
            }
        }
    }
}

void drawArwingHud(void)
{
    u8 buf[8];
    int* arwing;
    int shield;
    int maxShield;
    int bombs;
    int rings;
    int req;
    int fullPips;
    int partialFrame;
    int maxPips;
    u32 i;
    u32 pip;
    u8 texIdx;
    u8 bombSlot;
    int bombX;

    arwing = getArwing();
    *(int*)buf = lbl_803E1E08;
    buf[4] = lbl_803E1E0C;
    if (arwing != NULL)
    {
        if (arwingHudVisible != 0)
        {
            arwingHudAlpha = lbl_803E1FA0 * (f32)(u32)framesThisStep + arwingHudAlpha;
            if ((s16)arwingHudAlpha > 0xff)
            {
                arwingHudAlpha = 0xff;
            }
        }
        else
        {
            arwingHudAlpha = -(lbl_803E1FA0 * (f32)(u32)framesThisStep - arwingHudAlpha);
            if ((s16)arwingHudAlpha < 0)
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
        i = 0;
        fullPips = shield >> 2;
        partialFrame = (shield & 3) + 0x12;
        maxPips = maxShield >> 2;
        for (; (int)(pip = i & 0xff) < maxPips; i++)
        {
            if ((int)pip < fullPips)
            {
                texIdx = 0x16;
            }
            else if ((int)pip > fullPips)
            {
                texIdx = 0x12;
            }
            else
            {
                texIdx = partialFrame;
            }
            drawTexture(hudTextures[texIdx], (f32)(int)(pip * 0x21 + 0x1e), lbl_803E1FAC,
                        arwingHudAlpha, 0x100);
        }
        for (bombSlot = 0; bombSlot < 3; bombSlot++)
        {
            bombX = bombSlot * 0x1c;
            drawTexture(hudTextures[56], (f32)(bombX + 0x1e), lbl_803E2060, arwingHudAlpha, 0x100);
            if ((int)bombSlot < bombs)
            {
                drawTexture(hudTextures[57], (f32)(bombX + 0x23), lbl_803E2064, arwingHudAlpha, 0x100);
            }
        }
        if (((GameObject*)arwing)->anim.mapEventSlot != 0x26)
        {
            drawTexture(hudTextures[61], lbl_803E2068, lbl_803E1FAC, arwingHudAlpha, 0x100);
            for (i = 0; (int)(i & 0xff) < rings; i++)
            {
                drawTexture(hudTextures[60], (f32)(int)(0x244 - (i & 0xff) * 0x14), lbl_803E1F9C,
                            arwingHudAlpha, 0x100);
            }
            for (; (int)(pip = i & 0xff) < req; i++)
            {
                drawTexture(hudTextures[59], (f32)(int)(0x244 - pip * 0x14), lbl_803E1F9C,
                            arwingHudAlpha, 0x100);
            }
            drawTexture(hudTextures[58], (f32)(int)(0x23c - pip * 0x14), lbl_803E1FAC,
                        arwingHudAlpha, 0x100);
            sprintf((char*)buf, &sHeadDisplayScoreFmt, arwarwing_getScore(arwing));
        }
        gameTextSetColor(0xff, 0xff, 0xff, arwingHudAlpha);
        gameTextShowStr((char*)buf, 0x93, 0x23a, 0x41);
        drawFn_80125424();
    }
}
