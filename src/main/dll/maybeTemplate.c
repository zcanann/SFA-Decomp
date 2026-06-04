#include "ghidra_import.h"
#include "main/dll/maybeTemplate.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006c64();
extern undefined4 FUN_80006c78();
extern undefined4 FUN_80017448();
extern void* FUN_80017470();
extern undefined4 FUN_80017484();
extern int FUN_8001748c();
extern undefined8 FUN_80017494();
extern int FUN_800176d0();
extern undefined4 FUN_80017a90();
extern int FUN_80017a98();
extern undefined8 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_8005d370();
extern undefined4 FUN_800709d8();
extern undefined8 FUN_800709e0();
extern undefined8 FUN_800709e8();
extern undefined4 FUN_8011e458();
extern undefined4 FUN_8011e45c();
extern undefined4 FUN_8011e460();
extern undefined4 FUN_801246cc();
extern undefined8 FUN_8025da88();
extern undefined8 FUN_80286820();
extern undefined8 FUN_80286824();
extern int FUN_8028683c();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286888();
extern undefined8 FUN_8028fde8();
extern uint FUN_80294be4();
extern undefined4 FUN_80294d20();
extern int FUN_80294d38();
extern int FUN_80294d44();
extern int FUN_80294d50();
extern undefined4 FUN_80294d58();
extern undefined4 builtin_strncpy();

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);
extern void* fn_80296AE8(void* player);
extern void* fn_80296AD4(void* player);
extern int fn_80296A14(void* player);
extern int fn_80296A8C(void* player);
extern int objIsCurModelNotZero(void* obj);
extern void Sfx_KeepAliveLoopedObjectSound(int a, int b);
extern void* Sfx_PlayFromObject(int a, int b);
extern int playerGetMoney(void* player);
extern int getHudHiddenFrameCount(void);

extern undefined4 DAT_8031c340;
extern undefined4 DAT_8031c341;
extern undefined4 DAT_803a9610;
extern undefined4 DAT_803a9614;
extern undefined4 DAT_803a9618;
extern undefined4 DAT_803a961c;
extern undefined4 DAT_803a9620;
extern undefined4 DAT_803a9624;
extern undefined4 DAT_803a9628;
extern undefined4 DAT_803a962c;
extern undefined4 DAT_803a9630;
extern undefined4 DAT_803a9634;
extern undefined4 DAT_803a9694;
extern undefined4 DAT_803a96ac;
extern undefined4 DAT_803a96b0;
extern undefined4 DAT_803a96b4;
extern undefined4 DAT_803a96b8;
extern undefined4 DAT_803a96bc;
extern undefined4 DAT_803a96c0;
extern undefined4 DAT_803a96c4;
extern undefined4 DAT_803a96d4;
extern undefined4 DAT_803a96d8;
extern undefined4 DAT_803a96dc;
extern undefined4 DAT_803a9898;
extern undefined4 DAT_803a98d8;
extern undefined4 DAT_803a9e18;
extern undefined4 DAT_803a9f18;
extern undefined4 DAT_803a9f4c;
extern float* DAT_803a9f50;
extern undefined4 DAT_803a9f54;
extern float* DAT_803a9f58;
extern float* DAT_803a9f5c;
extern undefined4 DAT_803a9f60;
extern float* DAT_803a9f74;
extern float* DAT_803a9f78;
extern float* DAT_803a9f7c;
extern undefined4 DAT_803a9f80;
extern undefined4 DAT_803a9f84;
extern undefined4 DAT_803a9f88;
extern undefined4 DAT_803a9f8c;
extern undefined4 DAT_803a9f90;
extern undefined4 DAT_803a9f94;
extern undefined4 DAT_803a9fa0;
extern undefined4 DAT_803a9fa8;
extern undefined4 DAT_803a9fb4;
extern undefined4 DAT_803a9fc4;
extern undefined4 DAT_803a9fc8;
extern undefined4 DAT_803a9fcc;
extern undefined4 DAT_803a9fd0;
extern undefined4 DAT_803a9fd4;
extern undefined4 DAT_803a9fd8;
extern undefined4 DAT_803a9fe4;
extern undefined4 DAT_803aa008;
extern undefined4 DAT_803aa00c;
extern undefined4 DAT_803aa010;
extern undefined4 DAT_803aa014;
extern undefined4 DAT_803aa018;
extern undefined4 DAT_803aa01c;
extern undefined4 DAT_803aa020;
extern undefined4 DAT_803aa024;
extern undefined4 DAT_803aa028;
extern undefined4 DAT_803aa02c;
extern undefined4 DAT_803aa030;
extern undefined4 DAT_803aa034;
extern undefined4 DAT_803aa038;
extern undefined4 DAT_803aa03c;
// v1.0 symbols for minimapFn_8012310c
extern sbyte lbl_803DD7A0;
extern short lbl_803DD7A2;
extern byte framesThisStep;
extern short lbl_803DD8D2;
extern short lbl_803DBA68;
extern short lbl_803DBA6E;

// v1.0 symbols for cMenuUpdateAnims
extern byte lbl_803DBA65;
extern short lbl_803DD796;
extern short lbl_803DD78E;
extern byte cMenuOpen;
extern short cMenuFadeCounter;
extern short lbl_803DD8D6;
extern short lbl_803DBA66;

// v1.0 symbols for trickyBitFn_801241cc
extern int gTrickyHudItemMask;
extern short lbl_8031B4E0[];

extern undefined4 DAT_803dc734;
extern undefined4 DAT_803dc736;
extern undefined4 DAT_803dc738;
extern undefined4 DAT_803dc73c;
extern undefined4 DAT_803dc740;
extern undefined4 DAT_803dc744;
extern undefined4 DAT_803dc7b0;
extern undefined4 DAT_803dc7b8;
extern undefined4 DAT_803dc7c0;
extern undefined4 DAT_803dc7c4;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de3db;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de412;
extern undefined4 DAT_803de413;
extern undefined4 DAT_803de416;
extern undefined4 DAT_803de418;
extern undefined4 DAT_803de420;
extern undefined4 DAT_803de422;
extern undefined4 DAT_803de42a;
extern undefined4 DAT_803de42c;
extern undefined4 DAT_803de42e;
extern undefined4 DAT_803de430;
extern undefined4 DAT_803de431;
extern undefined4 DAT_803de432;
extern undefined4 DAT_803de433;
extern undefined4 DAT_803de450;
extern undefined4 DAT_803de4c0;
extern byte DAT_803de4c8;
extern undefined4 DAT_803de4f0;
extern undefined4 DAT_803de4f4;
extern undefined4 DAT_803de4f6;
extern undefined4 DAT_803de4fc;
extern undefined4 DAT_803de530;
extern undefined4 DAT_803de534;
extern undefined4 DAT_803de536;
extern undefined4 DAT_803de552;
extern undefined4 DAT_803de554;
extern undefined4 DAT_803e2a98;
extern undefined4 DAT_803e2a9c;
extern undefined4 DAT_803e2aa0;
extern undefined4 DAT_803e2aa4;
extern undefined4 DAT_803e2aa8;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b28;
extern f32 lbl_803DC074;
extern f32 lbl_803DC6DC;
extern f32 lbl_803DC6E0;
extern f32 lbl_803DC6E4;
extern f32 lbl_803DC6E8;
extern f32 lbl_803DC6EC;
extern f32 lbl_803DE468;
extern f32 lbl_803DE4BC;
extern f32 lbl_803DE4C4;
extern f32 lbl_803DE4F8;
extern f32 lbl_803E2ABC;
extern f32 lbl_803E2AE8;
extern f32 lbl_803E2AF0;
extern f32 lbl_803E2B40;
extern f32 lbl_803E2C1C;
extern f32 lbl_803E2C20;
extern f32 lbl_803E2C28;
extern f32 lbl_803E2C34;
extern f32 lbl_803E2C38;
extern f32 lbl_803E2C3C;
extern f32 lbl_803E2C40;
extern f32 lbl_803E2C44;
extern f32 lbl_803E2C48;
extern f32 lbl_803E2C4C;
extern f32 lbl_803E2C50;
extern f32 lbl_803E2C54;
extern f32 lbl_803E2C58;
extern f32 lbl_803E2C5C;
extern f32 lbl_803E2C60;
extern f32 lbl_803E2C64;
extern f32 lbl_803E2C68;
extern f32 lbl_803E2C6C;
extern f32 lbl_803E2C70;
extern f32 lbl_803E2C74;
extern f32 lbl_803E2C78;
extern f32 lbl_803E2C7C;
extern f32 lbl_803E2C80;
extern f32 lbl_803E2C84;
extern f32 lbl_803E2C88;
extern f32 lbl_803E2C8C;
extern f32 lbl_803E2C90;
extern f32 lbl_803E2C94;
extern f32 lbl_803E2C98;
extern char s__02d__02d_8031cd00[];
extern undefined uRam803de4c9;
extern undefined2 uRam803de4ca;
extern undefined uRam803de4cb;
extern undefined4 uRam803de4cc;
extern undefined uRam803de4cd;
extern undefined2 uRam803de4ce;

/*
 * --INFO--
 *
 * Function: hudDrawMagicBar
 * EN v1.0 Address: 0x80121C4C
 * EN v1.0 Size: 0x9A8
 * EN v1.1 Address: 0x80121F30
 * EN v1.1 Size: 2472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hudDrawMagicBar(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_80286824();
  iVar6 = DAT_803a9fe4;
  iVar3 = DAT_803a9fcc;
  uVar2 = (uint)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)uVar13;
  iVar11 = DAT_803a9fe4 + -0xd;
  iVar12 = DAT_803a9fcc;
  if (7 < DAT_803a9fcc) {
    iVar12 = 7;
  }
  if (iVar12 != 0) {
    iVar12 = iVar12 + 1;
  }
  iVar8 = 8 - iVar12;
  iVar9 = DAT_803a9fcc + -7;
  if (iVar11 < DAT_803a9fcc + -7) {
    iVar9 = iVar11;
  }
  if (iVar9 < 1) {
    iVar9 = 0;
  }
  iVar7 = iVar11 - iVar9;
  iVar1 = (DAT_803a9fcc + -7) - iVar11;
  if (5 < iVar1) {
    iVar1 = 5;
  }
  if (iVar1 < 1) {
    iVar1 = 0;
  }
  if (DAT_803a9fcc == DAT_803a9fe4) {
    iVar1 = 7;
  }
  iVar10 = 0x10 - iVar1;
  uVar5 = (undefined)((ulonglong)uVar13 >> 0x20);
  if ((param_3 & 0xff) == 0) {
    FUN_800709e8((double)(f32)(s32)(DAT_803dc740),
                 (double)(f32)(s32)(DAT_803dc744),DAT_803a96ac,uVar2,0x100);
  }
  else {
    FUN_8011e460((double)(f32)(s32)(DAT_803dc738),
                 (double)(f32)(s32)(DAT_803dc73c),DAT_803a96ac,iVar4,uVar5,0x100,0);
  }
  if (iVar12 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(f32)(s32)(DAT_803dc740 + 0x1c),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96b0,uVar2,0x100,iVar12,0x12,0);
    }
    else {
      FUN_8011e45c((double)(f32)(s32)(DAT_803dc738 + 0x1c),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96b0,iVar4,uVar5,0x100,iVar12,0x12,0);
    }
  }
  if (iVar8 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709d8((double)(f32)(s32)(iVar12 + DAT_803dc740 + 0x1c),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96b4,uVar2,0x100,iVar8,0x12,iVar12,0);
    }
    else {
      FUN_8011e458((double)(f32)(s32)(iVar12 + DAT_803dc738 + 0x1c),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96b4,iVar4,uVar5,iVar8,0x12,iVar12,0);
    }
  }
  if (iVar9 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(f32)(s32)(DAT_803dc740 + 0x24),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96b8,uVar2,0x100,iVar9,0x12,0);
    }
    else {
      FUN_8011e45c((double)(f32)(s32)(DAT_803dc738 + 0x24),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96b8,iVar4,uVar5,0x100,iVar9,0x12,0);
    }
  }
  if (iVar7 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(f32)(s32)(iVar9 + DAT_803dc740 + 0x24),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96bc,uVar2,0x100,iVar7,0x12,0);
    }
    else {
      FUN_8011e45c((double)(f32)(s32)(iVar9 + DAT_803dc738 + 0x24),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96bc,iVar4,uVar5,0x100,iVar7,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(f32)(s32)(iVar11 + DAT_803dc740 + 0x24),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96c0,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011e45c((double)(f32)(s32)(iVar11 + DAT_803dc738 + 0x24),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96c0,iVar4,uVar5,0x100,iVar1,0x12,0);
    }
  }
  if (iVar10 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709d8((double)(f32)(s32)(iVar11 + iVar1 + DAT_803dc740 + 0x24),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96c4,uVar2,0x100,iVar10,0x12,iVar1,0);
    }
    else {
      FUN_8011e458((double)(f32)(s32)(iVar11 + iVar1 + DAT_803dc738 + 0x24),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96c4,iVar4,uVar5,iVar10,0x12,iVar1,0);
    }
  }
  iVar3 = iVar3 - (uint)DAT_803de433;
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  if (iVar3 != 0) {
    iVar3 = iVar3 + 1;
  }
  if (iVar3 == iVar6) {
    iVar3 = iVar3 + 1;
  }
  iVar6 = iVar3;
  if (8 < iVar3) {
    iVar6 = 8;
  }
  iVar12 = iVar12 - iVar6;
  iVar8 = iVar3 + -8;
  if (iVar11 < iVar3 + -8) {
    iVar8 = iVar11;
  }
  if (iVar8 < 1) {
    iVar8 = 0;
  }
  iVar9 = iVar9 - iVar8;
  iVar3 = (iVar3 + -8) - iVar11;
  if (8 < iVar3) {
    iVar3 = 8;
  }
  if (iVar3 < 1) {
    iVar3 = 0;
  }
  iVar1 = iVar1 - iVar3;
  if (iVar12 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709d8((double)(f32)(s32)(iVar6 + DAT_803dc740 + 0x1c),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96d4,uVar2,0x100,iVar12,0x12,iVar6,0);
    }
    else {
      FUN_8011e458((double)(f32)(s32)(iVar6 + DAT_803dc738 + 0x1c),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96d4,iVar4,uVar5,iVar12,0x12,iVar6,0);
    }
  }
  if (iVar9 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(f32)(s32)(iVar8 + DAT_803dc740 + 0x24),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96d8,uVar2,0x100,iVar9,0x12,0);
    }
    else {
      FUN_8011e45c((double)(f32)(s32)(iVar8 + DAT_803dc738 + 0x24),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96d8,iVar4,uVar5,0x100,iVar9,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_800709e0((double)(f32)(s32)(iVar11 + iVar3 + DAT_803dc740 + 0x24),
                   (double)(f32)(s32)(DAT_803dc744),DAT_803a96dc,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011e45c((double)(f32)(s32)(iVar11 + iVar3 + DAT_803dc738 + 0x24),
                   (double)(f32)(s32)(DAT_803dc73c),DAT_803a96dc,iVar4,uVar5,0x100,iVar1,0x12,0);
    }
  }
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: hudDrawCounter
 * EN v1.0 Address: 0x801225F4
 * EN v1.0 Size: 0x308
 * EN v1.1 Address: 0x801228D8
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int gameTextFn_80019b14(void);
extern void gameTextSetCharset(int charset, int arg);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShowStr(char *str, int box, int x, int y);
extern void drawTexture(int texture, f32 x, f32 y, int alpha, int arg);
extern void sprintf(char *buf, const char *fmt, ...);
extern int hudTextures[];
extern char sTemplateProgressCounterFormat[];
extern char lbl_803DBB48;
extern char lbl_803DBB50;
extern char lbl_803DBB58;
extern u32 lbl_803E1E1C;
extern u32 lbl_803E1E20;
extern u32 lbl_803E1E24;
extern u32 lbl_803E1E28;
extern f32 lbl_803E1E68;
extern f32 lbl_803E1E70;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E1FA8;
extern f32 lbl_803E1FB8;

typedef struct CounterText {
  u32 a;
  u32 b;
} CounterText;

void hudDrawCounter(int idx, s16 value, s16 target, u8 alpha, int timer, int *yPos, u8 showTarget)
{
  int prevCharset;
  int tex;
  CounterText buf1;
  CounterText buf2;
  f32 width;

  buf1 = *(CounterText *)&lbl_803E1E1C;
  buf2 = *(CounterText *)&lbl_803E1E24;
  if (alpha != 0) {
    if (((f32)timer < lbl_803E1F9C) || ((f32)timer > lbl_803E1FA8) || ((timer & 8) != 0) ||
        (idx == 30)) {
      tex = hudTextures[idx];
      drawTexture(tex, (f32)(575 - *yPos), lbl_803E1FB8, alpha, 256);
      if (idx == 30) {
        if (showTarget != 0) {
          sprintf((char *)&buf1, sTemplateProgressCounterFormat, value < 0 ? -value : value, target);
          sprintf((char *)&buf2, &lbl_803DBB48, value < 0 ? -value : value);
        }
        else {
          sprintf((char *)&buf1, &lbl_803DBB50, value);
        }
      }
      else {
        sprintf((char *)&buf1, &lbl_803DBB58, value);
      }
      prevCharset = gameTextFn_80019b14();
      gameTextSetCharset(3, 3);
      gameTextMeasureString((u8 *)&buf1, lbl_803E1E68, &width, NULL, NULL, NULL, -1);
      if ((showTarget == 0) && (value >= target)) {
        gameTextSetColor(0, 0xFF, 0, alpha);
      }
      else {
        gameTextSetColor(0xFF, 0xFF, 0xFF, alpha);
      }
      gameTextShowStr((char *)&buf1, 0x93, (int)-(lbl_803E1E70 * width - (f32)(591 - *yPos)), 0x1A9);
      if (showTarget != 0) {
        if (value >= 0) {
          gameTextSetColor(0, 0xFF, 0, alpha);
        }
        else {
          gameTextSetColor(0xFF, 0, 0, alpha);
        }
        gameTextShowStr((char *)&buf2, 0x93, (int)-(lbl_803E1E70 * width - (f32)(591 - *yPos)), 0x1A9);
      }
      gameTextSetCharset(prevCharset, 3);
    }
    *yPos = *yPos + 0x28;
  }
}

/*
 * --INFO--
 *
 * Function: pauseMenuDrawStatus
 * EN v1.0 Address: 0x801228FC
 * EN v1.0 Size: 0x810
 * EN v1.1 Address: 0x80122BE0
 * EN v1.1 Size: 2064b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int *gMapEventInterface;
extern int *gScreenTransitionInterface;
extern int *gCameraInterface;
extern int lbl_803A87F0[];
extern f32 lbl_803DD83C;
extern u8 lbl_803DD75B;
extern u8 lbl_803DD792;
extern u8 lbl_803DD793;
extern u8 lbl_803DD840;
extern f32 lbl_803DD844;
extern u8 pauseMenuState;
extern u8 cMenuEnabled;
extern int airMeter;
extern f32 hudElementOpacity;
extern f32 timeDelta;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1FA0;
extern f32 lbl_803E1FBC;
extern f32 lbl_803E1FC0;
extern f32 lbl_803E1FC4;
extern f32 lbl_803E1FC8;

#define PMDS_MAP_EVENT_GET_STATUS() \
  ((u8 *(*)(void))(*(u32 *)((u8 *)*gMapEventInterface + 0x94)))()
#define PMDS_SCREEN_GET_FADE() \
  ((f32 (*)(void))(*(u32 *)((u8 *)*gScreenTransitionInterface + 0x18)))()
#define PMDS_CAMERA_GET_STATE() \
  ((int (*)(void))(*(u32 *)((u8 *)*gCameraInterface + 0x10)))()

void pauseMenuDrawStatus(void)
{
  u8 *player;
  u8 *trickyStatus;
  u8 *base;
  int delta;
  s8 negDelta;
  f32 *op;
  u8 *bp;
  int *dp;
  int bit;
  u8 i;
  u8 j;
  u32 ji;
  int off;
  int cur;
  int sv;
  f32 thresh;
  f32 prev;
  int statuses[13];

  base = (u8 *)lbl_803A87F0;
  player = (u8 *)Obj_GetPlayerObject();
  getTrickyObject();
  trickyStatus = PMDS_MAP_EVENT_GET_STATUS();
  statuses[0] = (int)fn_80296AE8(player);
  statuses[7] = (int)fn_80296AD4(player);
  statuses[1] = GameBit_Get(0xC1);
  if (*(int *)(base + 0xB38) - fn_80296A14(player) < 0) {
    delta = -1;
  }
  else if (*(int *)(base + 0xB38) - fn_80296A14(player) > 0) {
    delta = 1;
  }
  else {
    delta = 0;
  }
  statuses[2] = *(int *)(base + 0xB38) - delta;
  if (*(int *)(base + 0xB50) - fn_80296A8C(player) < 0) {
    delta = -1;
  }
  else if (*(int *)(base + 0xB50) - fn_80296A8C(player) > 0) {
    delta = 1;
  }
  else {
    delta = 0;
  }
  negDelta = -delta;
  statuses[8] = *(int *)(base + 0xB50) + negDelta;
  if ((negDelta != 0) && (lbl_803DD83C != lbl_803E1E3C) &&
      (objIsCurModelNotZero(player) != 0) && (GameBit_Get(0xEB1) != 0)) {
    Sfx_KeepAliveLoopedObjectSound(0, 0x3F0);
  }
  *(int *)(base + 0xB7C) = statuses[2];
  *(int *)(base + 0xB94) = statuses[8];
  statuses[4] = GameBit_Get(0x66C);
  statuses[10] = GameBit_Get(0x13D);
  if (statuses[10] != *(int *)(base + 0xB58)) {
    u8 flag = statuses[10] == 0;
    GameBit_Set(0x967, flag);
  }
  statuses[11] = GameBit_Get(0x86A);
  statuses[12] = GameBit_Get(0x3F5);
  statuses[3] = playerGetMoney(player);
  statuses[9] = *trickyStatus;
  if ((((lbl_803DD792 & 1) != 0) ||
       ((lbl_803E1E3C == PMDS_SCREEN_GET_FADE()) && (PMDS_CAMERA_GET_STATE() != 0x44) &&
        ((*(u16 *)(player + 0xB0) & 0x1000) == 0) && (getHudHiddenFrameCount() == 0) &&
        (lbl_803DD75B == 0))) &&
      (pauseMenuState == 0)) {
    lbl_803DD83C = lbl_803E1FA0 * timeDelta + lbl_803DD83C;
    if (lbl_803DD83C > hudElementOpacity) {
      lbl_803DD83C = hudElementOpacity;
    }
  }
  else {
    lbl_803DD83C = -(lbl_803E1FA0 * timeDelta - lbl_803DD83C);
    if (lbl_803DD83C < lbl_803E1E3C) {
      lbl_803DD83C = lbl_803E1E3C;
    }
  }
  if ((cMenuEnabled == 0) && (GameBit_Get(0xA7B) != 0)) {
    cMenuEnabled = 1;
  }
  for (i = 0; i < 13; i++) {
    switch (i) {
    case 1:
    case 3:
    case 4:
    case 10:
    case 11:
    case 12:
      off = i * 4;
      if (((((f32 *)(base + 0xAFC))[i] >= lbl_803E1E3C) &&
           ((*(u16 *)(player + 0xB0) & 0x1000) == 0) && (pauseMenuState == 0) &&
           (airMeter == 0) && (getHudHiddenFrameCount() == 0) &&
           (PMDS_CAMERA_GET_STATE() != 0x44)) ||
          ((i == 3) && ((lbl_803DD792 & 2) != 0))) {
        op = (f32 *)(base + 0xAC8) + i;
        *op = lbl_803E1FA0 * timeDelta + *op;
        if (*op > hudElementOpacity) {
          *op = hudElementOpacity;
        }
      }
      else {
        op = (f32 *)(base + 0xAC8) + i;
        *op = -(lbl_803E1FA0 * timeDelta - *op);
        if (*op < lbl_803E1E3C) {
          *op = lbl_803E1E3C;
        }
      }
      break;
    }
  }
  i = 0;
  statuses[6] = 0;
  if ((lbl_803DD840 & 1) != 0) {
    lbl_803DD840 = lbl_803DD840 & ~1;
    for (j = 0; j < 13; j++) {
      ((int *)(base + 0xB74))[j] = statuses[j];
      ((int *)(base + 0xB30))[j] = statuses[j];
      ((f32 *)(base + 0xAFC))[j] = lbl_803E1FBC;
    }
    if ((GameBit_Get(0xB98) != 0) || (statuses[4] != 0)) {
      *(f32 *)(base + 0xB0C) = lbl_803E1FC0;
    }
    if ((GameBit_Get(0xB99) != 0) || (statuses[1] != 0)) {
      *(f32 *)(base + 0xB00) = lbl_803E1FC0;
    }
    if ((GameBit_Get(0xB9A) != 0) || (statuses[10] != 0)) {
      *(f32 *)(base + 0xB24) = lbl_803E1FC0;
    }
    if ((GameBit_Get(0xB9B) != 0) || (statuses[11] != 0)) {
      *(f32 *)(base + 0xB28) = lbl_803E1FC0;
    }
    if ((GameBit_Get(0xB9C) != 0) || (statuses[3] != 0)) {
      *(f32 *)(base + 0xB08) = lbl_803E1FC0;
    }
    if ((GameBit_Get(0xD97) != 0) || (statuses[12] != 0)) {
      *(f32 *)(base + 0xB2C) = lbl_803E1FC0;
    }
    lbl_803DD844 = lbl_803E1E3C;
  }
  else {
    thresh = lbl_803E1FA8;
    for (; i < 13; i++) {
      ji = i;
      op = ((f32 *)(base + 0xAFC)) + ji;
      prev = *op;
      *op = prev - timeDelta;
      if ((prev > thresh) && (*op <= thresh)) {
        switch (ji) {
        case 3:
          Sfx_PlayFromObject(0, 0x38D);
          dp = ((int *)(base + 0xB74)) + ji;
          cur = *dp;
          sv = statuses[ji];
          if (cur > sv) {
            *dp = cur - 1;
          }
          else {
            *dp = cur + 1;
          }
          if (*dp != sv) {
            *op = lbl_803E1FC4;
          }
          break;
        default:
          ((int *)(base + 0xB74))[ji] = statuses[ji];
          break;
        }
      }
      if (statuses[ji] != 0) {
        bp = base + ji + 0xB64;
        if (*bp == 0) {
          bit = 0;
          switch (i) {
          case 3:
            bit = 0xB9C;
            break;
          case 4:
            bit = 0xB98;
            break;
          case 1:
            bit = 0xB99;
            break;
          case 10:
            bit = 0xB9A;
            break;
          case 11:
            bit = 0xB9B;
            break;
          case 12:
            bit = 0xD97;
            break;
          }
          if (bit != 0) {
            GameBit_Set(bit, 1);
            *bp = 1;
          }
        }
      }
      if (statuses[ji] != ((int *)(base + 0xB30))[ji]) {
        ((int *)(base + 0xB30))[ji] = statuses[ji];
        if (*op <= lbl_803E1FA8) {
          *op = lbl_803E1FC8 - timeDelta;
        }
      }
      switch (i) {
      case 1:
      case 3:
      case 4:
      case 10:
      case 11:
      case 12:
        if ((prev > lbl_803E1E3C) && (*op <= lbl_803E1E3C)) {
          *op = lbl_803E1FC0;
        }
        break;
      default:
        if (*op < lbl_803E1FBC) {
          *op = lbl_803E1FBC;
        }
        break;
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: minimapFn_8012310c
 * EN v1.0 Address: 0x8012310C
 * EN v1.0 Size: 0xF8
 * EN v1.1 Address: 0x801233F0
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void minimapFn_8012310c(void)
{
  if (lbl_803DD7A0 != '\0') {
    lbl_803DD7A2 = lbl_803DD7A2 + framesThisStep * 0x20;
    if (0xff < lbl_803DD7A2) {
      lbl_803DD7A2 = 0xff;
    }
  }
  else {
    if (lbl_803DD8D2 == 0) {
      lbl_803DD7A2 = lbl_803DD7A2 - framesThisStep * 0x20;
      if (lbl_803DD7A2 < 0) {
        lbl_803DD7A2 = 0;
      }
    }
  }
  if ((lbl_803DD7A0 != '\0') && (lbl_803DD7A2 == 0xff)) {
    lbl_803DD8D2 = lbl_803DD8D2 + framesThisStep * 4;
    if (lbl_803DBA68 < lbl_803DD8D2) {
      lbl_803DD8D2 = lbl_803DBA68;
    }
  }
  else {
    lbl_803DD8D2 = lbl_803DD8D2 - framesThisStep * 4;
    if (lbl_803DD8D2 < 0) {
      lbl_803DD8D2 = 0;
    }
  }
  if (lbl_803DD7A2 != 0) {
    return;
  }
  lbl_803DBA6E = 0xffff;
  return;
}

/*
 * --INFO--
 *
 * Function: hudDrawButtons
 * EN v1.0 Address: 0x80123204
 * EN v1.0 Size: 0xE64
 * EN v1.1 Address: 0x801234E8
 * EN v1.1 Size: 3684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void GXSetScissor(int x, int y, int w, int h);
extern void hudDrawCMenu(int a, int b, int c);
extern int gameTextGet();
extern void gameTextMeasureFn_800163c4(char *str, int n, int a, int b, int *x0, int *x1, int *y0, int *y1);
extern void drawScaledTexture(int texture, f32 x, f32 y, int alpha, int arg, int w, int h, int mode);
extern void textureFree(int texture);
extern int textureLoadAsset(int id);
extern void fn_8005D118(int a, int b, int c, int d, int e);
extern s16 cMenuFadeCounter;
extern int lbl_803DD8B0;
extern s16 lbl_803DD8B4;
extern s8 lbl_803DD8B6;
extern s16 lbl_803DD796;
extern u8 lbl_803DD848[7];
extern u8 lbl_803DD8D4;
extern int hudYButtonItemIconTexture;
extern s16 yButtonItemTextureId;
extern s16 lbl_803DD876;
extern s16 aButtonIcon;
extern s16 prevAButtonIcon;
extern u8 bButtonIcon;
extern u8 lbl_803DD7B0;
extern u8 lbl_803DD7B1;
extern u8 lbl_803DD7B2;
extern u8 lbl_803DD87C;
extern f32 lbl_803DD878;
extern f32 lbl_803DD7E8;
extern f32 lbl_803DBA74;
extern f32 lbl_803DBA78;
extern f32 lbl_803DBA7C;
extern f32 lbl_803DBA80;
extern f32 lbl_803DBA84;
extern s16 lbl_803DBACC;
extern s16 lbl_803DBACE;
extern u8 lbl_8031B6F0[];
extern char lbl_803DBB5C;
extern u32 lbl_803E1E18;
extern f64 lbl_803E1EA8;
extern f32 lbl_803E1FB4;
extern f32 lbl_803E1FCC;
extern f32 lbl_803E1FD0;
extern f32 lbl_803E1FD4;
extern f32 lbl_803E1FD8;
extern f32 lbl_803E1FDC;
extern f32 lbl_803E1FE0;
extern f32 lbl_803E1FE4;
extern f32 lbl_803E1FE8;
extern f32 lbl_803E1FEC;
extern f32 lbl_803E1FF0;
extern f32 lbl_803E1FF4;
extern f32 lbl_803E1FF8;
extern f32 lbl_803E1FFC;
extern f32 lbl_803E2000;
extern f32 lbl_803E2004;
extern f32 lbl_803E200C;
extern f32 lbl_803E2008;
extern f32 lbl_803E2010;
extern f32 lbl_803E2014;
extern f32 lbl_803E2018;

void hudDrawButtons(int param1, int param2, int param3)
{
  char slots[68];
  u32 label;
  int ax0;
  int ax1;
  int ay0;
  int ay1;
  int bx0;
  int bx1;
  int by0;
  int by1;
  int am3;
  int am2;
  int am1;
  int am0;
  int bm3;
  int bm2;
  int bm1;
  int bm0;
  u8 *base;
  void *player;
  u8 *gp;
  s16 fade;
  int slotCount;
  int sel;
  int k;
  int i;
  int yOff;
  u8 *iconPtr;
  s16 alpha;
  s16 rowFade;
  s16 a16;
  int prevCharset;
  int prevCharset2;
  int textObj;
  int textPtr;
  u32 glyph;
  int wid;
  u8 bi;
  int icon;
  f32 scaleT;
  f64 dv;

  base = (u8 *)lbl_803A87F0;
  player = Obj_GetPlayerObject();
  label = lbl_803E1E18;
  icon = 0;
  if ((cMenuFadeCounter != 0) && (cMenuEnabled != 0)) {
    slotCount = 3;
    sel = 1;
    for (i = 0; i < lbl_803DD8B0; i++) {
      slots[i] = 0;
    }
    for (; i < 3; i++) {
      slots[i] = 1;
    }
    if (lbl_803DD8B0 < 3) {
      lbl_803DD8B0 = 3;
    }
    if (lbl_803DD796 > 0) {
      sel = 2;
      slotCount = 4;
      if (lbl_803DD796 > 0x32) {
        sel = 3;
      }
    }
    else if ((lbl_803DD796 < 0) && (slotCount = 4, lbl_803DD796 < -0x32)) {
      sel = 0;
    }
    k = lbl_803DD8B4 - sel;
    if (k < 0) {
      k = k + lbl_803DD8B0;
    }
    if (k >= lbl_803DD8B0) {
      k = k - lbl_803DD8B0;
    }
    fade = cMenuFadeCounter;
    iconPtr = lbl_803DD848;
    for (i = 0; i < 7; i++) {
      ((int *)(base + 0xBD4))[i] = 0;
      iconPtr[i] = 0;
      ((int *)(base + 0xBB8))[i] = 0;
    }
    for (i = 0; i < slotCount; i++) {
      if (slots[k] == 0) {
        GXSetScissor(0, 0, 0x280, 0x1E0);
        ((int *)(base + 0xBD4))[(i + 3) - sel] = ((int *)(base + 0x9C8))[k];
        ((int *)(base + 0xBB8))[(i + 3) - sel] = ((u8 *)(base + 0x488))[k];
        if (((u8 *)(base + 0x448))[k] > 1) {
          lbl_803DD848[(i + 3) - sel] = ((u8 *)(base + 0x448))[k];
        }
      }
      k = k + 1;
      if (k >= lbl_803DD8B0) {
        k = k - lbl_803DD8B0;
      }
    }
    GXSetScissor(0, 0, 0x280, 0x1E0);
    hudDrawCMenu(param1, param2, param3);
    i = 0;
    yOff = i;
    do {
      if (*iconPtr > 1) {
        alpha = fade;
        rowFade = lbl_803DD796 + yOff;
        if (rowFade < lbl_803DBACC) {
          alpha = fade + (rowFade - lbl_803DBACC) * 8;
        }
        if (rowFade > lbl_803DBACE) {
          alpha = alpha - (rowFade - lbl_803DBACE) * 8;
        }
        if (alpha < 0) {
          alpha = 0;
        }
        if (alpha > 0xFF) {
          alpha = 0xFF;
        }
        a16 = alpha * lbl_803DD8D4 / 0xFF;
        GXSetScissor(0, 0, 0x280, 0x1E0);
        sprintf((char *)&label, &lbl_803DBB58, *iconPtr);
        gameTextSetColor(0, 0, 0, a16 & 0xFF);
        gameTextShowStr((char *)&label, 0x93, 0x247, 0x2B + yOff + lbl_803DD796);
        gameTextSetColor(0xFF, 0xFF, 0xFF, a16 & 0xFF);
        gameTextShowStr((char *)&label, 0x93, 0x246, 0x2A + yOff + lbl_803DD796);
      }
      iconPtr = iconPtr + 1;
      yOff += 0x32;
      i++;
    } while (i < 7);
    drawTexture(*(int *)(base + 0x244), lbl_803E1FCC, lbl_803E1FD0, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100);
    drawScaledTexture(*(int *)(base + 0x244), lbl_803E1FD4, lbl_803E1FD0, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100, 0x12, 10, 1);
    drawScaledTexture(*(int *)(base + 0x244), lbl_803E1FCC, lbl_803E1FD8, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100, 0x12, 10, 2);
    drawScaledTexture(*(int *)(base + 0x244), lbl_803E1FD4, lbl_803E1FD8, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100, 0x12, 10, 3);
    if ((player != NULL) && (objIsCurModelNotZero(player) != 0)) {
      if (lbl_803DD8B6 != 1) {
        if (lbl_803DD8B6 < 1) {
          if (lbl_803DD8B6 < 0) {
          } else {
            icon = 0x59;
          }
        } else if (lbl_803DD8B6 < 3) {
          icon = 0x58;
        }
      } else {
        icon = 0x5A;
      }
      drawTexture(((int *)(base + 0x1C0))[icon], lbl_803E1FDC, lbl_803E1FB4, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100);
    }
  }
  if (((u32)hudYButtonItemIconTexture != 0) && (lbl_803DD876 != yButtonItemTextureId)) {
    textureFree(hudYButtonItemIconTexture);
    lbl_803DD876 = -1;
    hudYButtonItemIconTexture = 0;
  }
  if ((hudYButtonItemIconTexture == 0) && (yButtonItemTextureId > 0)) {
    lbl_803DD876 = yButtonItemTextureId;
    hudYButtonItemIconTexture = textureLoadAsset(yButtonItemTextureId);
  }
  if (lbl_803DD83C != lbl_803E1E3C) {
    drawTexture(((int *)(base + 0x1C0))[0], lbl_803E1FE0, lbl_803E1F9C, (int)lbl_803DD83C, 0x100);
    drawTexture(((int *)(base + 0x1C0))[1], lbl_803E1FE4, lbl_803E1FE8, (int)lbl_803DD83C, 0x100);
    drawTexture(((int *)(base + 0x1C0))[2], lbl_803E1FEC, lbl_803E1FF0, (int)lbl_803DD83C, 0x100);
    if ((lbl_803DD7B1 & 8) == 0) {
      drawTexture(((int *)(base + 0x1C0))[9], lbl_803E1FF4, lbl_803E1FF8, (int)lbl_803DD83C, 0x100);
    }
    if ((aButtonIcon != 0) && (aButtonIcon != 0x1C)) {
      if (aButtonIcon != prevAButtonIcon) {
        lbl_803DD7B1 = 0x3F;
      }
      if (lbl_803DD7B1 != 0) {
        lbl_803DD7B1 = lbl_803DD7B1 - 1;
      }
      if (lbl_803DD7B1 & 8) {
        gameTextSetColor(0x32, 0x32, 0xFF, (int)lbl_803DD83C);
      }
      else {
        gameTextSetColor(200, 0xE6, 0xFF, (int)lbl_803DD83C);
      }
      prevCharset = gameTextFn_80019b14();
      gameTextSetCharset(3, 3);
      if (aButtonIcon > 0x3E8) {
        textObj = gameTextGet();
        icon = 1;
      }
      else {
        for (bi = 0; bi < 0x1D; bi++) {
          if (aButtonIcon == lbl_8031B6F0[bi * 2]) {
            icon = bi;
          }
        }
        textObj = gameTextGet(0x2AD);
      }
      if (icon != 0 && (void *)textObj != NULL && *(u16 *)(textObj + 2) > *(gp = lbl_8031B6F0 + icon * 2 + 1)) {
        textPtr = *(int *)(*(int *)(textObj + 8) + *gp * 4);
        prevCharset2 = gameTextFn_80019b14();
        gameTextSetCharset(3, 3);
        gameTextMeasureFn_800163c4((char *)textPtr, 8, 0, 0, &am0, &am1, &am2, &am3);
        gameTextShowStr((char *)textPtr, 8, 0, 0);
        gameTextSetCharset(prevCharset2, 3);
        gameTextMeasureFn_800163c4(*(char **)(*(int *)(textObj + 8) + *gp * 4), 8, 0, 0, &ax0, &ax1, &ay0, &ay1);
        wid = (ax1 - ax0) + -0x19;
        if (wid < 1) {
          wid = 1;
        }
        drawScaledTexture(((int *)(base + 0x1C0))[8], (f32)(0x219 - wid), lbl_803E1FFC, (int)lbl_803DD83C, 0x100, wid, 0x16, 0);
        drawTexture(((int *)(base + 0x1C0))[7], (f32)(0x20D - wid), lbl_803E1FFC, (int)lbl_803DD83C, 0x100);
      }
      else {
        drawTexture(((int *)(base + 0x1C0))[7], lbl_803E2000, lbl_803E1FFC, (int)lbl_803DD83C, 0x100);
      }
      prevAButtonIcon = aButtonIcon;
      drawTexture(((int *)(base + 0x1C0))[5], lbl_803E1FCC, lbl_803E1FFC, (int)lbl_803DD83C, 0x100);
      gameTextSetCharset(prevCharset, 3);
    }
    else {
      drawTexture(((int *)(base + 0x1C0))[3], lbl_803E1FCC, lbl_803E1FFC, (int)lbl_803DD83C, 0x100);
      prevAButtonIcon = 0;
      lbl_803DD7B1 = 0;
    }
    if (bButtonIcon != 0) {
      if (bButtonIcon != lbl_803DD7B0) {
        lbl_803DD7B2 = 0x3F;
      }
      if (lbl_803DD7B2 != 0) {
        lbl_803DD7B2 = lbl_803DD7B2 - 1;
      }
      if (lbl_803DD7B2 & 8) {
        gameTextSetColor(0x32, 0x32, 0xFF, (int)lbl_803DD83C);
      }
      else {
        gameTextSetColor(200, 0xE6, 0xFF, (int)lbl_803DD83C);
      }
      icon = 0;
      for (bi = icon; bi < 0x1D; bi++) {
        if (bButtonIcon == lbl_8031B6F0[bi * 2]) {
          icon = bi;
        }
      }
      prevCharset = gameTextFn_80019b14();
      gameTextSetCharset(3, 3);
      textObj = gameTextGet(0x2AD);
      if (icon != 0 && (void *)textObj != NULL && *(u16 *)(textObj + 2) > *(gp = lbl_8031B6F0 + icon * 2 + 1)) {
        textPtr = *(int *)(*(int *)(textObj + 8) + *gp * 4);
        prevCharset2 = gameTextFn_80019b14();
        gameTextSetCharset(3, 3);
        gameTextMeasureFn_800163c4((char *)textPtr, 9, 0, 0, &bm0, &bm1, &bm2, &bm3);
        gameTextShowStr((char *)textPtr, 9, 0, 0);
        gameTextSetCharset(prevCharset2, 3);
        gameTextMeasureFn_800163c4(*(char **)(*(int *)(textObj + 8) + *gp * 4), 9, 0, 0, &bx0, &bx1, &by0, &by1);
        wid = (bx1 - bx0) + -7;
        if (wid < 1) {
          wid = 1;
        }
        drawScaledTexture(((int *)(base + 0x1C0))[8], (f32)(0x219 - wid), lbl_803E2004, (int)lbl_803DD83C, 0x100, wid, 0x16, 0);
        drawTexture(((int *)(base + 0x1C0))[7], (f32)(0x20D - wid), lbl_803E2004, (int)lbl_803DD83C, 0x100);
      }
      else {
        drawTexture(((int *)(base + 0x1C0))[7], lbl_803E2008, lbl_803E2004, (int)lbl_803DD83C, 0x100);
      }
      lbl_803DD7B0 = bButtonIcon;
      drawTexture(((int *)(base + 0x1C0))[6], lbl_803E1FCC, lbl_803E200C, (int)lbl_803DD83C, 0x100);
      gameTextSetCharset(prevCharset, 3);
    }
    else {
      drawTexture(((int *)(base + 0x1C0))[4], lbl_803E1FCC, lbl_803E200C, (int)lbl_803DD83C, 0x100);
      lbl_803DD7B0 = 0;
    }
    if (hudYButtonItemIconTexture != 0) {
      if (lbl_803DD87C != 0) {
        scaleT = lbl_803E2010;
      }
      else {
        scaleT = lbl_803E1E68;
      }
      if (lbl_803DD7E8 > scaleT) {
        dv = lbl_803DD7E8 - lbl_803E1EA8;
        if (scaleT > dv) {
          dv = scaleT;
        }
        lbl_803DD7E8 = dv;
      }
      else {
        dv = lbl_803E1EA8 + lbl_803DD7E8;
        if (scaleT < dv) {
          dv = scaleT;
        }
        lbl_803DD7E8 = dv;
      }
      lbl_803DD878 = lbl_803DD878 -
                     (lbl_803DBA74 + (timeDelta * (lbl_803DD878 - lbl_803DBA74)) / lbl_803DBA84);
      if (lbl_803DD878 > lbl_803E1E3C) {
        lbl_803DD7E8 = lbl_803E1E68;
      }
      if (!(lbl_803DD878 > lbl_803E1E3C)) {
        lbl_803DD878 = lbl_803E1E3C;
      }
      drawTexture(hudYButtonItemIconTexture, lbl_803DBA78 * lbl_803DD878 + lbl_803E2014, lbl_803DBA7C * lbl_803DD878 + lbl_803E1F9C, (int)(lbl_803DD7E8 * lbl_803DD83C), (int)(lbl_803DBA80 * lbl_803DD878 + lbl_803E2018));
    }
    else {
      gameTextSetColor(0xFF, 0xFF, 0xFF, (int)lbl_803DD83C);
      prevCharset = gameTextFn_80019b14();
      gameTextSetCharset(3, 3);
      gameTextShowStr(&lbl_803DBB5C, 0x93, 0x216, 0x22);
      gameTextSetCharset(prevCharset, 3);
    }
  }
  fn_8005D118(0, 0xFF, 0xFF, 0xFF, 0xFF);
}

/*
 * --INFO--
 *
 * Function: cMenuUpdateAnims
 * EN v1.0 Address: 0x80124068
 * EN v1.0 Size: 0x164
 */
void cMenuUpdateAnims(void)
{
  sbyte s;
  byte b;

  s = (sbyte)lbl_803DBA65;
  if (s >= 0) {
    lbl_803DD796 = lbl_803DD796 - framesThisStep * s;
    if (lbl_803DD796 < 0) {
      lbl_803DD796 = 0;
      lbl_803DBA65 = 0;
      lbl_803DD78E = 0;
    }
  }
  else {
    lbl_803DD796 = lbl_803DD796 + framesThisStep * (-s);
    if (lbl_803DD796 > 0) {
      lbl_803DD796 = 0;
      lbl_803DBA65 = 0;
      lbl_803DD78E = 0;
    }
  }
  b = cMenuOpen;
  if ((sbyte)b != 0) {
    cMenuFadeCounter = cMenuFadeCounter + framesThisStep * 8;
    if (cMenuFadeCounter > 0xff) {
      cMenuFadeCounter = 0xff;
    }
  }
  else {
    if (lbl_803DD8D6 == 0) {
      cMenuFadeCounter = cMenuFadeCounter - framesThisStep * 8;
      if (cMenuFadeCounter < 0) {
        cMenuFadeCounter = 0;
      }
    }
  }
  if ((sbyte)b != 0 && cMenuFadeCounter > 0x40) {
    lbl_803DD8D6 = lbl_803DD8D6 + framesThisStep * 16;
    if (lbl_803DBA66 < lbl_803DD8D6) {
      lbl_803DD8D6 = lbl_803DBA66;
    }
  }
  else {
    lbl_803DD8D6 = lbl_803DD8D6 - framesThisStep * 16;
    if (lbl_803DD8D6 < 0) {
      lbl_803DD8D6 = 0;
    }
  }
}

/*
 * --INFO--
 *
 * Function: trickyBitFn_801241cc
 * EN v1.0 Address: 0x801241CC
 * EN v1.0 Size: 0x110
 */
#pragma peephole off
#pragma scheduling off
int trickyBitFn_801241cc(short* arr, sbyte flag)
{
  short* entry;
  int count;
  int mask;

  count = 0;
  if (flag == 0) {
    entry = arr;
    while (entry[0] > -1) {
      if (GameBit_Get((int)entry[0]) != 0) {
        if (arr == lbl_8031B4E0) {
          if (entry[2] < 0 || GameBit_Get((int)entry[2]) == 0) {
            count++;
          }
        }
        else {
          if (!(entry[1] >= 0 && GameBit_Get((int)entry[1]) != 0)) {
            if (entry[2] < 0 || GameBit_Get((int)entry[2]) == 0) {
              count++;
            }
          }
        }
      }
      entry += 8;
    }
  }
  else {
    mask = gTrickyHudItemMask;
    if (mask > 0) {
      entry = arr;
      while (entry[0] > -1) {
        if (mask != -1 && (mask & (int)entry[0]) != 0) {
          count++;
        }
        entry += 8;
      }
    }
  }
  return count;
}
#pragma scheduling reset
