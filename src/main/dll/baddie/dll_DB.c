#include "ghidra_import.h"
#include "main/dll/baddie/dll_DB.h"

extern undefined4 FUN_80006bb4();
extern uint FUN_80006c00();
extern int FUN_800174a0();
extern uint GameBit_Get(int eventId);
extern int FUN_800176d0();
extern u32 randomGetRange(int min, int max);
extern undefined8 FUN_80053754();
extern undefined4 FUN_8005398c();
extern uint FUN_8006f764();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_8011e7ac();
extern int FUN_801244a4();
extern undefined4 FUN_8012dca8();
extern undefined8 FUN_8012e050();
extern undefined8 FUN_8012e2a4();
extern undefined4 FUN_8012ed00();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();

extern undefined4 DAT_802c7b54;
extern undefined4 DAT_802c8e0a;
extern undefined4 DAT_8031c22c;
extern short DAT_8031c274;
extern undefined4 DAT_8031ce04;
extern undefined4 DAT_8031ce0a;
extern undefined4 DAT_8031ce12;
extern int DAT_803a9610;
extern undefined4 DAT_803a9898;
extern undefined4 DAT_803a98d8;
extern undefined4 DAT_803a9c98;
extern undefined4 DAT_803a9d98;
extern undefined4 DAT_803a9e18;
extern undefined4 DAT_803a9ff8;
extern undefined4 DAT_803a9ffc;
extern undefined4 DAT_803aa000;
extern undefined4 DAT_803aa004;
extern undefined2 DAT_803aa0b8;
extern undefined4 DAT_803aa0ba;
extern undefined4 DAT_803aa0be;
extern undefined4 DAT_803aa0c4;
extern undefined4 DAT_803aa0c8;
extern undefined4 DAT_803aa0ce;
extern undefined4 DAT_803aa0d7;
extern undefined4 DAT_803aa0f0;
extern undefined4 DAT_803de3c0;
extern undefined4 DAT_803de3c4;
extern undefined4 DAT_803de3fe;
extern undefined4 DAT_803de408;
extern undefined4 DAT_803de409;
extern undefined4 DAT_803de413;
extern undefined4 DAT_803de418;
extern undefined4 DAT_803de445;
extern undefined4 DAT_803de448;
extern undefined4 DAT_803de450;
extern undefined4 DAT_803de4a8;
extern undefined4 DAT_803de4ac;
extern undefined4 DAT_803de4b0;
extern undefined4 DAT_803de4b4;
extern undefined4 DAT_803de504;
extern undefined4 DAT_803de514;
extern undefined4 DAT_803de516;
extern undefined4 DAT_803de538;
extern undefined4 DAT_803de542;
extern undefined4 DAT_803de544;
extern undefined4 DAT_803de568;
extern undefined4 DAT_803de570;
extern undefined4 DAT_803de572;
extern undefined4 DAT_803de574;
extern undefined4 DAT_803de575;
extern undefined4 DAT_803de578;
extern undefined4 DAT_803de579;
extern undefined4 DAT_803de591;
extern undefined4 DAT_803de592;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de56c;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2e68;

/*
 * --INFO--
 *
 * Function: textureFreeFn_8012fcec
 * EN v1.0 Address: 0x8012FCEC
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8012FD0C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803A87F0[];
extern void gameUiResetMenuState(void);
extern void *lbl_803DD7C8;
extern s16 lbl_803DD830;
extern void *lbl_803DD834;
extern void textureFree(void *p);

#pragma scheduling off
#pragma peephole off
void textureFreeFn_8012fcec(void)
{
    u8 i;

    gameUiResetMenuState();
    for (i = 0; i < 64; i++) {
        if (*(void **)(lbl_803A87F0 + 2504 + i * 4) != NULL) {
            textureFree(*(void **)(lbl_803A87F0 + 2504 + i * 4));
            *(void **)(lbl_803A87F0 + 2504 + i * 4) = NULL;
        }
        *(s16 *)(lbl_803A87F0 + 2376 + i * 2) = -1;
        lbl_803A87F0[1096 + i] = 1;
    }
    if (lbl_803DD7C8 != NULL) {
        textureFree(lbl_803DD7C8);
        lbl_803DD7C8 = NULL;
    }
    if (lbl_803DD834 != NULL) {
        textureFree(lbl_803DD834);
    }
    lbl_803DD830 = -1;
    lbl_803DD834 = NULL;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8012fdac
 * EN v1.0 Address: 0x8012FDAC
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x8012FDC8
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012fdac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  short sVar3;
  uint uVar4;
  char cVar5;
  
  iVar2 = FUN_801244a4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  sVar3 = (&DAT_8031c22c)[param_9 * 8];
  uVar4 = 0;
  cVar5 = '\x01';
  while( true ) {
    if (iVar2 << 1 <= (int)(uVar4 & 0xff)) {
      return;
    }
    iVar1 = (int)sVar3;
    if (((&DAT_803a98d8)[iVar1] != '\0') && ((cVar5 != '\0' || (iVar2 <= (int)(uVar4 & 0xff)))))
    break;
    sVar3 = sVar3 + 1;
    if (iVar2 <= sVar3) {
      sVar3 = 0;
    }
    uVar4 = uVar4 + 1;
    cVar5 = (&DAT_803a98d8)[iVar1];
  }
  (&DAT_8031c22c)[param_9 * 8] = sVar3;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8012fe70
 * EN v1.0 Address: 0x8012FE70
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x8012FE84
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8012fe70(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined8 uVar1;
  
  if (DAT_803de445 != '\0') {
    if (DAT_803de3fe != '\0') {
      FUN_8012dca8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    uVar1 = FUN_8012e050();
    if (DAT_803de413 != '\0') {
      uVar1 = FUN_8012e2a4(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    FUN_8012ed00(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8012ff9c
 * EN v1.0 Address: 0x8012FF9C
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x8012FEF4
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012ff9c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int *piVar2;
  byte bVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286838();
  iVar1 = 0;
  piVar2 = &DAT_803a9610;
  do {
    if (*piVar2 != 0) {
      uVar4 = FUN_80053754();
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x66);
  FUN_8011e7ac(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  for (bVar3 = 0; bVar3 < 0x40; bVar3 = bVar3 + 1) {
    if ((&DAT_803a9e18)[bVar3] != 0) {
      FUN_80053754();
      (&DAT_803a9e18)[bVar3] = 0;
    }
    (&DAT_803a9d98)[bVar3] = 0xffff;
    (&DAT_803a9898)[bVar3] = 1;
  }
  if (DAT_803de448 != 0) {
    FUN_80053754();
    DAT_803de448 = 0;
  }
  if (DAT_803de4b4 != 0) {
    FUN_80053754();
  }
  DAT_803de4b0 = 0xffff;
  DAT_803de4b4 = 0;
  for (bVar3 = 0; bVar3 < 0x40; bVar3 = bVar3 + 1) {
    if ((&DAT_803a9e18)[bVar3] != 0) {
      FUN_80053754();
      (&DAT_803a9e18)[bVar3] = 0;
    }
    (&DAT_803a9d98)[bVar3] = 0xffff;
    (&DAT_803a9898)[bVar3] = 1;
  }
  FUN_80053754();
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80130150
 * EN v1.0 Address: 0x80130150
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80130044
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130150(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_80286838();
  FUN_8011e7ac(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  for (bVar1 = 0; bVar1 < 0x40; bVar1 = bVar1 + 1) {
    if ((&DAT_803a9e18)[bVar1] != 0) {
      FUN_80053754();
      (&DAT_803a9e18)[bVar1] = 0;
    }
    (&DAT_803a9d98)[bVar1] = 0xffff;
    (&DAT_803a9898)[bVar1] = 1;
  }
  if (DAT_803de448 != 0) {
    FUN_80053754();
    DAT_803de448 = 0;
  }
  if (DAT_803de4b4 != 0) {
    FUN_80053754();
  }
  DAT_803de4b0 = 0xffff;
  DAT_803de4b4 = 0;
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013028c
 * EN v1.0 Address: 0x8013028C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80130110
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013028c(undefined param_1)
{
  DAT_803de409 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80130298
 * EN v1.0 Address: 0x80130298
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80130118
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130298(void)
{
  DAT_803de408 = 0x3c;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801302a4
 * EN v1.0 Address: 0x801302A4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80130124
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801302a4(undefined2 param_1)
{
  DAT_803de418 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801302b0
 * EN v1.0 Address: 0x801302B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8013012C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801302b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801302b4
 * EN v1.0 Address: 0x801302B4
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80130240
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801302b4(int *param_1)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  char local_18;
  undefined auStack_17 [19];
  
  iVar1 = FUN_800176d0();
  if (iVar1 != 0) {
    return -1;
  }
  FLOAT_803de56c = FLOAT_803de56c + FLOAT_803dc074;
  if (FLOAT_803e2e68 < FLOAT_803de56c) {
    FLOAT_803de56c = FLOAT_803de56c - FLOAT_803e2e68;
  }
  FUN_80006bb4(0,auStack_17,&local_18);
  if (local_18 < '\0') {
    *param_1 = *param_1 + 1;
  }
  else if ('\0' < local_18) {
    *param_1 = *param_1 + -1;
  }
  if (*param_1 < 0) {
    *param_1 = DAT_803de570 + -1;
  }
  if ((int)DAT_803de570 <= *param_1) {
    *param_1 = 0;
  }
  if (DAT_803de568 != '\0') {
    uVar2 = FUN_80006c00(0);
    if (((uVar2 & 0x1100) != 0) && (uVar3 = GameBit_Get(0x44f), uVar3 == 0)) {
      return (int)DAT_803de575;
    }
    if ((uVar2 & 0x200) != 0) {
      return (int)DAT_803de574;
    }
  }
  DAT_803de568 = 1;
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_801303d8
 * EN v1.0 Address: 0x801303D8
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801303FC
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801303d8(undefined4 param_1,undefined2 param_2)
{
  FUN_8006f764();
  DAT_803de572 = param_2;
  DAT_803de570 = 0;
  DAT_803de574 = 0xff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013041c
 * EN v1.0 Address: 0x8013041C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x8013047C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort FUN_8013041c(void)
{
  return (&DAT_803aa0ba)[DAT_803de592 * 0x1e];
}

/*
 * --INFO--
 *
 * Function: FUN_80130434
 * EN v1.0 Address: 0x80130434
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x8013049C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130434(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  *(undefined *)(param_1 + 0x1f) = 0xff;
  *(undefined *)(param_1 + 0x20) = 0xff;
  *(undefined *)(param_1 + 0x21) = 0xff;
  *(undefined *)(param_1 + 0x22) = 0xff;
  *(undefined *)(param_1 + 0x23) = 0xff;
  *(undefined *)(param_1 + 0x24) = 0xff;
  *(undefined *)(param_1 + 0x25) = 0xff;
  *(undefined *)(param_1 + 0x26) = 0xff;
  *(undefined *)(param_1 + 0x27) = 0xff;
  *(undefined *)(param_1 + 0x28) = 0xff;
  *(undefined *)(param_1 + 0x29) = 0xff;
  *(undefined *)(param_1 + 0x2a) = 0xff;
  *(undefined *)(param_1 + 0x2b) = 0xff;
  *(undefined *)(param_1 + 0x2c) = 0xff;
  *(undefined *)(param_1 + 0x2d) = 0xff;
  *(undefined *)(param_1 + 0x2e) = 0xff;
  *(undefined *)(param_1 + 0x2f) = 0xff;
  *(undefined *)(param_1 + 0x30) = 0xff;
  *(undefined *)(param_1 + 0x31) = 0xff;
  *(undefined *)(param_1 + 0x32) = 0xff;
  *(undefined *)(param_1 + 0x33) = 0xff;
  *(undefined *)(param_1 + 0x34) = 0xff;
  *(undefined *)(param_1 + 0x35) = 0xff;
  *(undefined *)(param_1 + 0x36) = 0xff;
  *(undefined *)(param_1 + 0x37) = 0xff;
  iVar4 = 1;
  *(undefined *)(param_1 + 0x1f) = 0;
  for (iVar3 = (uint)*(ushort *)(param_1 + 0x14) - ((uint)DAT_8031ce0a + (uint)DAT_8031ce12);
      iVar3 != 0; iVar3 = iVar3 - (uint)(&DAT_8031ce0a)[*(char *)(param_1 + iVar1) * 8]) {
    if (iVar3 < 0x50) {
      if (iVar3 < 0x28) {
        *(undefined *)(param_1 + iVar4 + 0x1f) = 5;
      }
      else {
        uVar2 = randomGetRange(4,5);
        *(char *)(param_1 + iVar4 + 0x1f) = (char)uVar2;
      }
    }
    else {
      uVar2 = randomGetRange(2,5);
      *(char *)(param_1 + iVar4 + 0x1f) = (char)uVar2;
    }
    iVar1 = iVar4 + 0x1f;
    iVar4 = iVar4 + 1;
  }
  *(undefined *)(param_1 + iVar4 + 0x1f) = 1;
  if (0x18 < iVar4 + 1) {
    FUN_800723a0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80130588
 * EN v1.0 Address: 0x80130588
 * EN v1.0 Size: 416b
 * EN v1.1 Address: 0x80130618
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130588(void)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  
  iVar1 = (int)DAT_803de592;
  (&DAT_803aa0f0)[iVar1 * 0x3c] = 4;
  if ((((&DAT_803aa0ce)[iVar1 * 0x1e] & 4) == 0) || ((char)(&DAT_803aa0d7)[iVar1 * 0x3c] == -1)) {
    iVar4 = (&DAT_803aa0c8)[iVar1 * 0xf];
  }
  else {
    iVar4 = (&DAT_8031ce04)[(char)(&DAT_803aa0d7)[iVar1 * 0x3c] * 2];
  }
  if (iVar4 == 0) {
    iVar4 = FUN_800174a0();
    uVar2 = *(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar4 * 8] * 0x10) + 2;
    iVar1 = (short)(&DAT_803aa0be)[iVar1 * 0x1e] + -2;
  }
  else {
    uVar2 = (uint)*(ushort *)(iVar4 + 0xc);
    iVar1 = (int)(short)(&DAT_803aa0c4)[iVar1 * 0x1e];
  }
  puVar6 = &DAT_803aa0b8;
  for (iVar4 = 0; iVar4 < DAT_803de591; iVar4 = iVar4 + 1) {
    if (iVar4 != DAT_803de592) {
      if (((puVar6[0xb] & 4) == 0) || (*(char *)((int)puVar6 + 0x1f) == -1)) {
        iVar5 = *(int *)(puVar6 + 8);
      }
      else {
        iVar5 = (&DAT_8031ce04)[*(char *)((int)puVar6 + 0x1f) * 2];
      }
      if (iVar5 == 0) {
        iVar5 = FUN_800174a0();
        uVar3 = *(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar5 * 8] * 0x10) + 2;
        iVar5 = (short)puVar6[3] + -2;
      }
      else {
        uVar3 = (uint)*(ushort *)(iVar5 + 0xc);
        iVar5 = (int)(short)puVar6[6];
      }
      if ((iVar5 < (int)(iVar1 + uVar2)) && (iVar1 < (int)(iVar5 + uVar3))) {
        *(undefined *)(puVar6 + 0x1c) = 4;
      }
    }
    puVar6 = puVar6 + 0x1e;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80130728
 * EN v1.0 Address: 0x80130728
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x801307D4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130728(undefined param_1)
{
  DAT_803de578 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80130734
 * EN v1.0 Address: 0x80130734
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x801307DC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130734(void)
{
  DAT_803de579 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80130740
 * EN v1.0 Address: 0x80130740
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x801307E8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130740(void)
{
  DAT_803de579 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013074c
 * EN v1.0 Address: 0x8013074C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801307F4
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013074c(void)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  
  iVar4 = 0x1e0;
  iVar3 = 0;
  puVar6 = &DAT_803aa0b8;
  for (iVar5 = 0; iVar5 < DAT_803de591; iVar5 = iVar5 + 1) {
    if (((puVar6[0xb] & 4) == 0) || (*(char *)((int)puVar6 + 0x1f) == -1)) {
      iVar2 = *(int *)(puVar6 + 8);
    }
    else {
      iVar2 = (&DAT_8031ce04)[*(char *)((int)puVar6 + 0x1f) * 2];
    }
    if (iVar2 == 0) {
      iVar2 = FUN_800174a0();
      uVar1 = *(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar2 * 8] * 0x10) + 2;
      iVar2 = (short)puVar6[3] + -2;
    }
    else {
      uVar1 = (uint)*(ushort *)(iVar2 + 0xc);
      iVar2 = (int)(short)puVar6[6];
    }
    if (iVar2 < iVar4) {
      iVar4 = iVar2;
    }
    if (iVar3 < (int)(iVar2 + uVar1)) {
      iVar3 = iVar2 + uVar1;
    }
    puVar6 = puVar6 + 0x1e;
  }
  return;
}

/* ===== EN v1.0 retargeted leaves ========================================= */

extern u8  pauseDisabled;
extern u8  pauseMenuFrameCounter;
extern s16 cMenuFadeCounter;
extern s8  lbl_803DD8F0;
extern s16 lbl_803DD8F2;
extern s8  lbl_803DD8F4;
extern s8  lbl_803DD8F5;
extern s8  lbl_803DD8E8;
extern u8  linkFlag_803dd8f8;
extern u8  linkIsRotated;
extern s16 linkItemOpacity;
extern s16 linkCount_803dd90e;
extern s8  linkSelected;
extern u8  linkTextures[0x30];
extern int getScreenResolution(void);
extern void *textureLoadAsset(int id);
extern void *hudTextures[];
extern s16 lbl_8031B624[];
extern u8 lbl_803A9398[];
extern s8 lbl_803DD896;
extern s16 lbl_803DD894;
extern s16 lbl_803DD8C2;
extern u8 lbl_803DD8B8;
extern int lbl_803DD744;
extern int lbl_803DD740;
extern void *lbl_803DD8C4;
extern int lbl_803DD82C;
extern int lbl_803DD828;
extern f32 lbl_803E1E3C;
extern s16 yButtonState;
extern int airMeter;

typedef struct LinkMenuItem {
    u16 field00;
    u16 itemId;
    s16 field04;
    s16 field06;
    u8 pad8[4];
    s16 field0C;
    u8 padE[2];
    union {
        int textureAssetId;
        void *texture;
    };
    u16 field14;
    u16 field16;
    u8 pad18[2];
    u8 field1A;
    u8 pad1B[3];
    s8 state;
    s8 slots[25];
    s8 field38;
    u8 pad39[3];
} LinkMenuItem;

extern LinkMenuItem lbl_803A9458[40];

void Pause_SetDisabled(u8 v) { pauseDisabled = v; }
void Pause_ResetMenuFrameCounter(void) { pauseMenuFrameCounter = 60; }
void CMenu_SetFadeCounter(s16 v) { cMenuFadeCounter = v; }
s32  Menu_func0B(void) { return lbl_803DD8F0; }
#pragma peephole off
void Menu_func0A(int v) { lbl_803DD8E8 = (s8)v; }
#pragma peephole reset
void Menu_func09_nop(void) {}
#pragma peephole off
void Menu_func07(int v) { lbl_803DD8F4 = (s8)v; }
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
void Menu_func03(int v) { lbl_803DD8F2 = (s16)v; lbl_803DD8F0 = 0; lbl_803DD8F4 = -1; }
#pragma peephole reset
#pragma scheduling reset
void Menu_release(void) {}
void titleScreenFn_80130464(u8 v) { linkFlag_803dd8f8 = v; }
void setLinkNotRotated(void) { linkIsRotated = 0; }
void setLinkIsRotated(void) { linkIsRotated = 1; }
u8   Link_func0C(void) { return (u8)linkCount_803dd90e; }
void Link_func0A(int idx, int v) { lbl_803A9458[idx].state = (s8)v; }
s32  Link_func09(int idx) { return lbl_803A9458[idx].state; }
void Link_setOpacity(u8 v) { linkItemOpacity = v; }
#pragma peephole off
void Link_setSelected(int v) { linkSelected = (s8)v; }
#pragma peephole reset
s32  Link_getSelected(void) { return linkSelected; }

/* Stubs added to align function set with v1.0 asm. Source had many Ghidra
 * FUN_xxx splits at wrong addresses; these stubs (no body yet) ensure the
 * asm symbol set is fully present so future hunters can fill bodies. */
#pragma scheduling off
#pragma peephole off
void GameUI_initialise(void)
{
    int res;
    int height;
    int width;
    int i;
    void *p;

    lbl_803DD896 = -1;
    lbl_803DD894 = -1;
    lbl_803DD8C2 = -1;
    lbl_803DD8B8 = 0;
    lbl_803DD830 = -1;
    res = getScreenResolution();
    lbl_803DD744 = res;
    height = res >> 16;
    lbl_803DD740 = height;
    width = res & 0xffff;
    lbl_803DD744 = width;
    lbl_803DD744 = width - 320;
    lbl_803DD740 = height - 240;
    for (i = 0; i < 102; i++) {
        hudTextures[i] = textureLoadAsset(lbl_8031B624[i]);
    }
    p = textureLoadAsset(1280);
    lbl_803DD8C4 = p;
    *(short *)((char *)p + 20) = 40;
    lbl_803DD82C = 0x80000;
    lbl_803DD828 = 0;
    *(int *)(lbl_803A9398 + 4) = -1;
    *(short *)(lbl_803A9398 + 12) = 0;
    *(int *)(lbl_803A9398 + 0) = 0;
    *(float *)(lbl_803A9398 + 8) = lbl_803E1E3C;
    yButtonState = 0;
    airMeter = 0;
}
#pragma peephole reset
#pragma scheduling reset
extern int getHudHiddenFrameCount(void);
extern void padGetAnalogInput(int pad, s8 *y, s8 *x);
extern int getButtonsJustPressed(int pad);
extern f32 lbl_803DD8EC;
extern f32 lbl_803E21D8;
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
int Menu_func08(int *sel)
{
    s8 xInput;
    s8 yInput;
    int input;

    if (getHudHiddenFrameCount() != 0) {
        return -1;
    }
    lbl_803DD8EC += timeDelta;
    if (lbl_803DD8EC > lbl_803E21D8) {
        lbl_803DD8EC -= lbl_803E21D8;
    }
    padGetAnalogInput(0, &yInput, &xInput);
    if (xInput < 0) {
        *sel = *sel + 1;
    } else if (xInput > 0) {
        *sel = *sel - 1;
    }
    if (*sel < 0) {
        *sel = (s8)lbl_803DD8F0 - 1;
    }
    if (*sel >= (s8)lbl_803DD8F0) {
        *sel = 0;
    }
    if (lbl_803DD8E8 != 0) {
        input = getButtonsJustPressed(0);
        if (((input & 0x1100) != 0) && (GameBit_Get(1103) == 0)) {
            return lbl_803DD8F5;
        }
        if ((input & 0x200) != 0) {
            return lbl_803DD8F4;
        }
    }
    lbl_803DD8E8 = 1;
    return -1;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Menu_func05(int arg1, int unused2, int arg3, int arg4) {
    if (arg4 == (s32)lbl_803DD8F0) {
        lbl_803DD8F5 = (s8)arg1;
    }
    lbl_803DD8F2 = (s16)((s32)lbl_803DD8F2 + arg3);
    lbl_803DD8F0++;
}
void Menu_func06(int arg1, int unused2, int unused3, int arg4, int arg5) {
    if (arg5 == (s32)lbl_803DD8F0) {
        lbl_803DD8F5 = (s8)arg1;
    }
    lbl_803DD8F2 = (s16)((s32)lbl_803DD8F2 + arg4);
    lbl_803DD8F0++;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Menu_func04(int unused, int v) {
    getScreenResolution();
    lbl_803DD8F2 = (s16)v;
    lbl_803DD8F0 = 0;
    lbl_803DD8F4 = -1;
}
#pragma peephole reset
#pragma scheduling reset
void Menu_initialise(void) {
    lbl_803DD8F0 = 0;
    lbl_803DD8F2 = 0;
    lbl_803DD8F4 = 0;
    lbl_803DD8F5 = 0;
    lbl_803DD8E8 = 0;
}
#pragma scheduling off
u16 fn_80130124(void) {
    return lbl_803A9458[linkSelected].itemId;
}
#pragma scheduling reset
extern void OSReport(const char *fmt, ...);
extern char lbl_8031C234[];
#pragma scheduling off
#pragma peephole off
void linkInitTextures(LinkMenuItem *item)
{
    int budget;
    int i;

    budget = item->field14;
    for (i = 0; i < 25; i++) {
        item->slots[i] = -1;
    }
    item->slots[0] = 0;
    i = 1;
    budget -= linkTextures[6] + linkTextures[14];
    while (budget != 0) {
        if (budget >= 80) {
            item->slots[i] = (s8)randomGetRange(2, 5);
        } else if (budget >= 40) {
            item->slots[i] = (s8)randomGetRange(4, 5);
        } else {
            item->slots[i] = 5;
        }
        budget -= linkTextures[item->slots[i] * 8 + 6];
        i++;
    }
    item->slots[i] = 1;
    i++;
    if (i >= 25) {
        OSReport(lbl_8031C234);
    }
}
#pragma peephole reset
#pragma scheduling reset
extern int getCurLanguage(void);
extern u8 lbl_802C8680[];
extern u8 lbl_803DD911;
#pragma scheduling off
#pragma peephole off
void linkDrawFn_801302c0(void)
{
    LinkMenuItem *sel;
    LinkMenuItem *p;
    void *tex;
    int selLeft;
    int selRight;
    int itemLeft;
    int itemRight;
    int w;
    int i;

    sel = &lbl_803A9458[(s8)linkSelected];
    sel->field38 = 4;
    if (((sel->field16 & 4) != 0) && ((s8)sel->slots[0] != -1)) {
        tex = *(void **)(linkTextures + (s8)sel->slots[0] * 8);
    } else {
        tex = sel->texture;
    }
    if (tex != NULL) {
        w = *(u16 *)((char *)tex + 12);
        selLeft = sel->field0C;
    } else {
        if (getCurLanguage() == 4) {
            w = *(u16 *)(lbl_802C8680 + 0xa) + 2;
        } else {
            w = *(u16 *)(lbl_802C8680 + 0x4a) + 2;
        }
        selLeft = sel->field06 - 2;
    }
    selRight = selLeft + w;
    p = lbl_803A9458;
    for (i = 0; i < (s8)lbl_803DD911; i++) {
        if (i != (s8)linkSelected) {
            if (((p->field16 & 4) != 0) && ((s8)p->slots[0] != -1)) {
                tex = *(void **)(linkTextures + (s8)p->slots[0] * 8);
            } else {
                tex = p->texture;
            }
            if (tex != NULL) {
                w = *(u16 *)((char *)tex + 12);
                itemLeft = p->field0C;
            } else {
                if (getCurLanguage() == 4) {
                    w = *(u16 *)(lbl_802C8680 + 0xa) + 2;
                } else {
                    w = *(u16 *)(lbl_802C8680 + 0x4a) + 2;
                }
                itemLeft = p->field06 - 2;
            }
            itemRight = itemLeft + w;
            if (itemLeft < selRight && itemRight > selLeft) {
                p->field38 = 4;
            }
        }
        p++;
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void linkDrawFn_80130484(void)
{
    LinkMenuItem *p;
    void *tex;
    int minX;
    int maxX;
    int w;
    int x;
    int right;
    int i;

    minX = 480;
    maxX = 0;
    p = lbl_803A9458;
    for (i = 0; i < (s8)lbl_803DD911; i++) {
        if (((p->field16 & 4) != 0) && ((s8)p->slots[0] != -1)) {
            tex = *(void **)(linkTextures + (s8)p->slots[0] * 8);
        } else {
            tex = p->texture;
        }
        if (tex != NULL) {
            w = *(u16 *)((char *)tex + 12);
            x = p->field0C;
        } else {
            if (getCurLanguage() == 4) {
                w = *(u16 *)(lbl_802C8680 + 0xa) + 2;
            } else {
                w = *(u16 *)(lbl_802C8680 + 0x4a) + 2;
            }
            x = p->field06 - 2;
        }
        right = x + w;
        if (x < minX) {
            minX = x;
        }
        if (right > maxX) {
            maxX = right;
        }
        p++;
    }
}
#pragma peephole reset
#pragma scheduling reset
extern u8 lbl_803DD911;
#pragma scheduling off
#pragma peephole off
void Link_func0F(void)
{
    int i;

    for (i = 0; i < (s8)lbl_803DD911; i++) {
        lbl_803A9458[i].field38 = 4;
    }
}
#pragma peephole reset
#pragma scheduling reset
extern void *textureLoadAsset(int id);
extern void textureFree(void *p);

#pragma scheduling off
#pragma peephole off
void Link_copy(u8 *srcArg) {
    LinkMenuItem *dst;
    LinkMenuItem *src;
    int i;

    i = 0;
    dst = lbl_803A9458;
    src = (LinkMenuItem *)srcArg;
    for (; i < (s8)lbl_803DD911; i++) {
        dst->field16 = src->field16;
        dst->field1A = src->field1A;
        dst->field04 = src->field04;
        if (src->textureAssetId != -1) {
            if (dst->texture == NULL) {
                dst->texture = textureLoadAsset(src->textureAssetId);
            }
        } else {
            if (dst->texture != NULL) {
                textureFree(dst->texture);
            }
            dst->texture = NULL;
        }
        dst++;
        src++;
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0B(u8 *srcArg)
{
    LinkMenuItem *src;
    int i;

    src = (LinkMenuItem *)srcArg;
    for (i = 0; i < (s8)lbl_803DD911; i++) {
        lbl_803A9458[i].field00 = src[i].field00;
        lbl_803A9458[i].itemId = src[i].itemId;
        lbl_803A9458[i].field38 = 2;
    }
}
#pragma peephole reset
#pragma scheduling reset
