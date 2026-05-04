#include "ghidra_import.h"
#include "main/dll/baddie/dll_DB.h"

extern undefined4 FUN_80006bb4();
extern uint FUN_80006c00();
extern int FUN_800174a0();
extern uint FUN_80017690();
extern int FUN_800176d0();
extern uint FUN_80017760();
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
 * Function: FUN_8012fcec
 * EN v1.0 Address: 0x8012FCEC
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8012FD0C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012fcec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,short param_10)
{
  int iVar1;
  short sVar2;
  uint uVar3;
  
  iVar1 = FUN_801244a4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  sVar2 = (&DAT_8031c22c)[param_9 * 8];
  uVar3 = 0;
  while( true ) {
    if (iVar1 <= (int)(uVar3 & 0xff)) {
      return;
    }
    if (((&DAT_803a98d8)[sVar2] != '\0') && ((int)param_10 == (&DAT_803a9c98)[sVar2])) break;
    sVar2 = sVar2 + 1;
    if (iVar1 <= sVar2) {
      sVar2 = 0;
    }
    uVar3 = uVar3 + 1;
  }
  (&DAT_8031c22c)[param_9 * 8] = sVar2;
  return;
}

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
    if (((uVar2 & 0x1100) != 0) && (uVar3 = FUN_80017690(0x44f), uVar3 == 0)) {
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
undefined2 FUN_8013041c(void)
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
        uVar2 = FUN_80017760(4,5);
        *(char *)(param_1 + iVar4 + 0x1f) = (char)uVar2;
      }
    }
    else {
      uVar2 = FUN_80017760(2,5);
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

extern u8  lbl_803DD789;
extern u8  lbl_803DD788;
extern s16 lbl_803DD798;
extern s8  lbl_803DD8F0;
extern s16 lbl_803DD8F2;
extern s8  lbl_803DD8F4;
extern u8  lbl_803DD8E8;
extern u8  lbl_803DD8F8;
extern u8  lbl_803DD8F9;
extern s16 lbl_803DD90C;
extern s16 lbl_803DD90E;
extern s8  lbl_803DD912;
extern u8  lbl_803A9458[0x960];

void fn_8012FDB8(u8 v) { lbl_803DD789 = v; }
void fn_8012FDC0(void) { lbl_803DD788 = 60; }
void fn_8012FDCC(s16 v) { lbl_803DD798 = v; }
s32  fn_8012FECC(void) { return lbl_803DD8F0; }
void fn_8012FED8(s8 v) { lbl_803DD8E8 = v; }
void fn_8012FEE4(void) {}
void fn_80130028(s8 v) { lbl_803DD8F4 = v; }
#pragma scheduling off
#pragma peephole off
void fn_801300E8(int v) { lbl_803DD8F2 = (s16)v; lbl_803DD8F0 = 0; lbl_803DD8F4 = -1; }
#pragma peephole reset
#pragma scheduling reset
void fn_80130104(void) {}
void fn_80130464(u8 v) { lbl_803DD8F8 = v; }
void fn_8013046C(void) { lbl_803DD8F9 = 0; }
void fn_80130478(void) { lbl_803DD8F9 = 1; }
u8   fn_801306D8(void) { return (u8)lbl_803DD90E; }
void fn_8013082C(int idx, s8 v) { *(s8*)(lbl_803A9458 + idx * 60 + 0x1e) = v; }
s32  fn_80130848(int idx) { return *(s8*)(lbl_803A9458 + idx * 60 + 0x1e); }
void fn_80130864(u8 v) { lbl_803DD90C = v; }
void fn_80130870(s8 v) { lbl_803DD912 = v; }
s32  fn_8013087C(void) { return lbl_803DD912; }
