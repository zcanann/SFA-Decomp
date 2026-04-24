#include "ghidra_import.h"
#include "main/dll/FRONT/dll_44.h"

extern undefined4 FUN_801175f8();
extern undefined4 FUN_80119764();
extern undefined4 FUN_80119a10();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802446f8();
extern undefined4 FUN_802493c8();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();

extern undefined4 DAT_803a694c;
extern undefined DAT_803a69c0;
extern undefined4 DAT_803a6a04;
extern undefined4 DAT_803a6a08;
extern undefined4 DAT_803a6a18;
extern undefined4 DAT_803a6a40;
extern undefined4 DAT_803a6a44;
extern undefined4 DAT_803a6a54;
extern undefined4 DAT_803a6a58;
extern undefined4 DAT_803a6a5c;
extern undefined4 DAT_803a6a5f;
extern undefined4 DAT_803a6a68;
extern undefined4 DAT_803a6a6c;
extern undefined4 DAT_803a6ab4;
extern undefined4 DAT_803a6abc;
extern undefined4 DAT_803a6ac4;
extern undefined4 DAT_803a6acc;
extern undefined4 DAT_803a6ad4;
extern undefined4 DAT_803a6adc;
extern undefined4 DAT_803a6ae4;
extern undefined4 DAT_803a6aec;
extern undefined4 DAT_803a6af4;
extern undefined4 DAT_803a6afc;
extern undefined4 DAT_803a6b34;
extern undefined4 DAT_803a6b38;
extern undefined4 DAT_803a6b3c;
extern undefined4 DAT_803a6b44;
extern undefined4 DAT_803a6b48;
extern undefined4 DAT_803a6b4c;
extern undefined4 DAT_803a6b54;
extern undefined4 DAT_803a6b58;
extern undefined4 DAT_803a6b5c;
extern undefined4 DAT_803de2fc;

/*
 * --INFO--
 *
 * Function: FUN_80118e60
 * EN v1.0 Address: 0x80118C88
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80118E60
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80118e60(void)
{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  
  puVar3 = &DAT_803a69c0;
  if (DAT_803a6a68 == 0) {
    iVar1 = 0;
    do {
      FUN_80119764(puVar3 + 0xf4);
      puVar3 = puVar3 + 8;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 10);
  }
  iVar1 = 0;
  puVar2 = &DAT_803a69c0;
  puVar3 = puVar2;
  do {
    FUN_80119a10(puVar3 + 0x144);
    puVar3 = puVar3 + 0x10;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 3);
  if (DAT_803a6a5f != '\0') {
    iVar1 = 0;
    do {
      FUN_801175f8(puVar2 + 0x174);
      puVar2 = puVar2 + 0x10;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 3);
  }
  FUN_802446f8((undefined4 *)&DAT_803a694c,&DAT_803de2fc,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80118f30
 * EN v1.0 Address: 0x80118D44
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x80118F30
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80118f30(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,undefined4 param_6)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined *puVar5;
  uint uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_8028682c();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  if ((DAT_803a6a58 != 0) && (DAT_803a6a5c == '\0')) {
    if (DAT_803a6a68 == 0) {
      DAT_803a6abc = iVar2 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ac4 = DAT_803a6abc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6acc = DAT_803a6ac4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ad4 = DAT_803a6acc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6adc = DAT_803a6ad4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ae4 = DAT_803a6adc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6aec = DAT_803a6ae4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6af4 = DAT_803a6aec + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6afc = DAT_803a6af4 + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      uVar6 = DAT_803a6afc + (DAT_803a6a04 + 0x1fU & 0xffffffe0);
      DAT_803a6ab4 = iVar2;
    }
    else {
      uVar6 = iVar2 + DAT_803a6a18;
      DAT_803a6a6c = iVar2;
    }
    puVar5 = &DAT_803a69c0;
    uVar3 = DAT_803a6a40 * DAT_803a6a44;
    uVar1 = (uVar3 >> 2) + 0x1f & 0xffffffe0;
    uVar4 = 0;
    do {
      *(int *)(puVar5 + 0x144) = (int)uVar7;
      FUN_802420b0(uVar6,uVar3 + 0x1f & 0xffffffe0);
      *(undefined4 *)(puVar5 + 0x148) = param_3;
      FUN_802420b0(uVar6,uVar1);
      *(undefined4 *)(puVar5 + 0x14c) = param_4;
      FUN_802420b0(uVar6,uVar1);
      uVar6 = uVar6 + uVar1;
      puVar5 = puVar5 + 0x10;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 3);
    DAT_803a6a54 = param_6;
    if (DAT_803a6a5f != '\0') {
      DAT_803a6b3c = 0;
      uVar6 = DAT_803a6a08 * 4 + 0x1fU & 0xffffffe0;
      DAT_803a6b44 = param_5 + uVar6;
      DAT_803a6b4c = 0;
      DAT_803a6b54 = DAT_803a6b44 + uVar6;
      DAT_803a6b5c = 0;
      DAT_803a6b34 = param_5;
      DAT_803a6b38 = param_5;
      DAT_803a6b48 = DAT_803a6b44;
      DAT_803a6b58 = DAT_803a6b54;
    }
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119154
 * EN v1.0 Address: 0x80118ED8
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80119154
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119154(uint *param_1,int *param_2,int *param_3,int *param_4,int *param_5,
                 undefined4 *param_6)
{
  uint uVar1;
  int iVar2;
  
  if (DAT_803a6a58 != 0) {
    if (DAT_803a6a68 == 0) {
      uVar1 = (DAT_803a6a04 + 0x1fU & 0xffffffe0) * 10;
    }
    else {
      uVar1 = DAT_803a6a18 + 0x1fU & 0xffffffe0;
    }
    *param_1 = uVar1;
    *param_2 = (DAT_803a6a40 * DAT_803a6a44 + 0x1fU & 0xffffffe0) * 3;
    *param_3 = (((uint)(DAT_803a6a40 * DAT_803a6a44) >> 2) + 0x1f & 0xffffffe0) * 3;
    *param_4 = (((uint)(DAT_803a6a40 * DAT_803a6a44) >> 2) + 0x1f & 0xffffffe0) * 3;
    if (DAT_803a6a5f == '\0') {
      iVar2 = 0;
    }
    else {
      iVar2 = (DAT_803a6a08 * 4 + 0x1fU & 0xffffffe0) * 3;
    }
    *param_5 = iVar2;
    *param_6 = 0x1000;
    return;
  }
  *param_1 = 0;
  *param_2 = 0;
  *param_3 = 0;
  *param_4 = 0;
  *param_5 = 0;
  *param_6 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119254
 * EN v1.0 Address: 0x80118FC8
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80119254
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80119254(void)
{
  undefined4 uVar1;
  
  if ((DAT_803a6a58 == 0) || (DAT_803a6a5c != '\0')) {
    uVar1 = 0;
  }
  else {
    DAT_803a6a58 = 0;
    FUN_802493c8((int *)&DAT_803a69c0);
    uVar1 = 1;
  }
  return uVar1;
}
