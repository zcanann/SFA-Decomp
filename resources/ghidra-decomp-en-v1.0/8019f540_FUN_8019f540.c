// Function: FUN_8019f540
// Entry: 8019f540
// Size: 1000 bytes

/* WARNING: Removing unreachable block (ram,0x8019f88c) */
/* WARNING: Removing unreachable block (ram,0x8019f89c) */

void FUN_8019f540(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  bool bVar2;
  short sVar3;
  int iVar4;
  undefined4 uVar5;
  char cVar7;
  char cVar8;
  int iVar6;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined4 local_38;
  undefined auStack52 [4];
  undefined auStack48 [8];
  undefined4 local_28;
  uint uStack36;
  
  iVar4 = FUN_802860d0();
  iVar10 = *(int *)(iVar4 + 0xb8);
  local_38 = 0;
  iVar9 = *(int *)(iVar4 + 0x4c);
  bVar1 = *(byte *)(param_3 + 0x80);
  if (bVar1 == 5) {
    uStack36 = (uint)DAT_803db410;
    local_28 = 0x43300000;
    *(float *)(iVar10 + 0x30) =
         FLOAT_803e4264 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e4270) +
         *(float *)(iVar10 + 0x30);
  }
  else if (bVar1 < 5) {
    if (3 < bVar1) {
      *(undefined *)(iVar10 + 0x37) = 6;
      uVar5 = 0;
      goto LAB_8019f910;
    }
  }
  else if (bVar1 == 0x29) {
    *(float *)(iVar10 + 0x30) = FLOAT_803e4260;
  }
  if (*(short *)(iVar4 + 0xb4) < 0) {
    uVar5 = 0;
    goto LAB_8019f910;
  }
  FUN_80035f20(iVar4);
  cVar7 = FUN_8001ffb4(0x50);
  cVar8 = FUN_8001ffb4(0x48);
  if (((*(byte *)(iVar10 + 0x38) & 2) != 0) && (iVar6 = FUN_8001ffb4(0x4d), iVar6 != 0)) {
    *(byte *)(iVar10 + 0x38) = *(byte *)(iVar10 + 0x38) & 0xfd;
    uVar5 = 4;
    goto LAB_8019f910;
  }
  if (cVar7 != '\0') {
    uVar5 = 4;
    goto LAB_8019f910;
  }
  if ((cVar7 != '\0') || (*(char *)(iVar10 + 0x37) == '\x05')) {
    *(undefined *)(iVar10 + 0x37) = 5;
    uVar5 = 0;
    goto LAB_8019f910;
  }
  bVar2 = false;
  iVar6 = FUN_8002b9ec();
  switch(*(undefined *)(iVar10 + 0x37)) {
  case 0:
    FUN_8003b228(iVar4,iVar10);
    dVar11 = (double)FUN_80021704(iVar4 + 0x18,iVar6 + 0x18);
    if (cVar8 == '\0') {
      uStack36 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      if ((dVar11 < (double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e4278)) ||
         (iVar9 = FUN_800956f4((double)FLOAT_803e4268,iVar4 + 0xc), iVar9 != 0)) {
        iVar9 = FUN_80296ba0(iVar6);
        if (iVar9 == 0x40) {
          *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) | 8;
          *(undefined *)(iVar10 + 0x37) = 5;
          *(undefined2 *)(iVar10 + 0x34) = 0x14;
          (**(code **)(*DAT_803dca54 + 0x48))(2,iVar4,0xffffffff);
          uVar5 = 4;
          goto LAB_8019f910;
        }
        bVar2 = true;
        *(undefined *)(iVar10 + 0x37) = 4;
      }
    }
    break;
  case 1:
    dVar11 = (double)FUN_80021704(iVar4 + 0x18,iVar6 + 0x18);
    if (cVar8 == '\0') {
      uStack36 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      if (dVar11 < (double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e4278)) {
        iVar9 = FUN_80296ba0(iVar6);
        if (iVar9 == 0x40) {
          *(undefined *)(iVar10 + 0x37) = 2;
        }
        else {
          bVar2 = true;
          *(undefined *)(iVar10 + 0x37) = 4;
        }
      }
    }
    break;
  case 2:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803db410;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 1;
    }
    FUN_8003b228(iVar4,iVar10);
    break;
  case 3:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803db410;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 0;
    }
    break;
  case 5:
    uVar5 = 0;
    goto LAB_8019f910;
  case 6:
    uVar5 = 0;
    goto LAB_8019f910;
  case 7:
    bVar2 = true;
    *(undefined *)(iVar10 + 0x37) = 4;
  }
  if ((*(short *)(iVar4 + 0xa0) == 0x103) || (*(short *)(iVar4 + 0xa0) == 0x2e)) {
    FUN_8000bb18(iVar4,0xe3);
  }
  else {
    FUN_8000b7bc(iVar4,0x10);
  }
  if (bVar2) {
    uVar5 = 4;
  }
  else {
    *(undefined *)(iVar10 + 0x36) = 0;
    *(undefined *)(param_3 + 0x56) = 0;
    do {
      iVar9 = FUN_800374ec(iVar4,auStack52,auStack48,&local_38);
    } while (iVar9 != 0);
    if (*(char *)(param_3 + 0x80) == '\x01') {
      FUN_800066e0(iVar4,iVar4,0x18,0,0,0);
      *(undefined *)(param_3 + 0x80) = 0;
    }
    uVar5 = 0;
  }
LAB_8019f910:
  FUN_8028611c(uVar5);
  return;
}

