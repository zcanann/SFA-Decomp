// Function: FUN_8019fabc
// Entry: 8019fabc
// Size: 1000 bytes

/* WARNING: Removing unreachable block (ram,0x8019fe08) */
/* WARNING: Removing unreachable block (ram,0x8019fe18) */

void FUN_8019fabc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  bool bVar1;
  byte bVar2;
  short sVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  uint local_38;
  uint uStack_34;
  uint auStack_30 [2];
  undefined4 local_28;
  uint uStack_24;
  
  uVar4 = FUN_80286834();
  iVar10 = *(int *)(uVar4 + 0xb8);
  local_38 = 0;
  iVar9 = *(int *)(uVar4 + 0x4c);
  bVar2 = *(byte *)(param_11 + 0x80);
  if (bVar2 == 5) {
    param_2 = (double)FLOAT_803e4efc;
    uStack_24 = (uint)DAT_803dc070;
    local_28 = 0x43300000;
    *(float *)(iVar10 + 0x30) =
         (float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f08)
                + (double)*(float *)(iVar10 + 0x30));
  }
  else if (bVar2 < 5) {
    if (3 < bVar2) {
      *(undefined *)(iVar10 + 0x37) = 6;
      goto LAB_8019fe8c;
    }
  }
  else if (bVar2 == 0x29) {
    *(float *)(iVar10 + 0x30) = FLOAT_803e4ef8;
  }
  if (*(short *)(uVar4 + 0xb4) < 0) goto LAB_8019fe8c;
  FUN_80036018(uVar4);
  uVar5 = FUN_80020078(0x50);
  uVar6 = FUN_80020078(0x48);
  if (((*(byte *)(iVar10 + 0x38) & 2) != 0) && (uVar7 = FUN_80020078(0x4d), uVar7 != 0)) {
    *(byte *)(iVar10 + 0x38) = *(byte *)(iVar10 + 0x38) & 0xfd;
    goto LAB_8019fe8c;
  }
  bVar1 = (char)uVar5 != '\0';
  if (bVar1) goto LAB_8019fe8c;
  if ((bVar1) || (*(char *)(iVar10 + 0x37) == '\x05')) {
    *(undefined *)(iVar10 + 0x37) = 5;
    goto LAB_8019fe8c;
  }
  bVar1 = false;
  iVar8 = FUN_8002bac4();
  switch(*(undefined *)(iVar10 + 0x37)) {
  case 0:
    FUN_8003b320(uVar4,iVar10);
    dVar11 = (double)FUN_800217c8((float *)(uVar4 + 0x18),(float *)(iVar8 + 0x18));
    if ((char)uVar6 == '\0') {
      uStack_24 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      param_2 = DOUBLE_803e4f10;
      if ((dVar11 < (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f10)) ||
         (iVar9 = FUN_80095980((double)FLOAT_803e4f00,(float *)(uVar4 + 0xc)), iVar9 != 0)) {
        iVar9 = FUN_80297300(iVar8);
        if (iVar9 == 0x40) {
          *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
          *(undefined *)(iVar10 + 0x37) = 5;
          *(undefined2 *)(iVar10 + 0x34) = 0x14;
          (**(code **)(*DAT_803dd6d4 + 0x48))(2,uVar4,0xffffffff);
          goto LAB_8019fe8c;
        }
        bVar1 = true;
        *(undefined *)(iVar10 + 0x37) = 4;
      }
    }
    break;
  case 1:
    dVar11 = (double)FUN_800217c8((float *)(uVar4 + 0x18),(float *)(iVar8 + 0x18));
    if ((char)uVar6 == '\0') {
      uStack_24 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      param_2 = DOUBLE_803e4f10;
      if (dVar11 < (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f10)) {
        iVar9 = FUN_80297300(iVar8);
        if (iVar9 == 0x40) {
          *(undefined *)(iVar10 + 0x37) = 2;
        }
        else {
          bVar1 = true;
          *(undefined *)(iVar10 + 0x37) = 4;
        }
      }
    }
    break;
  case 2:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803dc070;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 1;
    }
    FUN_8003b320(uVar4,iVar10);
    break;
  case 3:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803dc070;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 0;
    }
    break;
  case 5:
    goto LAB_8019fe8c;
  case 6:
    goto LAB_8019fe8c;
  case 7:
    bVar1 = true;
    *(undefined *)(iVar10 + 0x37) = 4;
  }
  if ((*(short *)(uVar4 + 0xa0) == 0x103) || (*(short *)(uVar4 + 0xa0) == 0x2e)) {
    uVar12 = FUN_8000bb38(uVar4,0xe3);
  }
  else {
    uVar12 = FUN_8000b7dc(uVar4,0x10);
  }
  if (!bVar1) {
    *(undefined *)(iVar10 + 0x36) = 0;
    *(undefined *)(param_11 + 0x56) = 0;
    do {
      iVar9 = FUN_800375e4(uVar4,&uStack_34,auStack_30,&local_38);
    } while (iVar9 != 0);
    if (*(char *)(param_11 + 0x80) == '\x01') {
      FUN_800066e0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar4,uVar4,0x18,0
                   ,0,0,in_r9,in_r10);
      *(undefined *)(param_11 + 0x80) = 0;
    }
  }
LAB_8019fe8c:
  FUN_80286880();
  return;
}

