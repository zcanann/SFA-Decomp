// Function: FUN_801631c8
// Entry: 801631c8
// Size: 756 bytes

void FUN_801631c8(void)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char cVar7;
  undefined4 uVar6;
  int iVar8;
  int iVar9;
  int unaff_r29;
  int iVar10;
  int iVar11;
  undefined auStack40 [4];
  int local_24;
  int local_20 [8];
  
  iVar4 = FUN_802860dc();
  iVar11 = *(int *)(iVar4 + 0xb8);
  iVar10 = *(int *)(iVar4 + 0x4c);
  sVar1 = *(short *)(iVar4 + 0x46);
  if (sVar1 == 0x4b9) {
    unaff_r29 = 0x4ba;
  }
  else if (sVar1 < 0x4b9) {
    if (sVar1 == 0x3fd) {
      unaff_r29 = 0x3fb;
    }
    else if ((sVar1 < 0x3fd) && (sVar1 == 0x28d)) {
      iVar5 = (**(code **)(*DAT_803dca58 + 0x24))(auStack40);
      if (iVar5 == 0) {
        iVar4 = -1;
        goto LAB_801634a4;
      }
      unaff_r29 = 0x39d;
    }
  }
  else if (sVar1 == 0x4be) {
    unaff_r29 = 0x4c1;
  }
  local_20[0] = 0;
  iVar9 = -1;
  iVar5 = iVar11;
  while ((local_20[0] < (int)(uint)*(byte *)(iVar11 + 0x50) && (iVar9 == -1))) {
    if (*(int *)(iVar5 + 0xc) == 0) {
      iVar9 = local_20[0];
    }
    iVar5 = iVar5 + 4;
    local_20[0] = local_20[0] + 1;
  }
  if (iVar9 == -1) {
    iVar4 = -1;
  }
  else {
    iVar5 = FUN_8002e0fc(local_20,&local_24);
    iVar8 = 0;
    while (local_20[0] < local_24) {
      iVar3 = local_20[0] + 1;
      iVar2 = local_20[0] * 4;
      local_20[0] = iVar3;
      if (unaff_r29 == *(short *)(*(int *)(iVar5 + iVar2) + 0x46)) {
        iVar8 = iVar8 + 1;
      }
    }
    if (iVar8 < 7) {
      cVar7 = FUN_8002e04c();
      if (cVar7 == '\0') {
        iVar4 = -1;
      }
      else {
        iVar5 = FUN_8002bdf4(0x20,unaff_r29);
        iVar8 = iVar11 + iVar9 * 0xc;
        *(float *)(iVar5 + 8) = *(float *)(iVar4 + 0xc) + *(float *)(iVar8 + 0x1c);
        *(float *)(iVar5 + 0xc) = *(float *)(iVar4 + 0x10) + *(float *)(iVar8 + 0x20);
        *(float *)(iVar5 + 0x10) = *(float *)(iVar4 + 0x14) + *(float *)(iVar8 + 0x24);
        *(undefined *)(iVar5 + 4) = *(undefined *)(iVar10 + 4);
        *(undefined *)(iVar5 + 5) = *(undefined *)(iVar10 + 5);
        *(undefined *)(iVar5 + 6) = *(undefined *)(iVar10 + 6);
        *(undefined *)(iVar5 + 7) = *(undefined *)(iVar10 + 7);
        *(float *)(iVar5 + 0x1c) = FLOAT_803e2f40;
        if ((((*(byte *)(iVar11 + 0x4c) & 1) != 0) &&
            (*(int *)(*(int *)(iVar4 + 0x4c) + 0x14) == 0x292c)) && (*(short *)(iVar11 + 0x4e) == 6)
           ) {
          *(undefined *)(iVar5 + 0x1b) = 1;
          iVar10 = FUN_8002e0fc(local_20,&local_24);
          for (; local_20[0] < local_24; local_20[0] = local_20[0] + 1) {
            iVar8 = *(int *)(iVar10 + local_20[0] * 4);
            if (*(short *)(iVar8 + 0x46) == 0x27f) {
              *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(iVar8 + 0xc);
              *(undefined4 *)(iVar5 + 0xc) =
                   *(undefined4 *)(*(int *)(iVar10 + local_20[0] * 4) + 0x10);
              *(undefined4 *)(iVar5 + 0x10) =
                   *(undefined4 *)(*(int *)(iVar10 + local_20[0] * 4) + 0x14);
              local_20[0] = local_24;
            }
          }
        }
        uVar6 = FUN_8002df90(iVar5,5,(int)*(char *)(iVar4 + 0xac),0xffffffff,
                             *(undefined4 *)(iVar4 + 0x30));
        iVar10 = iVar11 + iVar9 * 4;
        *(undefined4 *)(iVar10 + 0xc) = uVar6;
        (**(code **)(**(int **)(*(int *)(iVar10 + 0xc) + 0x68) + 0x24))
                  ((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x14));
        *(short *)(iVar11 + 0x4e) = *(short *)(iVar11 + 0x4e) + 1;
        iVar4 = (int)(char)iVar9;
      }
    }
    else {
      iVar4 = -1;
    }
  }
LAB_801634a4:
  FUN_80286128(iVar4);
  return;
}

