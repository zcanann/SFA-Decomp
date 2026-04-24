// Function: FUN_801e7794
// Entry: 801e7794
// Size: 1096 bytes

uint FUN_801e7794(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  char local_18;
  undefined auStack_17 [7];
  
  iVar7 = *(int *)(param_1 + 0xb8);
  if (param_3 == 0x14) {
    FUN_80014ba4(0,auStack_17,&local_18);
    if (local_18 < '\0') {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9d0) + -1;
      FUN_8000bb38(0,0xf3);
    }
    else if ('\0' < local_18) {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9d0) + 1;
      FUN_8000bb38(0,0xf3);
    }
    if (*(short *)(iVar7 + 0x9c8) < *(short *)(iVar7 + 0x9d0)) {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9c8);
    }
    iVar3 = (int)*(short *)(iVar7 + 0x9cc) << 1;
    if (iVar3 < *(short *)(iVar7 + 0x9d0)) {
      *(short *)(iVar7 + 0x9d0) = (short)iVar3;
    }
    else {
      iVar3 = (int)*(short *)(iVar7 + 0x9cc) >> 1;
      if (*(short *)(iVar7 + 0x9d0) < iVar3) {
        *(short *)(iVar7 + 0x9d0) = (short)iVar3;
      }
    }
    iVar8 = (int)*(short *)(iVar7 + 0x9d0);
    piVar4 = (int *)FUN_800395a4(param_1,8);
    iVar3 = iVar8 >> 0x1f;
    iVar1 = iVar8 / 10 + iVar3;
    *piVar4 = (iVar8 + (iVar1 - (iVar1 >> 0x1f)) * -10) * 0x100;
    piVar4 = (int *)FUN_800395a4(param_1,7);
    iVar1 = iVar8 / 10 + iVar3;
    iVar1 = iVar1 - (iVar1 >> 0x1f);
    iVar2 = iVar1 / 10 + (iVar1 >> 0x1f);
    *piVar4 = (iVar1 + (iVar2 - (iVar2 >> 0x1f)) * -10) * 0x100;
    iVar3 = iVar8 / 100 + iVar3;
    iVar3 = iVar3 - (iVar3 >> 0x1f);
    if (9 < iVar3) {
      iVar3 = 9;
    }
    piVar4 = (int *)FUN_800395a4(param_1,6);
    *piVar4 = iVar3 << 8;
  }
  else if (param_3 == 0x17) {
    FUN_80014ba4(0,auStack_17,&local_18);
    if (local_18 < '\0') {
      *(char *)(iVar7 + 0x9d5) = *(char *)(iVar7 + 0x9d5) + -1;
      FUN_8000bb38(0,0xf3);
    }
    else if ('\0' < local_18) {
      *(char *)(iVar7 + 0x9d5) = *(char *)(iVar7 + 0x9d5) + '\x01';
      FUN_8000bb38(0,0xf3);
    }
    if (*(short *)(iVar7 + 0x9c8) < (short)(ushort)*(byte *)(iVar7 + 0x9d5)) {
      *(char *)(iVar7 + 0x9d5) = (char)*(short *)(iVar7 + 0x9c8);
    }
    if (*(byte *)(iVar7 + 0x9d5) < 0xb) {
      if (*(byte *)(iVar7 + 0x9d5) == 0) {
        *(undefined *)(iVar7 + 0x9d5) = 1;
      }
    }
    else {
      *(undefined *)(iVar7 + 0x9d5) = 10;
    }
    uVar5 = (uint)*(byte *)(iVar7 + 0x9d5);
    piVar4 = (int *)FUN_800395a4(param_1,8);
    *piVar4 = (uVar5 % 10) * 0x100;
    piVar4 = (int *)FUN_800395a4(param_1,7);
    *piVar4 = ((uVar5 / 10) % 10) * 0x100;
    uVar5 = uVar5 / 100;
    if (9 < uVar5) {
      uVar5 = 9;
    }
    piVar4 = (int *)FUN_800395a4(param_1,6);
    *piVar4 = uVar5 << 8;
    uVar5 = FUN_80014e9c(0);
    if ((uVar5 & 0x200) != 0) {
      *(byte *)(iVar7 + 0x9d4) = *(byte *)(iVar7 + 0x9d4) | 0x10;
      (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
      return 1;
    }
  }
  uVar5 = FUN_80014e9c(0);
  if ((uVar5 & 0x100) == 0) {
    uVar5 = 0;
  }
  else {
    if (*(short *)(iVar7 + 0x9d0) < *(short *)(iVar7 + 0x9ce)) {
      if (*(byte *)(iVar7 + 0x9d2) < 2) {
        cVar6 = '\0';
      }
      else {
        cVar6 = '\x02';
      }
    }
    else {
      cVar6 = '\x01';
    }
    if (param_3 == 0x15) {
      if (cVar6 == '\x01') {
        (**(code **)(**(int **)(*(int *)(iVar7 + 0x9b4) + 0x68) + 0x48))();
      }
      uVar5 = countLeadingZeros(1 - cVar6);
      uVar5 = uVar5 >> 5;
    }
    else {
      if (param_3 < 0x15) {
        if (0x13 < param_3) {
          if (cVar6 == '\0') {
            *(char *)(iVar7 + 0x9d2) = *(char *)(iVar7 + 0x9d2) + '\x01';
          }
          uVar5 = countLeadingZeros((int)cVar6);
          return uVar5 >> 5;
        }
      }
      else if (param_3 < 0x17) {
        uVar5 = countLeadingZeros(2 - cVar6);
        return uVar5 >> 5;
      }
      uVar5 = 0;
    }
  }
  return uVar5;
}

