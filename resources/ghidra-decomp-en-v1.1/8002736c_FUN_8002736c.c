// Function: FUN_8002736c
// Entry: 8002736c
// Size: 348 bytes

void FUN_8002736c(undefined4 param_1,undefined4 param_2,float *param_3)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  float *pfVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  float afStack_58 [22];
  
  uVar8 = FUN_80286838();
  piVar2 = (int *)((ulonglong)uVar8 >> 0x20);
  iVar6 = *piVar2;
  if (*(char *)(iVar6 + 0xf3) == '\0') {
    FUN_80247618((float *)uVar8,(float *)piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3],
                 (float *)piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3]);
  }
  else {
    iVar7 = 0;
    for (uVar5 = 0; uVar5 < *(byte *)(iVar6 + 0xf3); uVar5 = uVar5 + 1) {
      uVar3 = (uint)*(byte *)(*piVar2 + 0xf3);
      if (uVar3 == 0) {
        iVar1 = 1;
      }
      else {
        iVar1 = uVar3 + *(byte *)(*piVar2 + 0xf4);
      }
      uVar3 = uVar5;
      if (iVar1 <= (int)uVar5) {
        uVar3 = 0;
      }
      pfVar4 = (float *)(piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + uVar3 * 0x40);
      iVar1 = *(int *)(iVar6 + 0x3c) + iVar7;
      FUN_80247a48(-(double)*(float *)(iVar1 + 0x10),-(double)*(float *)(iVar1 + 0x14),
                   -(double)*(float *)(iVar1 + 0x18),afStack_58);
      FUN_80247618(pfVar4,afStack_58,afStack_58);
      FUN_80248134(afStack_58,param_3);
      FUN_80247618((float *)uVar8,pfVar4,pfVar4);
      iVar7 = iVar7 + 0x1c;
      param_3 = param_3 + 0xc;
    }
  }
  FUN_80286884();
  return;
}

