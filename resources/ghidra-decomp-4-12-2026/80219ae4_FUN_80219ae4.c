// Function: FUN_80219ae4
// Entry: 80219ae4
// Size: 212 bytes

void FUN_80219ae4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  undefined8 uVar8;
  
  iVar3 = FUN_80286840();
  pfVar7 = *(float **)(iVar3 + 0xb8);
  FUN_8002bac4();
  iVar6 = *(int *)(iVar3 + 0x4c);
  FUN_80036018(iVar3);
  uVar8 = FUN_80033a34(iVar3);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    if ((*(char *)(param_11 + iVar5 + 0x81) == '\x01') && (*(char *)(iVar6 + 0x19) != '\0')) {
      FUN_8002cf80(iVar3);
      uVar8 = FUN_80035ff8(iVar3);
      *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
    }
  }
  sVar1 = *(short *)((int)pfVar7[0x1b7] + 4);
  uVar4 = FUN_80114e4c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,param_11,
                       pfVar7,sVar1,sVar1,param_14,param_15,param_16);
  uVar2 = countLeadingZeros(uVar4);
  countLeadingZeros(uVar2 >> 5);
  FUN_8028688c();
  return;
}

