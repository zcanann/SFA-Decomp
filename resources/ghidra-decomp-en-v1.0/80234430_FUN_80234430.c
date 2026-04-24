// Function: FUN_80234430
// Entry: 80234430
// Size: 396 bytes

void FUN_80234430(short *param_1)

{
  double dVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined local_48;
  undefined local_47;
  undefined local_46 [6];
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  dVar1 = DOUBLE_803e7258;
  iVar4 = *(int *)(param_1 + 0x5c);
  iVar3 = *(int *)(param_1 + 0x26);
  if (*(int *)(iVar4 + 8) != 0) {
    uStack60 = (int)*(short *)(iVar3 + 0x32) ^ 0x80000000;
    local_40 = 0x43300000;
    uStack52 = (int)*param_1 ^ 0x80000000;
    local_38 = 0x43300000;
    iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7258) * FLOAT_803db414
                 + (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7258));
    local_30 = (longlong)iVar2;
    *param_1 = (short)iVar2;
    uStack36 = (int)*(short *)(iVar3 + 0x34) ^ 0x80000000;
    local_28 = 0x43300000;
    uStack28 = (int)param_1[1] ^ 0x80000000;
    local_20 = 0x43300000;
    iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack36) - dVar1) * FLOAT_803db414 +
                 (float)((double)CONCAT44(0x43300000,uStack28) - dVar1));
    local_18 = (longlong)iVar2;
    param_1[1] = (short)iVar2;
    if (*(char *)(iVar4 + 0xe) == '\0') {
      iVar3 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1e));
      if (iVar3 != 0) {
        *(undefined *)(iVar4 + 0xe) = 1;
        FUN_8001db6c((double)FLOAT_803e7254,*(undefined4 *)(iVar4 + 8),1);
      }
    }
    else {
      iVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1e));
      if (iVar2 == 0) {
        *(undefined *)(iVar4 + 0xe) = 0;
        FUN_8001db6c((double)FLOAT_803e7254,*(undefined4 *)(iVar4 + 8),0);
      }
      if ((*(byte *)(iVar3 + 0x2a) & 1) != 0) {
        FUN_800898c8(0,local_46,&local_47,&local_48);
        FUN_8001daf0(*(undefined4 *)(iVar4 + 8),local_46[0],local_47,local_48,0xff);
      }
    }
    FUN_8023404c(param_1,iVar4);
  }
  return;
}

