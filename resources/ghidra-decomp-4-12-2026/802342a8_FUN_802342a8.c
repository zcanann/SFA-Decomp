// Function: FUN_802342a8
// Entry: 802342a8
// Size: 428 bytes

void FUN_802342a8(short *param_1)

{
  int iVar1;
  double dVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  undefined local_48;
  undefined local_47;
  undefined local_46 [6];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  dVar2 = DOUBLE_803e7ed0;
  iVar4 = *(int *)(param_1 + 0x26);
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 != 0) {
    uStack_3c = (int)*(short *)(iVar4 + 0x32) ^ 0x80000000;
    local_40 = 0x43300000;
    uStack_34 = (int)*param_1 ^ 0x80000000;
    local_38 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ed0) * FLOAT_803dc074
                 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e7ed0));
    local_30 = (longlong)iVar1;
    *param_1 = (short)iVar1;
    uStack_24 = (int)*(short *)(iVar4 + 0x34) ^ 0x80000000;
    local_28 = 0x43300000;
    uStack_1c = (int)param_1[1] ^ 0x80000000;
    local_20 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_24) - dVar2) * FLOAT_803dc074 +
                 (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2));
    local_18 = (longlong)iVar1;
    param_1[1] = (short)iVar1;
    if (*(char *)(piVar5 + 1) == '\0') {
      if ((0 < *(short *)(iVar4 + 0x1e)) &&
         (uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x1e)), uVar3 != 0)) {
        *(undefined *)(piVar5 + 1) = 1;
        FUN_8001dc30((double)FLOAT_803e7ecc,*piVar5,'\x01');
      }
    }
    else {
      if ((0 < *(short *)(iVar4 + 0x1e)) &&
         (uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x1e)), uVar3 == 0)) {
        *(undefined *)(piVar5 + 1) = 0;
        FUN_8001dc30((double)FLOAT_803e7ecc,*piVar5,'\0');
      }
      if ((*(byte *)(iVar4 + 0x2a) & 1) != 0) {
        FUN_80089b54(0,local_46,&local_47,&local_48);
        FUN_8001dbb4(*piVar5,local_46[0],local_47,local_48,0xff);
        FUN_8001db7c(*piVar5,local_46[0],local_47,local_48,0xff);
      }
    }
    if (*piVar5 != 0) {
      FUN_8001d774(*piVar5);
    }
  }
  return;
}

