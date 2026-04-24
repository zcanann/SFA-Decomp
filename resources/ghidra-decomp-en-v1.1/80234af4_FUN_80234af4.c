// Function: FUN_80234af4
// Entry: 80234af4
// Size: 396 bytes

void FUN_80234af4(short *param_1)

{
  int iVar1;
  double dVar2;
  uint uVar3;
  int iVar4;
  char *pcVar5;
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
  
  dVar2 = DOUBLE_803e7ef0;
  pcVar5 = *(char **)(param_1 + 0x5c);
  iVar4 = *(int *)(param_1 + 0x26);
  if (*(int *)(pcVar5 + 8) != 0) {
    uStack_3c = (int)*(short *)(iVar4 + 0x32) ^ 0x80000000;
    local_40 = 0x43300000;
    uStack_34 = (int)*param_1 ^ 0x80000000;
    local_38 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ef0) * FLOAT_803dc074
                 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e7ef0));
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
    if (pcVar5[0xe] == '\0') {
      uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x1e));
      if (uVar3 != 0) {
        pcVar5[0xe] = '\x01';
        FUN_8001dc30((double)FLOAT_803e7eec,*(int *)(pcVar5 + 8),'\x01');
      }
    }
    else {
      uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x1e));
      if (uVar3 == 0) {
        pcVar5[0xe] = '\0';
        FUN_8001dc30((double)FLOAT_803e7eec,*(int *)(pcVar5 + 8),'\0');
      }
      if ((*(byte *)(iVar4 + 0x2a) & 1) != 0) {
        FUN_80089b54(0,local_46,&local_47,&local_48);
        FUN_8001dbb4(*(int *)(pcVar5 + 8),local_46[0],local_47,local_48,0xff);
      }
    }
    FUN_80234710(param_1,pcVar5);
  }
  return;
}

