// Function: FUN_8005e8ac
// Entry: 8005e8ac
// Size: 588 bytes

void FUN_8005e8ac(undefined4 param_1,undefined4 param_2,float *param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  undefined8 uVar5;
  byte local_68;
  byte local_67;
  byte local_66;
  undefined uStack_65;
  int local_64;
  float fStack_60;
  undefined4 uStack_5c;
  undefined4 auStack_58 [2];
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar5 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar1 = (int)uVar5;
  uStack_4c = (int)*(short *)(iVar2 + 6) >> 3 ^ 0x80000000;
  local_50 = 0x43300000;
  uStack_44 = (int)*(short *)(iVar2 + 8) >> 3 ^ 0x80000000;
  local_48 = 0x43300000;
  uStack_3c = (int)*(short *)(iVar2 + 10) >> 3 ^ 0x80000000;
  local_40 = 0x43300000;
  uStack_34 = (int)*(short *)(iVar2 + 0xc) >> 3 ^ 0x80000000;
  local_38 = 0x43300000;
  uStack_2c = (int)*(short *)(iVar2 + 0xe) >> 3 ^ 0x80000000;
  local_30 = 0x43300000;
  uStack_24 = (int)*(short *)(iVar2 + 0x10) >> 3 ^ 0x80000000;
  local_28 = 0x43300000;
  FUN_8001e9ec((double)((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x18) + FLOAT_803dda58),
               (double)((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df840) +
                       *(float *)(iVar1 + 0x28)),
               (double)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x38) + FLOAT_803dda5c),
               (double)((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x18) + FLOAT_803dda58),
               (double)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df840) +
                       *(float *)(iVar1 + 0x28)),
               (double)((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df840) +
                        *(float *)(iVar1 + 0x38) + FLOAT_803dda5c),&DAT_803ddaa0,2,&local_64);
  FUN_80052a6c();
  FUN_8004cf88(param_3);
  piVar3 = (int *)&DAT_803ddaa0;
  for (iVar2 = 0; iVar2 < local_64; iVar2 = iVar2 + 1) {
    FUN_8001db90(*piVar3,&local_68,&local_67,&local_66,&uStack_65);
    local_68 = (char)((int)(uint)local_68 >> 1) + (char)((int)(uint)local_68 >> 2);
    local_67 = (char)((int)(uint)local_67 >> 1) + (char)((int)(uint)local_67 >> 2);
    local_66 = (char)((int)(uint)local_66 >> 1) + (char)((int)(uint)local_66 >> 2);
    FUN_8001de14(*piVar3,&fStack_60,&uStack_5c,auStack_58);
    dVar4 = FUN_8001de0c(*piVar3);
    FUN_8004fbac(dVar4,(undefined4 *)&local_68,&fStack_60);
    piVar3 = piVar3 + 1;
  }
  FUN_80052a38();
  FUN_8025a5bc(1);
  FUN_80259288(2);
  FUN_8007048c(1,3,0);
  FUN_80070434(1);
  FUN_8025cce8(1,4,5,5);
  FUN_8025c754(7,0,0,7,0);
  FUN_80286884();
  return;
}

