// Function: FUN_802c1de4
// Entry: 802c1de4
// Size: 396 bytes

void FUN_802c1de4(undefined2 *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined2 local_38 [6];
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_802c136c;
  FUN_800372f8((int)param_1,10);
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar3 + 0xbb4) = *(undefined *)(param_2 + 0x19);
  *(undefined2 *)(iVar3 + 0xbae) = 5;
  *(undefined2 *)(iVar3 + 0xbb0) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined *)(iVar3 + 0xbc4) = 0xff;
  uStack_1c = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(iVar3 + 0xb50) =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e9098) / FLOAT_803e90ac;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xa10;
  }
  uVar2 = FUN_80020078(0x7a9);
  if (uVar2 != 0) {
    FUN_80114420(uVar2 + 0x13,local_38);
    *(undefined4 *)(param_1 + 6) = local_2c;
    *(undefined4 *)(param_1 + 8) = local_28;
    *(undefined4 *)(param_1 + 10) = local_24;
    *param_1 = local_38[0];
  }
  (**(code **)(*DAT_803dd70c + 4))(param_1,iVar3,8,1);
  *(float *)(iVar3 + 0x2a4) = FLOAT_803e90bc;
  FUN_802bf838(param_1,iVar3,*(byte *)(iVar3 + 0xbc0) >> 5 & 1);
  FUN_80115200((int)param_1,(undefined4 *)(iVar3 + 0x4c4),0xee39,0x1555,1);
  FUN_80115318(iVar3 + 0x4c4,300,0x78);
  FUN_800372f8((int)param_1,0x26);
  *(byte *)(iVar3 + 0xbc0) = *(byte *)(iVar3 + 0xbc0) & 0xfe;
  return;
}

