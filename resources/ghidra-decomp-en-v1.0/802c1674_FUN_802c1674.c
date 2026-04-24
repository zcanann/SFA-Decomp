// Function: FUN_802c1674
// Entry: 802c1674
// Size: 396 bytes

void FUN_802c1674(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined2 local_38 [6];
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack28;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_802c0bfc;
  FUN_80037200(param_1,10);
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 0xbb4) = *(undefined *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0xbae) = 5;
  *(undefined2 *)(iVar2 + 0xbb0) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined *)(iVar2 + 0xbc4) = 0xff;
  uStack28 = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(iVar2 + 0xb50) =
       (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e8400) / FLOAT_803e8414;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xa10;
  }
  iVar1 = FUN_8001ffb4(0x7a9);
  if (iVar1 != 0) {
    FUN_80114184(iVar1 + 0x13,local_38);
    *(undefined4 *)(param_1 + 6) = local_2c;
    *(undefined4 *)(param_1 + 8) = local_28;
    *(undefined4 *)(param_1 + 10) = local_24;
    *param_1 = local_38[0];
  }
  (**(code **)(*DAT_803dca8c + 4))(param_1,iVar2,8,1);
  *(float *)(iVar2 + 0x2a4) = FLOAT_803e8424;
  FUN_802bf0c8(param_1,iVar2,*(byte *)(iVar2 + 0xbc0) >> 5 & 1);
  FUN_80114f64(param_1,iVar2 + 0x4c4,0xffffee39,0x1555,1);
  FUN_8011507c(iVar2 + 0x4c4,300,0x78);
  FUN_80037200(param_1,0x26);
  *(byte *)(iVar2 + 0xbc0) = *(byte *)(iVar2 + 0xbc0) & 0xfe;
  return;
}

