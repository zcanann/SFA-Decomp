// Function: FUN_8021efd4
// Entry: 8021efd4
// Size: 728 bytes

void FUN_8021efd4(void)

{
  undefined2 *puVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined2 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined2 local_30;
  undefined4 local_28;
  uint uStack36;
  
  uVar5 = FUN_802860dc();
  puVar1 = (undefined2 *)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  iVar4 = *(int *)(puVar1 + 0x5c);
  local_58 = DAT_803e6aa0;
  local_40 = DAT_802c2590;
  local_3c = DAT_802c2594;
  local_38 = DAT_802c2598;
  local_34 = DAT_802c259c;
  local_30 = DAT_802c25a0;
  local_54 = DAT_802c25a4;
  local_50 = DAT_802c25a8;
  local_4c = DAT_802c25ac;
  local_48 = DAT_802c25b0;
  local_44 = DAT_802c25b4;
  *puVar1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  *(code **)(puVar1 + 0x5e) = FUN_8021e544;
  *(undefined *)(iVar4 + 0xc45) = *(undefined *)(iVar3 + 0x19);
  *(undefined2 *)(iVar4 + 0xc16) = 5;
  *(undefined *)(iVar4 + 0xc4b) = 0xff;
  iVar2 = *(int *)(puVar1 + 0x32);
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0xa10;
  }
  FUN_80037200(puVar1,0x26);
  FUN_80037200(puVar1,10);
  (**(code **)(*DAT_803dca8c + 4))(puVar1,iVar4,0xb,1);
  *(float *)(iVar4 + 0x2a4) = FLOAT_803e6b4c;
  iVar2 = iVar4 + 4;
  *(undefined *)(iVar4 + 0x25f) = 1;
  (**(code **)(*DAT_803dcaa8 + 4))(iVar2,3,0x400,0);
  (**(code **)(*DAT_803dcaa8 + 8))(iVar2,2,&DAT_8032ab98,&DAT_803dc318,8);
  (**(code **)(*DAT_803dcaa8 + 0xc))(iVar2,4,&DAT_8032ab58,&DAT_8032ab88,&local_58);
  (**(code **)(*DAT_803dcaa8 + 0x20))(puVar1,iVar2);
  FUN_80114f64(puVar1,iVar4 + 0x3ec,0xffffee39,0x5c71,6);
  FUN_8011507c(iVar4 + 0x3ec,300,0x78);
  FUN_80113f9c(iVar4 + 0x3ec,&local_54,&local_40,6);
  *(byte *)(iVar4 + 0x9fd) = *(byte *)(iVar4 + 0x9fd) | 2;
  *(byte *)(iVar4 + 0x9fd) = *(byte *)(iVar4 + 0x9fd) | 8;
  *(undefined2 *)(iVar4 + 0xc18) = *(undefined2 *)(iVar3 + 0x1a);
  *(byte *)(iVar4 + 0x9fd) = *(byte *)(iVar4 + 0x9fd) | 1;
  *(undefined *)(*(int *)(puVar1 + 0x28) + 0x71) = 0x7f;
  *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xf7;
  *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xfe;
  DAT_803dc320 = (int)*(short *)(iVar3 + 0x1a);
  if ((int)*(short *)(iVar3 + 0x1c) == 0) {
    *(float *)(iVar4 + 0xc28) = FLOAT_803e6b50;
  }
  else {
    uStack36 = (int)*(short *)(iVar3 + 0x1c) ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(iVar4 + 0xc28) =
         (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6af8) / FLOAT_803e6b54;
  }
  *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xfd;
  *(byte *)(iVar4 + 0xc4a) = *(byte *)(iVar4 + 0xc4a) & 0x7f;
  FUN_80286128();
  return;
}

