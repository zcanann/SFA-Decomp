// Function: FUN_802315ec
// Entry: 802315ec
// Size: 444 bytes

void FUN_802315ec(int param_1,undefined4 param_2,int param_3)

{
  char cVar3;
  int iVar1;
  undefined4 uVar2;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  cVar3 = FUN_8002e04c();
  if (cVar3 != '\0') {
    iVar1 = FUN_8002bdf4(0x20,0x616);
    uStack68 = FUN_800221a0(-(int)*(char *)(param_3 + 0x22));
    uStack68 = uStack68 ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(iVar1 + 8) =
         *(float *)(param_1 + 0xc) +
         (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e7148);
    uStack60 = FUN_800221a0(-(int)*(char *)(param_3 + 0x23));
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(iVar1 + 0xc) =
         *(float *)(param_1 + 0x10) +
         (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7148);
    uStack52 = FUN_800221a0(-(int)*(char *)(param_3 + 0x24));
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(iVar1 + 0x10) =
         *(float *)(param_1 + 0x14) +
         (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7148);
    *(undefined *)(iVar1 + 0x1a) = 0;
    *(undefined *)(iVar1 + 0x19) = 0;
    *(undefined *)(iVar1 + 0x18) = 0;
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 1;
    uVar2 = FUN_8002b5a0(param_1,iVar1);
    uStack44 = (int)*(char *)(param_3 + 0x1c) ^ 0x80000000;
    local_30 = 0x43300000;
    local_58 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7148) / FLOAT_803e7140;
    uStack36 = (int)*(char *)(param_3 + 0x1d) ^ 0x80000000;
    local_28 = 0x43300000;
    local_54 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e7148) / FLOAT_803e7140;
    uStack28 = (int)*(char *)(param_3 + 0x1e) ^ 0x80000000;
    local_20 = 0x43300000;
    local_50 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7148) / FLOAT_803e7140;
    FUN_8023137c(uVar2,&local_58);
    FUN_8023134c(uVar2,*(undefined2 *)(param_3 + 0x1a));
  }
  return;
}

