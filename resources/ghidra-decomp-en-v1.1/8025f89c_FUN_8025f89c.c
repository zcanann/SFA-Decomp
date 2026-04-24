// Function: FUN_8025f89c
// Entry: 8025f89c
// Size: 324 bytes

undefined4 FUN_8025f89c(int param_1,uint param_2,byte *param_3,int param_4,int param_5)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  byte local_24;
  byte local_23;
  undefined local_22;
  byte local_21;
  byte local_20;
  
  iVar5 = FUN_80254534(param_1,0,4);
  if (iVar5 == 0) {
    uVar6 = 0xfffffffd;
  }
  else {
    FUN_800033a8((int)&local_24,0,5);
    local_24 = 0x52;
    local_23 = (byte)((param_2 & 0xfffff000) >> 0x18);
    if (param_5 == 0) {
      local_23 = local_23 >> 5 & 3;
      local_22 = (undefined)(param_2 >> 0x15);
      local_21 = (byte)(param_2 >> 0x13) & 3;
      local_20 = (byte)(param_2 >> 0xc) & 0x7f;
    }
    else {
      local_22 = (undefined)((param_2 & 0xfffff000) >> 0x10);
    }
    uVar6 = FUN_80253c3c(param_1,&local_24,5,1);
    uVar1 = countLeadingZeros(uVar6);
    uVar6 = FUN_80253c3c(param_1,(byte *)((&DAT_803afec0)[param_1 * 0x44] + 0x200),
                         *(int *)(&DAT_803afe54 + param_1 * 0x110),1);
    uVar2 = countLeadingZeros(uVar6);
    uVar6 = FUN_80253c3c(param_1,param_3,param_4,0);
    uVar3 = countLeadingZeros(uVar6);
    uVar6 = FUN_80254660(param_1);
    uVar4 = countLeadingZeros(uVar6);
    if (((uVar1 >> 5 == 0 && uVar2 >> 5 == 0) && uVar3 >> 5 == 0) && uVar4 >> 5 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = 0xfffffffd;
    }
  }
  return uVar6;
}

