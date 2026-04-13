// Function: FUN_8028c214
// Entry: 8028c214
// Size: 292 bytes

void FUN_8028c214(int param_1)

{
  int iVar1;
  undefined4 extraout_r4;
  undefined4 uVar2;
  undefined4 extraout_r4_00;
  uint *puVar3;
  uint *puVar4;
  int local_18;
  undefined4 local_14;
  
  iVar1 = FUN_80287c44(param_1,DAT_803d9080);
  if (iVar1 == 0) {
    local_18 = 4;
    iVar1 = FUN_8028ce58((int)&local_14,DAT_803d9080,&local_18,0,1);
    if ((iVar1 == 0) && (local_18 != 4)) {
      iVar1 = 0x700;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80287c44(param_1,local_14);
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80287ca8(param_1,(short)DAT_803d92f8);
  }
  if (iVar1 == 0) {
    iVar1 = 0;
    puVar3 = &DAT_803d9000;
    puVar4 = puVar3;
    do {
      FUN_80287c44(param_1,*puVar4 & 0xffff);
      iVar1 = iVar1 + 1;
      puVar4 = puVar4 + 1;
    } while (iVar1 < 0x20);
    iVar1 = 0;
    uVar2 = extraout_r4;
    do {
      FUN_80287bbc(param_1,uVar2,0,puVar3[0x27] & 0xffff);
      iVar1 = iVar1 + 1;
      puVar3 = puVar3 + 2;
      uVar2 = extraout_r4_00;
    } while (iVar1 < 0x20);
  }
  return;
}

