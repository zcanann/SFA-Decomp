// Function: FUN_80202294
// Entry: 80202294
// Size: 404 bytes

undefined4 FUN_80202294(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar3 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,param_1,0,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined4 *)(param_2 + 0x2d0) = 0;
    if (*(int *)(iVar3 + 0x18) != 0) {
      FUN_800378c4(*(int *)(iVar3 + 0x18),0x11,param_1,0x10);
      *(undefined4 *)(iVar3 + 0x18) = 0;
    }
    iVar1 = FUN_8002b9ec();
    iVar1 = (**(code **)(**(int **)(*(int *)(iVar1 + 200) + 0x68) + 0x44))();
    if (iVar1 == 0) {
      iVar1 = FUN_800221a0(0,2);
      FUN_8000bb18(param_1,*(uint *)(&DAT_80329650 + iVar1 * 4) & 0xffff);
    }
    else {
      iVar1 = FUN_800221a0(3,4);
      FUN_8000bb18(param_1,*(uint *)(&DAT_80329650 + iVar1 * 4) & 0xffff);
    }
    local_20 = *(undefined4 *)(iVar3 + 0x30);
    local_24 = *(undefined4 *)(iVar3 + 0x2c);
    uVar2 = *(undefined4 *)(iVar3 + 0x24);
    local_28 = *(undefined4 *)(iVar3 + 0x28);
    iVar1 = FUN_800138c4(uVar2);
    if (iVar1 == 0) {
      FUN_80013958(uVar2,&local_28);
    }
    *(undefined4 *)(iVar3 + 0x3c) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 0x10;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e6340;
  *(float *)(param_2 + 0x280) = FLOAT_803e62a8;
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined *)(iVar3 + 0x34) = 1;
  }
  return 0;
}

