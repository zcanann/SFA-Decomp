// Function: FUN_80210ff8
// Entry: 80210ff8
// Size: 212 bytes

undefined4
FUN_80210ff8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined4 param_10,int param_11)

{
  undefined4 uVar1;
  int iVar2;
  undefined8 uVar3;
  
  *(byte *)(*(int *)(param_9 + 0xb8) + 9) = *(byte *)(*(int *)(param_9 + 0xb8) + 9) | 1;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
    if (*(char *)(param_11 + iVar2 + 0x81) == '\x01') {
      FUN_800201ac(0xdca,1);
      uVar3 = FUN_800201ac(0x458,0);
      FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xc);
      FUN_80043604(0,0,1);
      uVar1 = FUN_8004832c(0xc);
      FUN_80043658(uVar1,0);
      (**(code **)(*DAT_803dd72c + 0x50))(0xc,1,1);
    }
  }
  return 0;
}

