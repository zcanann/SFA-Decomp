// Function: FUN_801b78cc
// Entry: 801b78cc
// Size: 340 bytes

void FUN_801b78cc(uint param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8000bb38(param_1,0x1f5);
  if ((*(int *)(iVar2 + 0x10) != 0) &&
     (*(int *)(iVar2 + 0x10) = *(int *)(iVar2 + 0x10) + -1, *(int *)(iVar2 + 0x10) == 0)) {
    FUN_8000a538((int *)0xdf,0);
  }
  if (*(int *)(*(int *)(param_1 + 0x4c) + 0x14) == 0x49b23) {
    uVar1 = FUN_80020078(0xc61);
    if ((uVar1 != 0) &&
       (*(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) + FLOAT_803dc074,
       FLOAT_803e56f4 < *(float *)(iVar2 + 0xc))) {
      uVar1 = FUN_80020078(0xc5b);
      if (uVar1 == 0) {
        uVar1 = FUN_80020078(0xc5c);
        if (uVar1 != 0) {
          FUN_800201ac(0xc5c,0);
          FUN_800201ac(0xc5b,1);
        }
      }
      else {
        FUN_800201ac(0xc5c,1);
        FUN_800201ac(0xc5b,0);
      }
      *(float *)(iVar2 + 0xc) = FLOAT_803e56f8;
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 != 0) {
      FUN_800201ac(0xc5c,0);
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 == 0) {
      FUN_800201ac(0xc5c,1);
    }
  }
  return;
}

