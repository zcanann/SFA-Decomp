// Function: FUN_801b7318
// Entry: 801b7318
// Size: 340 bytes

void FUN_801b7318(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8000bb18(param_1,0x1f5);
  if ((*(int *)(iVar2 + 0x10) != 0) &&
     (*(int *)(iVar2 + 0x10) = *(int *)(iVar2 + 0x10) + -1, *(int *)(iVar2 + 0x10) == 0)) {
    FUN_8000a518(0xdf,0);
  }
  if (*(int *)(*(int *)(param_1 + 0x4c) + 0x14) == 0x49b23) {
    iVar1 = FUN_8001ffb4(0xc61);
    if ((iVar1 != 0) &&
       (*(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) + FLOAT_803db414,
       FLOAT_803e4a5c < *(float *)(iVar2 + 0xc))) {
      iVar1 = FUN_8001ffb4(0xc5b);
      if (iVar1 == 0) {
        iVar1 = FUN_8001ffb4(0xc5c);
        if (iVar1 != 0) {
          FUN_800200e8(0xc5c,0);
          FUN_800200e8(0xc5b,1);
        }
      }
      else {
        FUN_800200e8(0xc5c,1);
        FUN_800200e8(0xc5b,0);
      }
      *(float *)(iVar2 + 0xc) = FLOAT_803e4a60;
    }
    iVar2 = FUN_8001ffb4(0xc5b);
    if (iVar2 != 0) {
      FUN_800200e8(0xc5c,0);
    }
    iVar2 = FUN_8001ffb4(0xc5b);
    if (iVar2 == 0) {
      FUN_800200e8(0xc5c,1);
    }
  }
  return;
}

