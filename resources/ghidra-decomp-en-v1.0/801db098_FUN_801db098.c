// Function: FUN_801db098
// Entry: 801db098
// Size: 340 bytes

undefined4 FUN_801db098(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 2) {
      FUN_801db1f8(param_1,5);
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        FUN_801db1f8(param_1,7);
      }
    }
    else if (bVar1 < 4) {
      *(byte *)(iVar3 + 0x1f) = *(byte *)(iVar3 + 0x1f) | 2;
    }
  }
  *(byte *)(iVar3 + 0x1f) = *(byte *)(iVar3 + 0x1f) | 1;
  FUN_800200e8(0x60f,0);
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8002b9ec();
  if (*(char *)(iVar2 + 0x1d) == '\x05') {
    FUN_800200e8(0x60f,1);
    iVar3 = FUN_80014670();
    if (iVar3 != 0) {
      iVar3 = FUN_8001ffb4(0x7a);
      if (iVar3 != 0) {
        FUN_800200e8(0x85,1);
      }
      *(float *)(iVar2 + 0x10) = FLOAT_803e5550;
      *(undefined *)(iVar2 + 0x1d) = 0;
      FUN_8000bb18(0,0x10a);
      FUN_8000a518(0xef,0);
    }
  }
  return 0;
}

