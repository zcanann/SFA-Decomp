// Function: FUN_801db688
// Entry: 801db688
// Size: 340 bytes

undefined4 FUN_801db688(int param_1,undefined4 param_2,int param_3)

{
  byte bVar2;
  uint uVar1;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar2 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar2 == 2) {
      FUN_801db7e8(param_1,5);
    }
    else if (bVar2 < 2) {
      if (bVar2 != 0) {
        FUN_801db7e8(param_1,7);
      }
    }
    else if (bVar2 < 4) {
      *(byte *)(iVar4 + 0x1f) = *(byte *)(iVar4 + 0x1f) | 2;
    }
  }
  *(byte *)(iVar4 + 0x1f) = *(byte *)(iVar4 + 0x1f) | 1;
  FUN_800201ac(0x60f,0);
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_8002bac4();
  if (*(char *)(iVar3 + 0x1d) == '\x05') {
    FUN_800201ac(0x60f,1);
    bVar2 = FUN_8001469c();
    if (bVar2 != 0) {
      uVar1 = FUN_80020078(0x7a);
      if (uVar1 != 0) {
        FUN_800201ac(0x85,1);
      }
      *(float *)(iVar3 + 0x10) = FLOAT_803e61e8;
      *(undefined *)(iVar3 + 0x1d) = 0;
      FUN_8000bb38(0,0x10a);
      FUN_8000a538((int *)0xef,0);
    }
  }
  return 0;
}

