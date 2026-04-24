// Function: FUN_80208098
// Entry: 80208098
// Size: 348 bytes

undefined4 FUN_80208098(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar1 == 2) {
      FUN_800200e8(*(short *)(iVar4 + 2) + 5,0);
      *(undefined *)(iVar4 + 8) = 1;
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        FUN_800200e8(*(short *)(iVar4 + 2) + 5,1);
      }
    }
    else if (bVar1 < 4) {
      sVar2 = *(short *)(iVar4 + 2);
      if (sVar2 == 0x674) {
        FUN_800200e8(0x670,1);
        *(undefined2 *)(iVar4 + 4) = 0x96;
      }
      else if (sVar2 < 0x674) {
        if (sVar2 == 0x672) {
          FUN_800200e8(0x66e,1);
          *(undefined2 *)(iVar4 + 4) = 0x96;
        }
        else if (0x671 < sVar2) {
          FUN_800200e8(0x66f,1);
          *(undefined2 *)(iVar4 + 4) = 0x96;
        }
      }
      else if (sVar2 < 0x676) {
        FUN_800200e8(0x9f5,1);
        *(undefined2 *)(iVar4 + 4) = 0x96;
      }
    }
    *(undefined *)(param_3 + iVar3 + 0x81) = 0;
  }
  return 0;
}

