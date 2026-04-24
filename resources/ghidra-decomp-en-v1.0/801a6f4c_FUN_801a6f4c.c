// Function: FUN_801a6f4c
// Entry: 801a6f4c
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x801a6fa4) */

undefined4 FUN_801a6f4c(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar1 == 2) {
      *pbVar4 = *pbVar4 & 0xf6;
      *pbVar4 = *pbVar4 | 0x30;
      *(undefined *)(param_1 + 0xad) = 1;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        FUN_8005cdf8(0);
      }
      else {
        *pbVar4 = 0xd;
        pbVar4[1] = 1;
        FUN_800200e8(0x87b,pbVar4[1]);
        *(undefined *)(param_1 + 0x36) = 0xff;
      }
    }
    else if (bVar1 == 4) {
      *(float *)(pbVar4 + 4) = FLOAT_803e44e8;
      FUN_8005cdf8(1);
    }
    else if (bVar1 < 4) {
      *pbVar4 = *pbVar4 & 0xdf;
      *pbVar4 = *pbVar4 | 0x50;
      uVar2 = FUN_800221a0(10,0x3c);
      *(float *)(pbVar4 + 8) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e44f0);
      pbVar4[1] = 1;
      FUN_800200e8(0x87b,pbVar4[1]);
    }
  }
  *pbVar4 = *pbVar4 | 0x80;
  FUN_801a7124(param_1);
  return 0;
}

