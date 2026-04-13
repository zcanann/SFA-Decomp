// Function: FUN_801a7500
// Entry: 801a7500
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x801a7558) */

undefined4
FUN_801a7500(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
            undefined4 param_10,int param_11)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_9 + 0xb8);
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
    if (bVar1 == 2) {
      *pbVar4 = *pbVar4 & 0xf6;
      *pbVar4 = *pbVar4 | 0x30;
      *(undefined *)(param_9 + 0xad) = 1;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        param_1 = FUN_8005cf74(0);
      }
      else {
        *pbVar4 = 0xd;
        pbVar4[1] = 1;
        param_1 = FUN_800201ac(0x87b,(uint)pbVar4[1]);
        *(undefined *)(param_9 + 0x36) = 0xff;
      }
    }
    else if (bVar1 == 4) {
      *(float *)(pbVar4 + 4) = FLOAT_803e5180;
      param_1 = FUN_8005cf74(1);
    }
    else if (bVar1 < 4) {
      *pbVar4 = *pbVar4 & 0xdf;
      *pbVar4 = *pbVar4 | 0x50;
      uVar2 = FUN_80022264(10,0x3c);
      *(float *)(pbVar4 + 8) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5188);
      pbVar4[1] = 1;
      param_1 = FUN_800201ac(0x87b,(uint)pbVar4[1]);
    }
  }
  *pbVar4 = *pbVar4 | 0x80;
  FUN_801a76d8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  return 0;
}

