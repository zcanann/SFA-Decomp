// Function: FUN_801a5d88
// Entry: 801a5d88
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x801a5f4c) */

void FUN_801a5d88(int param_1)

{
  undefined uVar2;
  uint uVar1;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(param_1 + 0xb8);
  DAT_803ddb20 = DAT_803ddb20 + 1;
  FUN_8000bb18(param_1,0x106);
  if (DAT_803ddb20 < 2) {
    uVar2 = FUN_800221a0(0,1);
    uVar1 = FUN_800221a0(0x32,0x3c);
    FUN_8009ab70((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e4488),
                 param_1,1,1,0,uVar2,0,1,0);
  }
  else {
    uVar2 = FUN_800221a0(0,1);
    uVar1 = FUN_800221a0(0x32,0x3c);
    FUN_8009ab70((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e4488),
                 param_1,1,1,0,uVar2,0,0,0);
  }
  *(undefined *)(iVar3 + 0x114) = 1;
  *(float *)(iVar3 + 0x110) = FLOAT_803e4468;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  FUN_80035974(param_1,(int)(FLOAT_803e446c *
                            (float)((double)CONCAT44(0x43300000,
                                                     (uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62
                                                                    )) - DOUBLE_803e4490)));
  iVar3 = FUN_8002b9ec();
  if ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0) {
    dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar3 + 0x18);
    if (dVar5 <= (double)FLOAT_803e4470) {
      dVar5 = (double)(FLOAT_803e4474 - (float)(dVar5 / (double)FLOAT_803e4470));
      FUN_8000e650((double)(float)((double)FLOAT_803e4478 * dVar5),
                   (double)(float)((double)FLOAT_803e447c * dVar5),(double)FLOAT_803e4480);
      FUN_80014aa0((double)(float)((double)FLOAT_803e4484 * dVar5));
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

