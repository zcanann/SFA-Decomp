// Function: FUN_80238ab0
// Entry: 80238ab0
// Size: 180 bytes

/* WARNING: Removing unreachable block (ram,0x80238b3c) */

undefined4 FUN_80238ab0(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  double dVar3;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar3 = DOUBLE_803e7428;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    FUN_8009ab70((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + iVar1 + 0x81)
                                                 ) - dVar3),param_1,1,1,1,1,0,1,0);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return 0;
}

