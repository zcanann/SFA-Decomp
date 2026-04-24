// Function: FUN_8005df5c
// Entry: 8005df5c
// Size: 240 bytes

/* WARNING: Removing unreachable block (ram,0x8005e318) */
/* WARNING: Removing unreachable block (ram,0x8005e320) */

undefined4 FUN_8005df5c(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  float local_58;
  float local_54;
  float local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar4 = 0;
  iVar3 = 0;
  dVar5 = (double)FLOAT_803dec20;
  dVar6 = (double)FLOAT_803dec28;
  while( true ) {
    if (uVar4 < 8) {
                    /* WARNING: Could not recover jumptable at 0x8005dfb8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)((int)&PTR_LAB_8030e844 + iVar3))();
      return uVar1;
    }
    local_58 = (float)((double)local_58 * dVar5);
    local_54 = (float)((double)local_54 * dVar5);
    local_50 = (float)((double)local_50 * dVar5);
    FUN_80247494(param_2,&local_58,&local_58);
    if (dVar6 <= (double)local_50) break;
    uVar4 = uVar4 + 1;
    iVar3 = iVar3 + 4;
    if (7 < (int)uVar4) {
      uVar2 = 0;
LAB_8005e318:
      __psq_l0(auStack8,uVar1);
      __psq_l1(auStack8,uVar1);
      __psq_l0(auStack24,uVar1);
      __psq_l1(auStack24,uVar1);
      return uVar2;
    }
  }
  uVar2 = 1;
  goto LAB_8005e318;
}

