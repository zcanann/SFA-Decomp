// Function: FUN_8029d900
// Entry: 8029d900
// Size: 352 bytes

/* WARNING: Removing unreachable block (ram,0x8029da3c) */

undefined4 FUN_8029d900(undefined8 param_1,int param_2,int param_3)

{
  short sVar1;
  int iVar2;
  undefined2 uVar4;
  undefined4 uVar3;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  int local_28 [3];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *(int *)(param_2 + 0xb8);
  *(undefined *)(param_3 + 0x34d) = 3;
  if (*(char *)(param_3 + 0x27a) != '\0') {
    iVar2 = FUN_8003687c(param_2,local_28,0,0);
    if (iVar2 != 0) {
      uVar4 = FUN_800217c0(-(double)*(float *)(local_28[0] + 0x24),
                           -(double)*(float *)(local_28[0] + 0x2c));
      *(undefined2 *)(iVar5 + 0x478) = uVar4;
      *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
    }
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x407,0);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7f34;
  }
  sVar1 = *(short *)(param_2 + 0xa0);
  if (sVar1 == 0x408) {
    if (*(char *)(param_3 + 0x346) != '\0') {
      *(code **)(param_3 + 0x308) = FUN_802a514c;
      uVar3 = 2;
      goto LAB_8029da3c;
    }
  }
  else if (((sVar1 < 0x408) && (0x406 < sVar1)) && (*(char *)(param_3 + 0x346) != '\0')) {
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x408,0);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7fcc;
  }
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  uVar3 = 0;
LAB_8029da3c:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return uVar3;
}

