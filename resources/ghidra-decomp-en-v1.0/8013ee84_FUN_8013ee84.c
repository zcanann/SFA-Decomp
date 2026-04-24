// Function: FUN_8013ee84
// Entry: 8013ee84
// Size: 264 bytes

/* WARNING: Removing unreachable block (ram,0x8013ef60) */
/* WARNING: Removing unreachable block (ram,0x8013ef68) */

int FUN_8013ee84(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f30;
  undefined8 in_f31;
  int local_38 [3];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar1 = *(int *)(param_2 + 0x24);
  if (*(short *)(iVar1 + 0x46) != 0x6a3) {
    iVar1 = FUN_80296118(*(undefined4 *)(param_2 + 4));
    if ((iVar1 != 0) && (piVar2 = (int *)FUN_80036f50(3,local_38), 0 < local_38[0])) {
      do {
        if (*piVar2 == iVar1) {
          dVar4 = (double)FUN_80021690(param_1 + 0x18,iVar1 + 0x18);
          dVar5 = (double)FUN_80021690(param_1 + 0x18,*(int *)(param_2 + 4) + 0x18);
          dVar6 = (double)FUN_80021690(iVar1 + 0x18,*(int *)(param_2 + 4) + 0x18);
          if ((float)(dVar4 + dVar5) < (float)((double)FLOAT_803e23f8 * dVar6)) goto LAB_8013ef60;
          break;
        }
        piVar2 = piVar2 + 1;
        local_38[0] = local_38[0] + -1;
      } while (local_38[0] != 0);
    }
    iVar1 = 0;
  }
LAB_8013ef60:
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  return iVar1;
}

