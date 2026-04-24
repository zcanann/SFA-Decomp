// Function: FUN_800380e0
// Entry: 800380e0
// Size: 296 bytes

/* WARNING: Removing unreachable block (ram,0x800381e8) */

void FUN_800380e0(undefined4 param_1,undefined4 param_2,float *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f31;
  undefined8 uVar8;
  int local_38;
  int local_34 [11];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar8 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  iVar2 = FUN_8002e0fc(local_34,&local_38);
  iVar3 = 0;
  *param_3 = *param_3 * *param_3;
  if ((int)uVar8 == -1) {
    piVar4 = (int *)(iVar2 + local_34[0] * 4);
    dVar6 = (double)FLOAT_803de970;
    for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
      dVar7 = (double)FUN_800216d0(iVar1 + 0x18,*piVar4 + 0x18);
      if ((dVar7 != dVar6) && (dVar7 < (double)*param_3)) {
        *param_3 = (float)dVar7;
        iVar3 = *piVar4;
      }
      piVar4 = piVar4 + 1;
    }
  }
  else {
    piVar4 = (int *)(iVar2 + local_34[0] * 4);
    for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
      iVar2 = *piVar4;
      if ((((int)uVar8 == (int)*(short *)(iVar2 + 0x46)) && (iVar1 != iVar2)) &&
         (dVar6 = (double)FUN_800216d0(iVar1 + 0x18,iVar2 + 0x18), dVar6 < (double)*param_3)) {
        *param_3 = (float)dVar6;
        iVar3 = *piVar4;
      }
      piVar4 = piVar4 + 1;
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  FUN_80286124(iVar3);
  return;
}

