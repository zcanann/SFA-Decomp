// Function: FUN_802b4ed8
// Entry: 802b4ed8
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x802b50a4) */
/* WARNING: Removing unreachable block (ram,0x802b509c) */
/* WARNING: Removing unreachable block (ram,0x802b50ac) */

void FUN_802b4ed8(int param_1,char param_2,char param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double in_f29;
  double in_f30;
  double in_f31;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((((param_2 == -1) || ((*(uint *)(iVar5 + 0x360) & 0x4001) == 0)) &&
      ((*(byte *)(iVar5 + 0x3f3) >> 3 & 1) == 0)) && (1 < *(byte *)(param_1 + 0x36))) {
    if ((*(int *)(iVar5 + 0x7f0) != 0) &&
       (((*(ushort *)(param_1 + 0xb0) & 0x1000) != 0 ||
        (iVar4 = FUN_8007fe74(&DAT_803dc6c4,2,(int)*(short *)(iVar5 + 0x274)), iVar4 != -1)))) {
      (**(code **)(**(int **)(*(int *)(iVar5 + 0x7f0) + 0x68) + 0x50))
                ((double)*(float *)(*(int *)(param_1 + 0x50) + 4));
    }
    if ((*(uint *)(iVar5 + 0x360) & 0x8000000) != 0) {
      fVar1 = *(float *)(param_1 + 0xc);
      in_f31 = (double)fVar1;
      fVar2 = *(float *)(param_1 + 0x10);
      in_f30 = (double)fVar2;
      fVar3 = *(float *)(param_1 + 0x14);
      in_f29 = (double)fVar3;
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(param_1 + 100) + 0x20);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(param_1 + 100) + 0x24);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(param_1 + 100) + 0x28);
      *(float *)(*(int *)(param_1 + 100) + 0x20) = fVar1;
      *(float *)(*(int *)(param_1 + 100) + 0x24) = fVar2;
      *(float *)(*(int *)(param_1 + 100) + 0x28) = fVar3;
    }
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + *(float *)(iVar5 + 0x7c8);
    if (param_3 == '\x01') {
      FUN_800414b4(param_1);
    }
    else if (param_3 == '\x02') {
      FUN_800413d4(param_1);
    }
    else if (param_3 == '\x04') {
      FUN_800412dc(param_1);
    }
    FUN_800412d4(0);
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - *(float *)(iVar5 + 0x7c8);
    if ((*(uint *)(iVar5 + 0x360) & 0x8000000) != 0) {
      *(undefined4 *)(*(int *)(param_1 + 100) + 0x20) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(*(int *)(param_1 + 100) + 0x24) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(*(int *)(param_1 + 100) + 0x28) = *(undefined4 *)(param_1 + 0x14);
      *(float *)(param_1 + 0xc) = (float)in_f31;
      *(float *)(param_1 + 0x10) = (float)in_f30;
      *(float *)(param_1 + 0x14) = (float)in_f29;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  return;
}

