// Function: FUN_801c5d64
// Entry: 801c5d64
// Size: 380 bytes

/* WARNING: Removing unreachable block (ram,0x801c5ec0) */
/* WARNING: Removing unreachable block (ram,0x801c5d74) */

void FUN_801c5d64(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  double in_f31;
  undefined4 *local_28 [4];
  
  iVar5 = *(int *)(param_1 + 0x4c);
  FUN_80035eec(param_1,9,1,0);
  iVar3 = FUN_8002e1ac(*(int *)(param_1 + 0xf8));
  if (iVar3 == 0) {
    FUN_80137cd0();
    iVar3 = FUN_80065fcc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,local_28,0,0);
    if ((iVar3 != 0) && (in_f31 = (double)FLOAT_803e5c18, 0 < iVar3)) {
      do {
        if ((*(char *)((float *)*local_28[0] + 5) == '\x0e') &&
           (dVar6 = (double)(*(float *)*local_28[0] - *(float *)(param_1 + 0x10)), in_f31 < dVar6))
        {
          in_f31 = dVar6;
        }
        local_28[0] = local_28[0] + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  else {
    dVar6 = FUN_80194e3c(iVar3,3);
    in_f31 = (double)(float)(dVar6 - (double)*(float *)(param_1 + 0x10));
  }
  fVar1 = (float)((double)*(float *)(param_1 + 0x10) + in_f31);
  fVar2 = *(float *)(iVar5 + 0xc);
  if (fVar1 <= fVar2) {
    *(float *)(param_1 + 0x10) = fVar1;
    *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    if (*(int *)(param_1 + 0xf4) < 1) {
      uVar4 = FUN_80022264(0x3c,0xf0);
      *(uint *)(param_1 + 0xf4) = uVar4;
      if ((double)FLOAT_803e5c1c == in_f31) {
        (**(code **)(*DAT_803dd718 + 0x14))
                  ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                   (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e5c20,0,3);
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = fVar2;
  }
  return;
}

