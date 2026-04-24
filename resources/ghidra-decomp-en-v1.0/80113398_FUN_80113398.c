// Function: FUN_80113398
// Entry: 80113398
// Size: 364 bytes

/* WARNING: Removing unreachable block (ram,0x801134dc) */
/* WARNING: Removing unreachable block (ram,0x801134e4) */

void FUN_80113398(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined2 param_5,float *param_6,float *param_7,int *param_8)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar10 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar10 >> 0x20);
  iVar4 = (int)uVar10;
  if (*(char *)(iVar4 + 0x381) == '\0') {
    uVar3 = 0;
  }
  else {
    *(undefined4 *)(iVar4 + 0x318) = 0;
    *(undefined4 *)(iVar4 + 0x31c) = 0;
    *(undefined2 *)(iVar4 + 0x330) = 0;
    fVar1 = FLOAT_803e1c2c;
    *(float *)(iVar4 + 0x290) = FLOAT_803e1c2c;
    *(float *)(iVar4 + 0x28c) = fVar1;
    *param_8 = 1;
    dVar9 = (double)(*param_6 - *(float *)(iVar2 + 0xc));
    dVar8 = (double)(*param_7 - *(float *)(iVar2 + 0x14));
    dVar6 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)));
    if ((double)FLOAT_803e1c68 <= dVar6) {
      dVar7 = (double)FLOAT_803e1c6c;
      *(float *)(iVar4 + 0x290) = (float)(dVar7 * -(double)(float)(dVar9 / dVar6));
      *(float *)(iVar4 + 0x28c) = (float)(dVar7 * (double)(float)(dVar8 / dVar6));
      *(float *)(iVar2 + 0xc) =
           (float)(dVar6 * (double)(float)(dVar9 / dVar6) + (double)*(float *)(iVar2 + 0xc));
      *(float *)(iVar2 + 0x14) =
           (float)(dVar6 * (double)(float)(dVar8 / dVar6) + (double)*(float *)(iVar2 + 0x14));
      (**(code **)(*DAT_803dca8c + 8))
                ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar2,iVar4,param_3,param_4);
    }
    else {
      *param_8 = 0;
    }
    if (*param_8 == 0) {
      *(undefined *)(iVar4 + 0x405) = 0;
      *(undefined2 *)(iVar4 + 0x274) = param_5;
      *(undefined4 *)(iVar4 + 0x2d0) = 0;
      *(undefined *)(iVar4 + 0x25f) = 0;
      FUN_800200e8((int)*(short *)(iVar4 + 0x3f4),0);
    }
    uVar3 = 1;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  FUN_80286124(uVar3);
  return;
}

