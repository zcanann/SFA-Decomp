// Function: FUN_8016558c
// Entry: 8016558c
// Size: 1068 bytes

/* WARNING: Removing unreachable block (ram,0x80165988) */
/* WARNING: Removing unreachable block (ram,0x80165978) */
/* WARNING: Removing unreachable block (ram,0x801657b0) */
/* WARNING: Removing unreachable block (ram,0x80165980) */
/* WARNING: Removing unreachable block (ram,0x80165990) */

undefined4 FUN_8016558c(undefined2 *param_1,uint *param_2)

{
  int iVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,SUB84(in_f28,0),0);
  iVar4 = *(int *)(*(int *)(param_1 + 0x5c) + 0x40c);
  iVar1 = FUN_8002b9ec();
  *(undefined *)((int)param_2 + 0x34d) = 1;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0x60) = FLOAT_803e3004;
    FUN_80035f20(param_1);
    dVar6 = (double)FUN_80293464(*param_1);
    *(float *)(param_1 + 0x12) = (float)(-(double)*(float *)(iVar4 + 0x60) * dVar6);
    *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
    dVar6 = (double)FUN_8029397c(*param_1);
    *(float *)(param_1 + 0x16) = (float)(-(double)*(float *)(iVar4 + 0x60) * dVar6);
    *param_2 = *param_2 | 0x2004000;
    FUN_80030334((double)FLOAT_803e2fdc,param_1,0,0);
    *(float *)(iVar4 + 0x44) = FLOAT_803e3008;
  }
  FUN_80035df4(param_1,9,1,0xffffffff);
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6c) = 9;
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6d) = 1;
  FUN_8003393c(param_1);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,param_2 + 1);
  if (*(char *)(iVar4 + 0x90) == '\x06') {
    if ((*(byte *)(iVar4 + 0x92) & 1) == 0) {
      uVar3 = 0;
    }
    else {
      uVar3 = 2;
      if ((ushort)DAT_803db410 < *(ushort *)(iVar4 + 0x8e)) {
        *(ushort *)(iVar4 + 0x8e) = *(ushort *)(iVar4 + 0x8e) - (ushort)DAT_803db410;
      }
      else {
        *(byte *)(iVar4 + 0x92) = *(byte *)(iVar4 + 0x92) & 0xfe;
      }
    }
  }
  else if ((((iVar1 == 0) || (*(float *)(iVar1 + 0x18) < *(float *)(iVar4 + 0x48))) ||
           (*(float *)(iVar4 + 0x4c) < *(float *)(iVar1 + 0x18))) ||
          (((*(float *)(iVar1 + 0x1c) < *(float *)(iVar4 + 0x5c) ||
            (*(float *)(iVar4 + 0x58) < *(float *)(iVar1 + 0x1c))) ||
           ((*(float *)(iVar1 + 0x20) < *(float *)(iVar4 + 0x54) ||
            (*(float *)(iVar4 + 0x50) < *(float *)(iVar1 + 0x20))))))) {
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
  }
  if (uVar3 == 1) {
    if ((ushort)DAT_803db410 < *(ushort *)(iVar4 + 0x8c)) {
      *(ushort *)(iVar4 + 0x8c) = *(ushort *)(iVar4 + 0x8c) - (ushort)DAT_803db410;
    }
    else {
      uVar3 = FUN_800221a0((int)*(float *)(iVar4 + 0x48),(int)*(float *)(iVar4 + 0x4c));
      *(float *)(iVar4 + 100) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3018);
      uVar3 = FUN_800221a0((int)*(float *)(iVar4 + 0x5c),(int)*(float *)(iVar4 + 0x58));
      *(float *)(iVar4 + 0x68) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3018);
      uVar3 = FUN_800221a0((int)*(float *)(iVar4 + 0x54),(int)*(float *)(iVar4 + 0x50));
      *(float *)(iVar4 + 0x6c) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3018);
      uVar2 = FUN_800221a0(300,600);
      *(undefined2 *)(iVar4 + 0x8c) = uVar2;
    }
    in_f31 = (double)*(float *)(iVar4 + 100);
    in_f30 = (double)*(float *)(iVar4 + 0x68);
    in_f29 = (double)*(float *)(iVar4 + 0x6c);
    in_f28 = (double)FLOAT_803e3010;
  }
  else if (uVar3 == 0) {
    in_f31 = (double)*(float *)(iVar1 + 0xc);
    in_f30 = (double)(float)((double)*(float *)(iVar1 + 0x10) - (double)FLOAT_803e2fd8);
    in_f29 = (double)*(float *)(iVar1 + 0x14);
    in_f28 = (double)FLOAT_803e300c;
    iVar1 = FUN_8001ffb4((double)*(float *)(iVar1 + 0x10),0x698);
    if (iVar1 != 0) {
      in_f28 = -(double)FLOAT_803e300c;
    }
  }
  else if (uVar3 < 3) {
    in_f31 = (double)*(float *)(iVar4 + 0x70);
    in_f30 = (double)*(float *)(iVar4 + 0x74);
    in_f29 = (double)*(float *)(iVar4 + 0x78);
    in_f28 = (double)FLOAT_803e300c;
  }
  FUN_80166a50(in_f31,in_f30,in_f29,in_f28,param_1);
  if (*(char *)(iVar4 + 0x90) == '\x06') {
    if ((*(byte *)(iVar4 + 0x92) >> 2 & 1) == 0) {
      FUN_80166444(param_1,iVar4);
    }
    else {
      FUN_80165b3c(param_1,iVar4);
    }
  }
  else {
    FUN_80165c8c(param_1,iVar4);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  __psq_l0(auStack56,uVar5);
  __psq_l1(auStack56,uVar5);
  return 0;
}

