// Function: FUN_80165884
// Entry: 80165884
// Size: 436 bytes

undefined4 FUN_80165884(short *param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  iVar4 = *(int *)(*(int *)(param_1 + 0x5c) + 0x40c);
  iVar2 = FUN_8002bac4();
  *(undefined *)(param_2 + 0x34d) = 1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined2 *)(iVar4 + 0x8e) = 0x3c;
    *(float *)(iVar4 + 0x60) = FLOAT_803e3c94;
    FUN_80035ff8((int)param_1);
  }
  if ((*(char *)(iVar4 + 0x90) == '\x06') ||
     ((((iVar2 != 0 && (*(float *)(iVar4 + 0x48) <= *(float *)(iVar2 + 0x18))) &&
       ((*(float *)(iVar2 + 0x18) <= *(float *)(iVar4 + 0x4c) ||
        (*(float *)(iVar4 + 0x5c) <= *(float *)(iVar2 + 0x1c))))) &&
      (((*(float *)(iVar2 + 0x1c) <= *(float *)(iVar4 + 0x58) ||
        (*(float *)(iVar4 + 0x54) <= *(float *)(iVar2 + 0x20))) &&
       (*(float *)(iVar2 + 0x20) <= *(float *)(iVar4 + 0x50))))))) {
    dVar5 = -(double)(FLOAT_803e3c98 * (*(float *)(iVar2 + 0xc) - *(float *)(param_1 + 6)) -
                     *(float *)(param_1 + 6));
    dVar6 = -(double)(FLOAT_803e3c98 * (*(float *)(iVar2 + 0x10) - *(float *)(param_1 + 8)) -
                     *(float *)(param_1 + 8));
    dVar7 = -(double)(FLOAT_803e3c98 * (*(float *)(iVar2 + 0x14) - *(float *)(param_1 + 10)) -
                     *(float *)(param_1 + 10));
    fVar1 = FLOAT_803e3c8c;
  }
  else {
    dVar5 = (double)*(float *)(param_1 + 6);
    dVar6 = (double)*(float *)(param_1 + 8);
    dVar7 = (double)*(float *)(param_1 + 10);
    fVar1 = FLOAT_803e3c74;
  }
  FUN_80166efc(dVar5,dVar6,dVar7,(double)fVar1,(int)param_1);
  if (*(char *)(iVar4 + 0x90) == '\x06') {
    if ((*(byte *)(iVar4 + 0x92) >> 2 & 1) == 0) {
      FUN_801668f0((int)param_1,iVar4);
    }
    else {
      FUN_80165fe8((int)param_1,iVar4);
    }
  }
  else {
    FUN_80166138(param_1,iVar4);
  }
  if ((ushort)DAT_803dc070 < *(ushort *)(iVar4 + 0x8e)) {
    *(ushort *)(iVar4 + 0x8e) = *(ushort *)(iVar4 + 0x8e) - (ushort)DAT_803dc070;
    uVar3 = 0;
  }
  else {
    uVar3 = 2;
  }
  return uVar3;
}

