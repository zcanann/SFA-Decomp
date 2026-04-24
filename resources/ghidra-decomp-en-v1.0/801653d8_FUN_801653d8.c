// Function: FUN_801653d8
// Entry: 801653d8
// Size: 436 bytes

undefined4 FUN_801653d8(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  iVar4 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  iVar2 = FUN_8002b9ec();
  *(undefined *)(param_2 + 0x34d) = 1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined2 *)(iVar4 + 0x8e) = 0x3c;
    *(float *)(iVar4 + 0x60) = FLOAT_803e2ffc;
    FUN_80035f00(param_1);
  }
  if ((*(char *)(iVar4 + 0x90) == '\x06') ||
     ((((iVar2 != 0 && (*(float *)(iVar4 + 0x48) <= *(float *)(iVar2 + 0x18))) &&
       ((*(float *)(iVar2 + 0x18) <= *(float *)(iVar4 + 0x4c) ||
        (*(float *)(iVar4 + 0x5c) <= *(float *)(iVar2 + 0x1c))))) &&
      (((*(float *)(iVar2 + 0x1c) <= *(float *)(iVar4 + 0x58) ||
        (*(float *)(iVar4 + 0x54) <= *(float *)(iVar2 + 0x20))) &&
       (*(float *)(iVar2 + 0x20) <= *(float *)(iVar4 + 0x50))))))) {
    dVar5 = -(double)(FLOAT_803e3000 * (*(float *)(iVar2 + 0xc) - *(float *)(param_1 + 0xc)) -
                     *(float *)(param_1 + 0xc));
    dVar6 = -(double)(FLOAT_803e3000 * (*(float *)(iVar2 + 0x10) - *(float *)(param_1 + 0x10)) -
                     *(float *)(param_1 + 0x10));
    dVar7 = -(double)(FLOAT_803e3000 * (*(float *)(iVar2 + 0x14) - *(float *)(param_1 + 0x14)) -
                     *(float *)(param_1 + 0x14));
    fVar1 = FLOAT_803e2ff4;
  }
  else {
    dVar5 = (double)*(float *)(param_1 + 0xc);
    dVar6 = (double)*(float *)(param_1 + 0x10);
    dVar7 = (double)*(float *)(param_1 + 0x14);
    fVar1 = FLOAT_803e2fdc;
  }
  FUN_80166a50(dVar5,dVar6,dVar7,(double)fVar1,param_1);
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
  if ((ushort)DAT_803db410 < *(ushort *)(iVar4 + 0x8e)) {
    *(ushort *)(iVar4 + 0x8e) = *(ushort *)(iVar4 + 0x8e) - (ushort)DAT_803db410;
    uVar3 = 0;
  }
  else {
    uVar3 = 2;
  }
  return uVar3;
}

