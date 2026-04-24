// Function: FUN_802a00e0
// Entry: 802a00e0
// Size: 732 bytes

undefined4 FUN_802a00e0(int param_1,uint *param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined auStack40 [4];
  undefined auStack36 [8];
  undefined auStack28 [8];
  float local_14;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  FUN_802a13f4();
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    FUN_80035e8c(param_1);
    if ((*(char *)(iVar4 + 0x8c8) != 'H') && (*(char *)(iVar4 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x3c,0xff);
    }
    FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)DAT_80332f6e,1);
    FUN_8002ed6c(param_1,(int)DAT_80332f70,0);
    param_2[0xa8] = (uint)FLOAT_803e7f34;
    FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(param_1 + 8),
                 *(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),0,0,
                 auStack28,auStack36);
    *(float *)(iVar4 + 0x564) = *(float *)(iVar4 + 0x56c) * local_14;
    *(float *)(iVar4 + 0x568) = *(float *)(iVar4 + 0x574) * local_14;
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0x550);
    *(undefined2 *)(param_2 + 0x9e) = 0x15;
    *(code **)(iVar4 + 0x898) = FUN_8029ffd0;
  }
  iVar3 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) & 0xfffffffd;
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x2000;
  param_2[1] = param_2[1] | 0x100000;
  fVar1 = FLOAT_803e7ea4;
  param_2[0xa0] = (uint)FLOAT_803e7ea4;
  param_2[0xa1] = (uint)fVar1;
  *param_2 = *param_2 | 0x200000;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  param_2[1] = param_2[1] | 0x8000000;
  *(float *)(param_1 + 0x28) = fVar1;
  FUN_8002f52c(param_1,0,1,(int)*(short *)(iVar4 + 0x5a4));
  if ((param_2[0xc5] & 0x200) != 0) {
    FUN_80014aa0((double)FLOAT_803e7f10);
  }
  fVar1 = *(float *)(param_1 + 0x98);
  if (fVar1 <= FLOAT_803e7f68) {
    (**(code **)(*DAT_803dca50 + 0x2c))
              ((double)(*(float *)(iVar4 + 0x564) * fVar1 + *(float *)(param_1 + 0xc)),
               -(double)(*(float *)(iVar4 + 0x560) * (FLOAT_803e7ee0 - fVar1) -
                        *(float *)(param_1 + 0x10)),
               (double)(*(float *)(iVar4 + 0x568) * fVar1 + *(float *)(param_1 + 0x14)));
    FUN_802ab5a4(param_1,iVar4,5);
    uVar2 = 0;
  }
  else {
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(iVar4 + 0x768);
    *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(iVar4 + 0x770);
    if (*(int *)(param_1 + 0x30) != 0) {
      *(float *)(param_1 + 0x18) = *(float *)(param_1 + 0x18) + FLOAT_803dcdd8;
      *(float *)(param_1 + 0x20) = *(float *)(param_1 + 0x20) + FLOAT_803dcddc;
    }
    FUN_8000e034((double)*(float *)(param_1 + 0x18),(double)FLOAT_803e7ea4,
                 (double)*(float *)(param_1 + 0x20),param_1 + 0xc,auStack40,param_1 + 0x14,
                 *(undefined4 *)(param_1 + 0x30));
    FUN_802ab5a4(param_1,iVar4,5);
    FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)**(short **)(iVar4 + 0x3f8),1);
    *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
    param_2[0xc2] = (uint)FUN_802a514c;
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

