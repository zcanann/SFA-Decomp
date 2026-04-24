// Function: FUN_802a3f24
// Entry: 802a3f24
// Size: 616 bytes

undefined4 FUN_802a3f24(int param_1,uint *param_2)

{
  float fVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(undefined2 *)(param_2 + 0x9e) = 9;
    *(undefined4 *)(iVar4 + 0x898) = 0;
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
  if (*(short *)(param_1 + 0xa0) == 0x419) {
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      FUN_80030334(param_1,(int)DAT_80332efc,0);
      DAT_803dc6a0 = 6;
      param_2[0xa8] = (uint)FLOAT_803e8038;
      FUN_802ab5a4(param_1,iVar4 + 4,5);
      param_2[0xc2] = 0;
      return 0xd;
    }
  }
  else {
    FUN_80030334(param_1,0x419,1);
    param_2[0xa8] = (uint)FLOAT_803e7e90;
    uVar2 = FUN_800217c0((double)*(float *)(iVar4 + 0x5c4),(double)*(float *)(iVar4 + 0x5cc));
    *(undefined2 *)(iVar4 + 0x478) = uVar2;
    *(undefined2 *)(iVar4 + 0x484) = *(undefined2 *)(iVar4 + 0x478);
    fVar1 = FLOAT_803e7f10;
    *(float *)(param_1 + 0x18) =
         FLOAT_803e7f10 * *(float *)(iVar4 + 0x5c4) + *(float *)(iVar4 + 0x5d4);
    *(float *)(param_1 + 0x1c) = *(float *)(iVar4 + 0x5ac) - *(float *)(iVar4 + 0x874);
    *(float *)(param_1 + 0x20) = fVar1 * *(float *)(iVar4 + 0x5cc) + *(float *)(iVar4 + 0x5dc);
    FUN_8000e034((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),param_1 + 0xc,param_1 + 0x10,param_1 + 0x14,
                 *(undefined4 *)(param_1 + 0x30));
    FUN_80062e84(param_1,*(undefined4 *)(iVar4 + 0x4c4),1);
    if (*(int *)(iVar4 + 0x4c4) != 0) {
      FUN_8000e034((double)*(float *)(iVar4 + 0x5d4),(double)*(float *)(iVar4 + 0x5d8),
                   (double)*(float *)(iVar4 + 0x5dc),iVar4 + 0x5d4,iVar4 + 0x5d8,iVar4 + 0x5dc);
      FUN_8000e034((double)*(float *)(iVar4 + 0x5ec),(double)*(float *)(iVar4 + 0x5f0),
                   (double)*(float *)(iVar4 + 0x5f4),iVar4 + 0x5ec,iVar4 + 0x5f0,iVar4 + 0x5f4,
                   *(undefined4 *)(iVar4 + 0x4c4));
      FUN_8000e034((double)*(float *)(iVar4 + 0x5f8),(double)*(float *)(iVar4 + 0x5fc),
                   (double)*(float *)(iVar4 + 0x600),iVar4 + 0x5f8,iVar4 + 0x5fc,iVar4 + 0x600,
                   *(undefined4 *)(iVar4 + 0x4c4));
      *(float *)(iVar4 + 0x5ac) =
           *(float *)(iVar4 + 0x5ac) - *(float *)(*(int *)(iVar4 + 0x4c4) + 0x10);
      *(float *)(iVar4 + 0x5b0) =
           *(float *)(iVar4 + 0x5b0) - *(float *)(*(int *)(iVar4 + 0x4c4) + 0x10);
      *(undefined *)(iVar4 + 0x609) = 0;
    }
  }
  FUN_802ab5a4(param_1,iVar4 + 4,5);
  return 0;
}

