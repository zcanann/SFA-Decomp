// Function: FUN_802a36ec
// Entry: 802a36ec
// Size: 1048 bytes

undefined4 FUN_802a36ec(int param_1,uint *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  undefined2 uVar7;
  undefined4 uVar6;
  int iVar8;
  
  iVar8 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) & 0xfffffffd;
  *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) | 0x2000;
  param_2[1] = param_2[1] | 0x100000;
  fVar1 = FLOAT_803e7ea4;
  param_2[0xa0] = (uint)FLOAT_803e7ea4;
  param_2[0xa1] = (uint)fVar1;
  *param_2 = *param_2 | 0x200000;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  param_2[1] = param_2[1] | 0x8000000;
  *(float *)(param_1 + 0x28) = fVar1;
  *param_2 = *param_2 | 0x200000;
  fVar2 = FLOAT_803e8048;
  fVar5 = FLOAT_803e8044;
  fVar4 = FLOAT_803e8040;
  fVar1 = FLOAT_803e8018;
  fVar3 = FLOAT_803e7f30;
  switch(DAT_803dc6a0) {
  case 0xe:
  case 0x16:
    break;
  default:
    if (*(char *)(iVar8 + 0x606) == '\x10') {
      DAT_803dc6a0 = 0x1a;
      param_2[0xa8] = (uint)FLOAT_803e7f28;
      fVar1 = fVar4;
      fVar2 = fVar5;
    }
    else if (*(float *)(iVar8 + 0x5a8) < FLOAT_803e8040) {
      if (*(float *)(iVar8 + 0x5a8) < FLOAT_803e8048) {
        DAT_803dc6a0 = 0x12;
        param_2[0xa8] = (uint)FLOAT_803e804c;
      }
      else {
        DAT_803dc6a0 = 0x16;
        param_2[0xa8] = (uint)FLOAT_803e804c;
        fVar1 = fVar2;
        fVar2 = fVar4;
      }
    }
    else {
      DAT_803dc6a0 = 0xe;
      param_2[0xa8] = (uint)FLOAT_803e7f0c;
      fVar1 = fVar4;
      fVar2 = fVar3;
    }
    fVar1 = ((*(float *)(iVar8 + 0x5a8) - fVar1) / (fVar2 - fVar1)) * FLOAT_803e7fac;
    fVar2 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e7fac < fVar1)) {
      fVar2 = FLOAT_803e7fac;
    }
    *(short *)(iVar8 + 0x604) = (short)(int)fVar2;
    FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)*(short *)(&DAT_80332ef0 + DAT_803dc6a0 * 2),0)
    ;
    FUN_8002f574(param_1,10);
    uVar7 = FUN_800217c0((double)*(float *)(iVar8 + 0x5c4),(double)*(float *)(iVar8 + 0x5cc));
    *(undefined2 *)(iVar8 + 0x484) = uVar7;
    *(undefined2 *)(iVar8 + 0x478) = uVar7;
    FUN_8000e034((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),param_1 + 0xc,param_1 + 0x10,param_1 + 0x14,
                 *(undefined4 *)(param_1 + 0x30));
    FUN_80062e84(param_1,*(undefined4 *)(iVar8 + 0x4c4),1);
    *(undefined4 *)(iVar8 + 0x5b4) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar8 + 0x5b8) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar8 + 0x5bc) = *(undefined4 *)(param_1 + 0x14);
    if (*(int *)(iVar8 + 0x4c4) != 0) {
      FUN_8000e034((double)*(float *)(iVar8 + 0x5d4),(double)*(float *)(iVar8 + 0x5d8),
                   (double)*(float *)(iVar8 + 0x5dc),iVar8 + 0x5d4,iVar8 + 0x5d8,iVar8 + 0x5dc);
      FUN_8000e034((double)*(float *)(iVar8 + 0x5ec),(double)*(float *)(iVar8 + 0x5f0),
                   (double)*(float *)(iVar8 + 0x5f4),iVar8 + 0x5ec,iVar8 + 0x5f0,iVar8 + 0x5f4,
                   *(undefined4 *)(iVar8 + 0x4c4));
      FUN_8000e034((double)*(float *)(iVar8 + 0x5f8),(double)*(float *)(iVar8 + 0x5fc),
                   (double)*(float *)(iVar8 + 0x600),iVar8 + 0x5f8,iVar8 + 0x5fc,iVar8 + 0x600,
                   *(undefined4 *)(iVar8 + 0x4c4));
      *(float *)(iVar8 + 0x5ac) =
           *(float *)(iVar8 + 0x5ac) - *(float *)(*(int *)(iVar8 + 0x4c4) + 0x10);
      *(float *)(iVar8 + 0x5b0) =
           *(float *)(iVar8 + 0x5b0) - *(float *)(*(int *)(iVar8 + 0x4c4) + 0x10);
      *(undefined *)(iVar8 + 0x609) = 0;
    }
    goto LAB_802a3a68;
  case 0x12:
  case 0x1a:
    if ((param_2[0xc5] & 1) != 0) {
      if (*(short *)(iVar8 + 0x81a) == 0) {
        uVar6 = 0x398;
      }
      else {
        uVar6 = 0x1d;
      }
      FUN_8000bb18(param_1,uVar6);
    }
    if ((((*(byte *)(iVar8 + 0x3f0) >> 5 & 1) != 0) || (DAT_803dc6a0 == 0x1a)) &&
       ((param_2[0xc5] & 0x80) != 0)) {
      FUN_8000bb18(param_1,0x2f);
    }
  }
  if (*(char *)((int)param_2 + 0x346) == '\0') {
LAB_802a3a68:
    *(float *)(param_1 + 0xc) =
         *(float *)(param_1 + 0x98) * (*(float *)(iVar8 + 0x5ec) - *(float *)(iVar8 + 0x5b4)) +
         *(float *)(iVar8 + 0x5b4);
    *(float *)(param_1 + 0x10) =
         *(float *)(param_1 + 0x98) * (*(float *)(iVar8 + 0x5f0) - *(float *)(iVar8 + 0x5b8)) +
         *(float *)(iVar8 + 0x5b8);
    *(float *)(param_1 + 0x14) =
         *(float *)(param_1 + 0x98) * (*(float *)(iVar8 + 0x5f4) - *(float *)(iVar8 + 0x5bc)) +
         *(float *)(iVar8 + 0x5bc);
    FUN_8002ed6c(param_1,(int)*(short *)(&DAT_80332ef4 + DAT_803dc6a0 * 2),
                 (int)*(short *)(iVar8 + 0x604));
    FUN_802ab5a4(param_1,iVar8,5);
    uVar6 = 0;
  }
  else {
    param_2[1] = param_2[1] & 0xffefffff;
    FUN_802ab5a4(param_1,iVar8,5);
    *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) | 0x800000;
    param_2[0xc2] = (uint)FUN_802a514c;
    uVar6 = 2;
  }
  return uVar6;
}

