// Function: FUN_802a3b04
// Entry: 802a3b04
// Size: 1056 bytes

undefined4 FUN_802a3b04(int param_1,uint *param_2)

{
  short sVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined2 local_18;
  undefined local_16;
  undefined local_15;
  
  iVar8 = *(int *)(param_1 + 0xb8);
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    if (*(short *)(iVar8 + 0x81a) == 0) {
      uVar4 = 0x2cb;
    }
    else {
      uVar4 = 0x29;
    }
    FUN_8000bb18(param_1,uVar4);
    *(undefined2 *)(param_2 + 0x9e) = 10;
    *(undefined4 *)(iVar8 + 0x898) = 0;
    *(undefined *)(iVar8 + 0x800) = 0;
    if (*(int *)(iVar8 + 0x7f8) != 0) {
      sVar1 = *(short *)(*(int *)(iVar8 + 0x7f8) + 0x46);
      if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
        FUN_80182504();
      }
      else {
        FUN_800ea774();
      }
      *(ushort *)(*(int *)(iVar8 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar8 + 0x7f8) + 6) & 0xbfff;
      *(undefined4 *)(*(int *)(iVar8 + 0x7f8) + 0xf8) = 0;
      *(undefined4 *)(iVar8 + 0x7f8) = 0;
    }
  }
  fVar2 = FLOAT_803e7ea4;
  *(float *)(iVar8 + 0x778) = FLOAT_803e7ea4;
  iVar6 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) & 0xfffffffd;
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x2000;
  param_2[1] = param_2[1] | 0x100000;
  param_2[0xa0] = (uint)fVar2;
  param_2[0xa1] = (uint)fVar2;
  *param_2 = *param_2 | 0x200000;
  *(float *)(param_1 + 0x24) = fVar2;
  *(float *)(param_1 + 0x2c) = fVar2;
  param_2[1] = param_2[1] | 0x8000000;
  *(float *)(param_1 + 0x28) = fVar2;
  sVar1 = *(short *)(param_1 + 0xa0);
  if ((sVar1 == 0x22) || ((sVar1 < 0x22 && (sVar1 == 0xd)))) {
    fVar2 = *(float *)(param_1 + 0x98) / FLOAT_803e7f44;
    fVar3 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar2) && (fVar3 = fVar2, FLOAT_803e7ee0 < fVar2)) {
      fVar3 = FLOAT_803e7ee0;
    }
    *(float *)(param_1 + 0xc) =
         fVar3 * (*(float *)(iVar8 + 0x5f8) - *(float *)(iVar8 + 0x5b4)) + *(float *)(iVar8 + 0x5b4)
    ;
    *(float *)(param_1 + 0x10) =
         -(*(float *)(param_1 + 0x98) *
           (*(float *)(iVar8 + 0x5b8) - (*(float *)(iVar8 + 0x5ac) - *(float *)(iVar8 + 0x874))) -
          *(float *)(iVar8 + 0x5b8));
    *(float *)(param_1 + 0x14) =
         fVar3 * (*(float *)(iVar8 + 0x600) - *(float *)(iVar8 + 0x5bc)) + *(float *)(iVar8 + 0x5bc)
    ;
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)DAT_80332efc,0);
      param_2[0xa8] = (uint)FLOAT_803e8038;
      DAT_803dc6a0 = 6;
      FUN_802ab5a4(param_1,iVar8 + 4,5);
      param_2[0xc2] = 0;
      return 0xd;
    }
  }
  else {
    uVar5 = FUN_800217c0((double)*(float *)(iVar8 + 0x5c4),(double)*(float *)(iVar8 + 0x5cc));
    iVar6 = (uVar5 & 0xffff) - (int)*(short *)(iVar8 + 0x478);
    if (0x8000 < iVar6) {
      iVar6 = iVar6 + -0xffff;
    }
    if (iVar6 < -0x8000) {
      iVar6 = iVar6 + 0xffff;
    }
    if (*(char *)(iVar8 + 0x607) == '\x01') {
      iVar7 = 0xb;
    }
    else {
      iVar7 = 10;
    }
    *(short *)(iVar8 + 0x478) = *(short *)(iVar8 + 0x478) + (short)iVar6;
    *(undefined2 *)(iVar8 + 0x484) = *(undefined2 *)(iVar8 + 0x478);
    FUN_8000e034((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),param_1 + 0xc,param_1 + 0x10,param_1 + 0x14,
                 *(undefined4 *)(param_1 + 0x30));
    FUN_80062e84(param_1,*(undefined4 *)(iVar8 + 0x4c4),1);
    *(undefined4 *)(iVar8 + 0x5b4) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar8 + 0x5b8) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar8 + 0x5bc) = *(undefined4 *)(param_1 + 0x14);
    FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)*(short *)(&DAT_80332ef0 + iVar7 * 2),4);
    param_2[0xa8] = (uint)FLOAT_803e7f34;
    if ((*(char *)(iVar8 + 0x8c8) != 'H') && (*(char *)(iVar8 + 0x8c8) != 'G')) {
      local_18 = 0;
      local_16 = 0;
      local_15 = 1;
      (**(code **)(*DAT_803dca50 + 0x1c))(0x43,1,0,4,&local_18,0,0xff);
    }
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
  }
  *(byte *)(iVar8 + 0x8c9) = *(byte *)(iVar8 + 0x8c9) | 4;
  FUN_802ab5a4(param_1,iVar8 + 4,5);
  return 0;
}

