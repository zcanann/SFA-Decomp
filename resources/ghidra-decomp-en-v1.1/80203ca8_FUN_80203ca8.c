// Function: FUN_80203ca8
// Entry: 80203ca8
// Size: 1080 bytes

void FUN_80203ca8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 in_r7;
  undefined4 uVar5;
  undefined4 in_r8;
  undefined4 uVar6;
  undefined4 in_r9;
  undefined4 uVar7;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  double extraout_f1;
  double dVar13;
  undefined8 extraout_f1_00;
  undefined8 uVar14;
  uint local_48 [3];
  float local_3c;
  float local_38;
  float local_34;
  
  uVar2 = FUN_80286830();
  iVar12 = *(int *)(uVar2 + 0xb8);
  iVar11 = *(int *)(uVar2 + 0x4c);
  iVar10 = *(int *)(iVar12 + 0x40c);
  *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
  if ((*(byte *)(iVar10 + 0x44) >> 4 & 1) != 0) {
    sVar1 = *(short *)(iVar11 + 0x24);
    uVar3 = FUN_80013a08(0x14,0xc);
    *(undefined4 *)(iVar10 + 0x24) = uVar3;
    iVar8 = (int)*(short *)(&DAT_8032a158 + sVar1 * 8);
    iVar9 = iVar8 * 0xc;
    for (; iVar8 != 0; iVar8 = iVar8 + -1) {
      iVar9 = iVar9 + -0xc;
      FUN_80013978(*(short **)(iVar10 + 0x24),(uint)((&PTR_DAT_8032a154)[sVar1 * 2] + iVar9));
    }
    *(undefined *)(iVar10 + 0x34) = 1;
    *(byte *)(iVar10 + 0x44) = *(byte *)(iVar10 + 0x44) & 0xef;
  }
  uVar4 = FUN_80020078((int)*(short *)(iVar12 + 0x3f6));
  if (uVar4 != 0) {
    if (*(int *)(uVar2 + 0xf4) == 0) {
      if (*(int *)(uVar2 + 0xf8) == 0) {
        *(undefined4 *)(uVar2 + 0xc) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(uVar2 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
        *(undefined4 *)(uVar2 + 0x14) = *(undefined4 *)(iVar11 + 0x10);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar11 + 0x2e),uVar2,0xffffffff);
        *(undefined4 *)(uVar2 + 0xf8) = 1;
      }
      else {
        iVar10 = (**(code **)(*DAT_803dd738 + 0x30))(uVar2,iVar12,0);
        if (iVar10 == 0) {
          *(undefined2 *)(iVar12 + 0x402) = 0;
        }
        else {
          iVar10 = *(int *)(iVar12 + 0x2d0);
          dVar13 = extraout_f1;
          if (iVar10 != 0) {
            local_3c = *(float *)(iVar10 + 0x18) - *(float *)(uVar2 + 0x18);
            param_4 = (double)local_3c;
            local_38 = *(float *)(iVar10 + 0x1c) - *(float *)(uVar2 + 0x1c);
            param_3 = (double)local_38;
            local_34 = *(float *)(iVar10 + 0x20) - *(float *)(uVar2 + 0x20);
            param_2 = (double)(local_34 * local_34);
            dVar13 = FUN_80293900((double)(float)(param_2 +
                                                 (double)((float)(param_4 * param_4) +
                                                         (float)(param_3 * param_3))));
            *(float *)(iVar12 + 0x2c0) = (float)dVar13;
          }
          local_48[0] = 0;
          local_48[1] = 0;
          iVar10 = *(int *)(*(int *)(uVar2 + 0xb8) + 0x40c);
          while (iVar11 = FUN_800375e4(uVar2,local_48,local_48 + 2,local_48 + 1), iVar11 != 0) {
            if ((local_48[0] == 0x11) && (*(short *)(iVar10 + 0x1c) != -1)) {
              uVar3 = 0x14;
              FUN_800379bc(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(iVar10 + 0x18),0x11,uVar2,0x14,in_r7,in_r8,in_r9,in_r10);
              *(undefined4 *)(iVar10 + 0x18) = 0;
              *(undefined2 *)(iVar10 + 0x1c) = 0xffff;
              dVar13 = (double)FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,
                                            param_6,param_7,param_8,uVar2,0xf,0,uVar3,in_r7,in_r8,
                                            in_r9,in_r10);
            }
          }
          iVar10 = (**(code **)(*DAT_803dd738 + 0x50))
                             (uVar2,iVar12,iVar12 + 0x35c,(int)*(short *)(iVar12 + 0x3f4),
                              &DAT_8032a2a4,&DAT_8032a31c,1,&DAT_803add20);
          uVar14 = extraout_f1_00;
          if (iVar10 != 0) {
            DAT_803add2c = *(undefined4 *)(uVar2 + 0xc);
            DAT_803add30 = *(undefined4 *)(uVar2 + 0x10);
            DAT_803add34 = *(undefined4 *)(uVar2 + 0x14);
            uVar14 = FUN_8009a468(uVar2,&DAT_803add20,1,(int *)0x0);
          }
          if (*(short *)(iVar12 + 0x402) == 0) {
            FUN_8020377c(uVar2,iVar12,iVar12);
          }
          else {
            iVar10 = *(int *)(iVar12 + 0x40c);
            FUN_80203638(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,iVar12
                        );
            (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e7020,uVar2,iVar12,0xffffffff);
            if ((*(byte *)(iVar10 + 0x15) & 4) == 0) {
              (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,uVar2,iVar12,4);
            }
            *(undefined4 *)(iVar12 + 0x3e0) = *(undefined4 *)(uVar2 + 0xc0);
            *(undefined4 *)(uVar2 + 0xc0) = 0;
            (**(code **)(*DAT_803dd70c + 8))
                      ((double)FLOAT_803dc074,(double)FLOAT_803dc074,uVar2,iVar12,&DAT_803add54,
                       &DAT_803add38);
            *(undefined4 *)(uVar2 + 0xc0) = *(undefined4 *)(iVar12 + 0x3e0);
          }
        }
      }
    }
    else if (((*(byte *)(iVar12 + 0x404) & 4) == 0) &&
            (iVar10 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar11 + 0x14)),
            iVar10 != 0)) {
      uVar3 = 0x10;
      uVar5 = 7;
      uVar6 = 0x10a;
      uVar7 = 0x26;
      iVar10 = *DAT_803dd738;
      (**(code **)(iVar10 + 0x58))((double)FLOAT_803e6f94,uVar2,iVar11,iVar12);
      FUN_800372f8(uVar2,3);
      *(undefined2 *)(iVar12 + 0x402) = 0;
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar2,8,0x10,uVar3,uVar5,uVar6,uVar7,iVar10);
      *(undefined *)(iVar12 + 0x346) = 0;
      *(undefined *)(uVar2 + 0x36) = 0xff;
      *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    }
  }
  FUN_8028687c();
  return;
}

