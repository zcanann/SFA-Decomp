// Function: FUN_80168d0c
// Entry: 80168d0c
// Size: 940 bytes

void FUN_80168d0c(int param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  if (*(int *)(param_1 + 0xf4) == 0) {
    iVar5 = (**(code **)(*DAT_803dcab8 + 0x30))(param_1,iVar6,0);
    if (iVar5 == 0) {
      *(undefined2 *)(iVar6 + 0x402) = 0;
    }
    else {
      FUN_8016874c(param_1,iVar6,iVar6);
      if (*(short *)(iVar6 + 0x402) == 0) {
        iVar5 = *(int *)(iVar6 + 0x40c);
        *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x34) - FLOAT_803db414;
        if (*(float *)(iVar5 + 0x34) <= FLOAT_803e3060) {
          FUN_8000bb18(param_1,0x271);
          uVar2 = FUN_800221a0(300,600);
          *(float *)(iVar5 + 0x34) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3070);
        }
        uVar3 = FUN_8002b9ec();
        *(undefined4 *)(iVar6 + 0x2d0) = uVar3;
        if (*(short *)(iVar6 + 0x274) != 6) {
          (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,param_1,iVar6,5);
        }
        iVar5 = (**(code **)(*DAT_803dcab8 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar6 + 0x3fe)) -
                                          DOUBLE_803e3068),param_1,iVar6,0x8000);
        if (iVar5 != 0) {
          (**(code **)(*DAT_803dcab8 + 0x28))
                    (param_1,iVar6,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,0,4,0xffffffff);
          *(undefined *)(iVar6 + 0x349) = 0;
          *(undefined2 *)(iVar6 + 0x402) = 1;
        }
      }
      else {
        iVar5 = *(int *)(iVar6 + 0x40c);
        piVar4 = (int *)FUN_800394ac(param_1,0,0);
        *(short *)(iVar5 + 0x48) = *(short *)(iVar5 + 0x48) + 0x1000;
        dVar7 = (double)FUN_80293e80((double)((FLOAT_803e30b4 *
                                              (float)((double)CONCAT44(0x43300000,
                                                                       (int)*(short *)(iVar5 + 0x48)
                                                                       ^ 0x80000000) -
                                                     DOUBLE_803e3070)) / FLOAT_803e30b8));
        *piVar4 = (int)(FLOAT_803e30b0 * (float)((double)FLOAT_803e3078 + dVar7));
        uVar3 = FUN_8002b9ec();
        *(undefined4 *)(iVar6 + 0x2d0) = uVar3;
        FUN_8016855c(param_1,iVar6,iVar6);
        (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e3060,param_1,iVar6,0xffffffff);
        if (*(short *)(iVar6 + 0x274) != 6) {
          (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,param_1,iVar6,5);
        }
        *(undefined4 *)(iVar6 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
        *(undefined4 *)(param_1 + 0xc0) = 0;
        (**(code **)(*DAT_803dca8c + 8))
                  ((double)FLOAT_803db414,(double)FLOAT_803db414,param_1,iVar6,&DAT_803ac698,
                   &DAT_803ac680);
        *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(iVar6 + 0x3e0);
      }
    }
  }
  else if ((*(short *)(iVar6 + 0x270) != 3) &&
          (iVar1 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar5 + 0x14)), iVar1 != 0))
  {
    (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e30c8,param_1,iVar5,iVar6,8,6,0,0x26);
    *(undefined2 *)(iVar6 + 0x402) = 0;
    FUN_8000bb18(param_1,0x270);
    FUN_80030334((double)FLOAT_803e3060,param_1,4,0x10);
    *(undefined *)(iVar6 + 0x346) = 0;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

