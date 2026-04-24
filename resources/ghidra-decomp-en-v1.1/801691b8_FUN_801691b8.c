// Function: FUN_801691b8
// Entry: 801691b8
// Size: 940 bytes

void FUN_801691b8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 in_r7;
  undefined4 uVar5;
  int in_r8;
  undefined4 uVar6;
  int in_r9;
  undefined4 uVar7;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  double dVar10;
  double dVar11;
  
  iVar9 = *(int *)(param_9 + 0xb8);
  iVar8 = *(int *)(param_9 + 0x4c);
  if (*(int *)(param_9 + 0xf4) == 0) {
    iVar1 = *DAT_803dd738;
    iVar8 = (**(code **)(iVar1 + 0x30))(param_9,iVar9,0);
    if (iVar8 == 0) {
      *(undefined2 *)(iVar9 + 0x402) = 0;
    }
    else {
      FUN_80168bf8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar9
                   ,iVar9);
      if (*(short *)(iVar9 + 0x402) == 0) {
        iVar8 = *(int *)(iVar9 + 0x40c);
        *(float *)(iVar8 + 0x34) = *(float *)(iVar8 + 0x34) - FLOAT_803dc074;
        if (*(float *)(iVar8 + 0x34) <= FLOAT_803e3cf8) {
          FUN_8000bb38(param_9,0x271);
          uVar2 = FUN_80022264(300,600);
          *(float *)(iVar8 + 0x34) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3d08);
        }
        uVar4 = FUN_8002bac4();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar4;
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_9,iVar9,5);
        }
        iVar8 = (**(code **)(*DAT_803dd738 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar9 + 0x3fe)) -
                                          DOUBLE_803e3d00),param_9,iVar9,0x8000);
        if (iVar8 != 0) {
          (**(code **)(*DAT_803dd738 + 0x28))
                    (param_9,iVar9,iVar9 + 0x35c,(int)*(short *)(iVar9 + 0x3f4),0,0,0,4,0xffffffff);
          *(undefined *)(iVar9 + 0x349) = 0;
          *(undefined2 *)(iVar9 + 0x402) = 1;
        }
      }
      else {
        iVar8 = *(int *)(iVar9 + 0x40c);
        piVar3 = (int *)FUN_800395a4(param_9,0);
        *(short *)(iVar8 + 0x48) = *(short *)(iVar8 + 0x48) + 0x1000;
        dVar11 = (double)FLOAT_803e3d4c;
        dVar10 = (double)FUN_802945e0();
        dVar10 = (double)(float)((double)FLOAT_803e3d10 + dVar10);
        *piVar3 = (int)((double)FLOAT_803e3d48 * dVar10);
        uVar4 = FUN_8002bac4();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar4;
        FUN_80168a08(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar9,
                     iVar9,iVar1,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3cf8,param_9,iVar9,0xffffffff);
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_9,iVar9,5);
        }
        *(undefined4 *)(iVar9 + 0x3e0) = *(undefined4 *)(param_9 + 0xc0);
        *(undefined4 *)(param_9 + 0xc0) = 0;
        (**(code **)(*DAT_803dd70c + 8))
                  ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_9,iVar9,&DAT_803ad2f8,
                   &DAT_803ad2e0);
        *(undefined4 *)(param_9 + 0xc0) = *(undefined4 *)(iVar9 + 0x3e0);
      }
    }
  }
  else if ((*(short *)(iVar9 + 0x270) != 3) &&
          (iVar1 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar8 + 0x14)), iVar1 != 0))
  {
    uVar4 = 8;
    uVar5 = 6;
    uVar6 = 0;
    uVar7 = 0x26;
    iVar1 = *DAT_803dd738;
    (**(code **)(iVar1 + 0x58))((double)FLOAT_803e3d60,param_9,iVar8,iVar9);
    *(undefined2 *)(iVar9 + 0x402) = 0;
    FUN_8000bb38(param_9,0x270);
    FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0x10,uVar4,uVar5,uVar6,uVar7,iVar1);
    *(undefined *)(iVar9 + 0x346) = 0;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return;
}

