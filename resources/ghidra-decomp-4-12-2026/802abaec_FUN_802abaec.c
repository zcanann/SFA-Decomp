// Function: FUN_802abaec
// Entry: 802abaec
// Size: 536 bytes

void FUN_802abaec(uint param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  if (param_3 == 0x5bd) {
    param_3 = -1;
    iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
    iVar1 = *(short *)(iVar2 + 4) + -0x14;
    if (iVar1 < 0) {
      iVar1 = 0;
    }
    else if (*(short *)(iVar2 + 6) < iVar1) {
      iVar1 = (int)*(short *)(iVar2 + 6);
    }
    *(short *)(iVar2 + 4) = (short)iVar1;
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x40))();
    if ((iVar1 != 0) && ((*(short *)(iVar1 + 0x46) == 0x414 || (*(short *)(iVar1 + 0x46) == 0x4a9)))
       ) {
      param_3 = 0x5bd;
      FUN_80021884();
    }
    goto LAB_802abce0;
  }
  if (param_3 < 0x5bd) {
    if (param_3 == 0x40) {
      *(float *)(param_2 + 0x854) = FLOAT_803e8b74;
      iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
      iVar1 = *(short *)(iVar2 + 4) + -10;
      if (iVar1 < 0) {
        iVar1 = 0;
      }
      else if (*(short *)(iVar2 + 6) < iVar1) {
        iVar1 = (int)*(short *)(iVar2 + 6);
      }
      *(short *)(iVar2 + 4) = (short)iVar1;
      FUN_802965f0();
      FUN_8000bb38(param_1,0x209);
      goto LAB_802abce0;
    }
    if (param_3 < 0x40) {
      if (param_3 == 0x2d) {
        DAT_803df132 = 0x2d;
      }
      goto LAB_802abce0;
    }
    if (param_3 != 0x107) goto LAB_802abce0;
  }
  else {
    if (param_3 == 0x958) {
      DAT_803df132 = 0x958;
      goto LAB_802abce0;
    }
    if (param_3 < 0x958) {
      if (param_3 == 0x5ce) {
        DAT_803df132 = 0x5ce;
      }
      else if ((0x5cd < param_3) && (0x956 < param_3)) {
        DAT_803df0b4 = *(undefined4 *)(param_2 + 0x4b8);
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0x32);
        *(code **)(param_2 + 0x304) = FUN_80299c04;
      }
      goto LAB_802abce0;
    }
    if (param_3 != 0xc55) goto LAB_802abce0;
  }
  (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0x36);
  *(code **)(param_2 + 0x304) = FUN_80298d0c;
LAB_802abce0:
  *(short *)(param_2 + 0x80a) = (short)param_3;
  return;
}

