// Function: FUN_8015b3bc
// Entry: 8015b3bc
// Size: 912 bytes

/* WARNING: Removing unreachable block (ram,0x8015b6f8) */

undefined4 FUN_8015b3bc(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 local_18;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) == '\0') {
      if ((*(short *)(param_2 + 0x274) == 7) && ((int)*(float *)(param_2 + 0x2c0) < 0x37)) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
      }
    }
    else {
      uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e3998);
      if ((uVar2 & 1) == 0) {
        return 5;
      }
      local_18 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x3fe));
      iVar4 = (**(code **)(*DAT_803dd738 + 0x44))
                        ((double)(float)(local_18 - DOUBLE_803e39a0),param_1,param_2,1);
      if (iVar4 != 0) {
        return 5;
      }
      if ((int)*(float *)(param_2 + 0x2c0) < 0x38) {
        if (*(short *)(param_2 + 0x274) == 6) {
          (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,5);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
        }
      }
      else if ((*(byte *)(iVar3 + 0x404) & 2) == 0) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,7);
      }
      else {
        iVar4 = *(int *)(iVar3 + 0x40c);
        if ((*(byte *)(iVar3 + 0x404) & 0x10) == 0) {
          sVar1 = *(short *)(iVar4 + 4);
          *(short *)(iVar4 + 4) = sVar1 + 1;
          (**(code **)(*DAT_803dd70c + 0x14))
                    (param_1,param_2,(int)*(short *)(&DAT_803209d0 + sVar1 * 2));
        }
        else {
          sVar1 = *(short *)(iVar4 + 4);
          *(short *)(iVar4 + 4) = sVar1 + 1;
          (**(code **)(*DAT_803dd70c + 0x14))
                    (param_1,param_2,(int)*(short *)(&DAT_803209e0 + sVar1 * 2));
        }
        if (6 < *(short *)(iVar4 + 4)) {
          *(undefined2 *)(iVar4 + 4) = 0;
        }
      }
    }
  }
  else if ((int)*(float *)(param_2 + 0x2c0) < 0x38) {
    if (*(short *)(param_2 + 0x274) == 6) {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,5);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
    }
  }
  else if ((*(byte *)(iVar3 + 0x404) & 2) == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,7);
  }
  else {
    iVar4 = *(int *)(iVar3 + 0x40c);
    if ((*(byte *)(iVar3 + 0x404) & 0x10) == 0) {
      sVar1 = *(short *)(iVar4 + 4);
      *(short *)(iVar4 + 4) = sVar1 + 1;
      (**(code **)(*DAT_803dd70c + 0x14))
                (param_1,param_2,(int)*(short *)(&DAT_803209d0 + sVar1 * 2));
    }
    else {
      sVar1 = *(short *)(iVar4 + 4);
      *(short *)(iVar4 + 4) = sVar1 + 1;
      (**(code **)(*DAT_803dd70c + 0x14))
                (param_1,param_2,(int)*(short *)(&DAT_803209e0 + sVar1 * 2));
    }
    if (6 < *(short *)(iVar4 + 4)) {
      *(undefined2 *)(iVar4 + 4) = 0;
    }
  }
  return 0;
}

