// Function: FUN_8015b2a0
// Entry: 8015b2a0
// Size: 644 bytes

undefined4 FUN_8015b2a0(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(param_2 + 0x346) == '\0') ||
     (uVar3 = (**(code **)(*DAT_803dcab8 + 0x18))((double)FLOAT_803e2d00), (uVar3 & 1) != 0)) {
    if (*(char *)(param_2 + 0x27b) == '\0') {
      sVar1 = *(short *)(iVar5 + 0x402);
      if (sVar1 == 3) {
        (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,4);
      }
      else if (sVar1 == 4) {
        if ((*(float *)(param_2 + 0x2c0) < FLOAT_803e2d10) && (*(char *)(param_2 + 0x346) != '\0'))
        {
          if (*(byte *)(iVar5 + 0x406) < 0x33) {
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
          }
          else {
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
          }
        }
      }
      else if (sVar1 == 1) {
        return 8;
      }
    }
    else {
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0xb);
    }
    fVar2 = FLOAT_803e2d14;
    *(float *)(param_2 + 0x290) = FLOAT_803e2d14;
    *(float *)(param_2 + 0x28c) = fVar2;
    FUN_80003494(iVar5 + 0x35c,param_1 + 0xc,0xc);
    FUN_80003494(iVar5 + 0x368,*(int *)(param_2 + 0x2d0) + 0xc,0xc);
    FUN_80012294(iVar5 + 0x35c,iVar5 + 900);
    if (*(char *)(iVar5 + 0x381) == '\0') {
      (**(code **)(*DAT_803dca8c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)FLOAT_803e2d14,(double)FLOAT_803e2d14,(double)FLOAT_803e2d18,param_1,
                 param_2);
    }
    else {
      (**(code **)(*DAT_803dca8c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)FLOAT_803e2d1c,(double)FLOAT_803e2d20,(double)FLOAT_803e2d18,param_1,
                 param_2);
    }
    if ((0x78 < *(short *)(param_2 + 0x32e)) &&
       (iVar5 = (**(code **)(*DAT_803dcab8 + 0x44))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar5 + 0x3fe)) -
                                          DOUBLE_803e2d08),param_1,param_2,1), iVar5 != 0)) {
      return 5;
    }
    uVar4 = 0;
  }
  else {
    uVar4 = 5;
  }
  return uVar4;
}

