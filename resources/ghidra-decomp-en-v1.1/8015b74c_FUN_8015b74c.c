// Function: FUN_8015b74c
// Entry: 8015b74c
// Size: 644 bytes

undefined4
FUN_8015b74c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  if ((*(char *)(param_10 + 0x346) == '\0') ||
     (uVar3 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e3998), (uVar3 & 1) != 0)) {
    if (*(char *)(param_10 + 0x27b) == '\0') {
      sVar1 = *(short *)(iVar5 + 0x402);
      if (sVar1 == 3) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,4);
      }
      else if (sVar1 == 4) {
        if ((*(float *)(param_10 + 0x2c0) < FLOAT_803e39a8) && (*(char *)(param_10 + 0x346) != '\0')
           ) {
          if (*(byte *)(iVar5 + 0x406) < 0x33) {
            (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
          }
          else {
            (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0);
          }
        }
      }
      else if (sVar1 == 1) {
        return 8;
      }
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0xb);
    }
    fVar2 = FLOAT_803e39ac;
    *(float *)(param_10 + 0x290) = FLOAT_803e39ac;
    *(float *)(param_10 + 0x28c) = fVar2;
    FUN_80003494(iVar5 + 0x35c,param_9 + 0xc,0xc);
    uVar6 = FUN_80003494(iVar5 + 0x368,*(int *)(param_10 + 0x2d0) + 0xc,0xc);
    FUN_800122b4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (*(char *)(iVar5 + 0x381) == '\0') {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)FLOAT_803e39ac,(double)FLOAT_803e39ac,(double)FLOAT_803e39b0,param_9,
                 param_10);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)FLOAT_803e39b4,(double)FLOAT_803e39b8,(double)FLOAT_803e39b0,param_9,
                 param_10);
    }
    if ((0x78 < *(short *)(param_10 + 0x32e)) &&
       (iVar5 = (**(code **)(*DAT_803dd738 + 0x44))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar5 + 0x3fe)) -
                                          DOUBLE_803e39a0),param_9,param_10,1), iVar5 != 0)) {
      return 5;
    }
    uVar4 = 0;
  }
  else {
    uVar4 = 5;
  }
  return uVar4;
}

