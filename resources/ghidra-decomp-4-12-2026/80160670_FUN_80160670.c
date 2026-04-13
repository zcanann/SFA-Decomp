// Function: FUN_80160670
// Entry: 80160670
// Size: 360 bytes

undefined4
FUN_80160670(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)

{
  float fVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(int *)(param_10 + 0x2d0) == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
    fVar1 = FLOAT_803e3b00;
    *(float *)(param_10 + 0x290) = FLOAT_803e3b00;
    *(float *)(param_10 + 0x28c) = fVar1;
    FUN_80003494(iVar2 + 0x35c,param_9 + 0xc,0xc);
    uVar3 = FUN_80003494(iVar2 + 0x368,*(int *)(param_10 + 0x2d0) + 0xc,0xc);
    FUN_800122b4(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if ((*(float *)(param_10 + 0x2c0) < FLOAT_803e3b04) && (*(char *)(iVar2 + 0x405) == '\x02')) {
      return 5;
    }
    if (*(char *)(iVar2 + 0x381) == '\0') {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)FLOAT_803e3b00,(double)FLOAT_803e3b00,(double)FLOAT_803e3b08,param_9,
                 param_10);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)FLOAT_803e3b0c,(double)FLOAT_803e3b10,(double)FLOAT_803e3b08,param_9,
                 param_10);
    }
  }
  return 0;
}

