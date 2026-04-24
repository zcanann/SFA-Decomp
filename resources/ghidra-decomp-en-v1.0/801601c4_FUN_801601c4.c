// Function: FUN_801601c4
// Entry: 801601c4
// Size: 360 bytes

undefined4 FUN_801601c4(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_2 + 0x2d0) == 0) {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
    fVar1 = FLOAT_803e2e68;
    *(float *)(param_2 + 0x290) = FLOAT_803e2e68;
    *(float *)(param_2 + 0x28c) = fVar1;
    FUN_80003494(iVar2 + 0x35c,param_1 + 0xc,0xc);
    FUN_80003494(iVar2 + 0x368,*(int *)(param_2 + 0x2d0) + 0xc,0xc);
    FUN_80012294(iVar2 + 0x35c,iVar2 + 900);
    if ((*(float *)(param_2 + 0x2c0) < FLOAT_803e2e6c) && (*(char *)(iVar2 + 0x405) == '\x02')) {
      return 5;
    }
    if (*(char *)(iVar2 + 0x381) == '\0') {
      (**(code **)(*DAT_803dca8c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)FLOAT_803e2e68,(double)FLOAT_803e2e68,(double)FLOAT_803e2e70,param_1,
                 param_2);
    }
    else {
      (**(code **)(*DAT_803dca8c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)FLOAT_803e2e74,(double)FLOAT_803e2e78,(double)FLOAT_803e2e70,param_1,
                 param_2);
    }
  }
  return 0;
}

