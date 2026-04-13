// Function: FUN_801975e4
// Entry: 801975e4
// Size: 284 bytes

void FUN_801975e4(undefined2 *param_1,int param_2)

{
  float fVar1;
  undefined uVar2;
  uint uVar3;
  int iVar4;
  undefined local_18 [12];
  
  local_18[0] = 5;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  fVar1 = FLOAT_803e4ccc;
  iVar4 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar4 + 0x26c) = FLOAT_803e4ccc;
  *(float *)(iVar4 + 0x270) = fVar1;
  *(float *)(iVar4 + 0x274) = fVar1;
  FUN_80196a9c(param_1,iVar4,param_2);
  uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x3e));
  if (uVar3 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = 2;
  }
  *(undefined *)(iVar4 + 0x29e) = uVar2;
  DAT_803de780 = 0;
  if ((*(byte *)(param_2 + 0x3c) & 2) != 0) {
    (**(code **)(*DAT_803dd728 + 4))(iVar4,0,0x40002,1);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar4,1,&DAT_80322fb8,&DAT_803dca60,local_18);
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar4);
  }
  return;
}

