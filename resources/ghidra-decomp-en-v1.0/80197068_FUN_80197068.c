// Function: FUN_80197068
// Entry: 80197068
// Size: 284 bytes

void FUN_80197068(int param_1,int param_2)

{
  float fVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  undefined local_18 [12];
  
  local_18[0] = 5;
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  fVar1 = FLOAT_803e4034;
  iVar4 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar4 + 0x26c) = FLOAT_803e4034;
  *(float *)(iVar4 + 0x270) = fVar1;
  *(float *)(iVar4 + 0x274) = fVar1;
  FUN_80196520(param_1,iVar4,param_2);
  iVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x3e));
  if (iVar3 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = 2;
  }
  *(undefined *)(iVar4 + 0x29e) = uVar2;
  DAT_803ddb00 = 0;
  if ((*(byte *)(param_2 + 0x3c) & 2) != 0) {
    (**(code **)(*DAT_803dcaa8 + 4))(iVar4,0,0x40002,1);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar4,1,&DAT_80322368,&DAT_803dbdf8,local_18);
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar4);
  }
  return;
}

