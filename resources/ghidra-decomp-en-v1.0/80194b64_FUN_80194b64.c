// Function: FUN_80194b64
// Entry: 80194b64
// Size: 172 bytes

void FUN_80194b64(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  fVar1 = FLOAT_803e4000;
  iVar4 = *(int *)(param_1 + 0xb8);
  uVar3 = *(undefined4 *)(param_1 + 0x4c);
  *(float *)(iVar4 + 0x40) = FLOAT_803e4000;
  *(float *)(iVar4 + 0x44) = fVar1;
  *(float *)(iVar4 + 0x48) = fVar1;
  if (param_2 == 0) {
    FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14));
    iVar2 = FUN_8005aeec();
    if ((iVar2 != 0) && (*(int *)(iVar4 + 4) != 0)) {
      FUN_80194c40(uVar3,iVar4);
    }
  }
  if (*(int *)(iVar4 + 0xc) != 0) {
    FUN_80023800();
  }
  FUN_80036fa4(param_1,0x51);
  return;
}

