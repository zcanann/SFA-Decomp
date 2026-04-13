// Function: FUN_801950e0
// Entry: 801950e0
// Size: 172 bytes

void FUN_801950e0(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int iVar5;
  
  fVar1 = FLOAT_803e4c98;
  iVar5 = *(int *)(param_1 + 0xb8);
  uVar4 = *(undefined4 *)(param_1 + 0x4c);
  *(float *)(iVar5 + 0x40) = FLOAT_803e4c98;
  *(float *)(iVar5 + 0x44) = fVar1;
  *(float *)(iVar5 + 0x48) = fVar1;
  if (param_2 == 0) {
    iVar2 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
    puVar3 = (undefined4 *)FUN_8005b068(iVar2);
    if ((puVar3 != (undefined4 *)0x0) && (*(int *)(iVar5 + 4) != 0)) {
      FUN_801951bc(uVar4,iVar5,puVar3);
    }
  }
  if (*(uint *)(iVar5 + 0xc) != 0) {
    FUN_800238c4(*(uint *)(iVar5 + 0xc));
  }
  FUN_8003709c(param_1,0x51);
  return;
}

