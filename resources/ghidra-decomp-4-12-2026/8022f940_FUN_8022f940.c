// Function: FUN_8022f940
// Entry: 8022f940
// Size: 132 bytes

void FUN_8022f940(int param_1)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  uint *puVar4;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  piVar1 = (int *)FUN_8002b660(param_1);
  piVar2 = (int *)FUN_800395a4(param_1,0);
  iVar3 = FUN_800284ac(*piVar1,0);
  FUN_80054320(iVar3,(short)puVar4[1]);
  FUN_800540a8(iVar3,puVar4,piVar2);
  return;
}

