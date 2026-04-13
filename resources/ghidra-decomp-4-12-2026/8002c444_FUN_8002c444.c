// Function: FUN_8002c444
// Entry: 8002c444
// Size: 228 bytes

void FUN_8002c444(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  int iVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar7 >> 0x20);
  uVar6 = extraout_f1;
  iVar1 = FUN_8004908c(0x38);
  if (iVar4 <= iVar1 + -4 >> 2) {
    puVar2 = (uint *)FUN_80023d8c(0x10,0x1a);
    uVar6 = FUN_800490c4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x38,puVar2,
                         iVar4 << 2,8,in_r7,in_r8,in_r9,in_r10);
    uVar3 = *puVar2;
    uVar5 = puVar2[1] - uVar3;
    if (0 < (int)uVar5) {
      iVar4 = FUN_80023d8c(uVar5,5);
      FUN_800490c4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x37,iVar4,uVar3,
                   uVar5,in_r7,in_r8,in_r9,in_r10);
    }
    FUN_800238c4((uint)puVar2);
    *(undefined2 *)uVar7 = (short)(uVar5 / 0x14);
  }
  FUN_8028688c();
  return;
}

