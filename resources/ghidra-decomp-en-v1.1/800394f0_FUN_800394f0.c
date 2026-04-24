// Function: FUN_800394f0
// Entry: 800394f0
// Size: 168 bytes

void FUN_800394f0(undefined4 param_1,undefined4 param_2,ushort param_3,short param_4,uint param_5,
                 uint param_6)

{
  uint uVar1;
  bool bVar2;
  undefined *puVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  puVar3 = (undefined *)uVar4;
  if (((param_6 & 0xff) != 0) || (bVar2 = FUN_8000b598(uVar1,0x10), !bVar2)) {
    FUN_8000bad0(uVar1,0x10,param_3);
    *(float *)(puVar3 + 0xc) =
         (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - DOUBLE_803df650);
    *(short *)(puVar3 + 0x14) = -param_4;
    *puVar3 = 1;
    *(float *)(puVar3 + 4) = FLOAT_803df61c;
  }
  FUN_8028688c();
  return;
}

