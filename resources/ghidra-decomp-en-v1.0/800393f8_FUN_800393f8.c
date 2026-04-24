// Function: FUN_800393f8
// Entry: 800393f8
// Size: 168 bytes

void FUN_800393f8(undefined4 param_1,undefined4 param_2,undefined4 param_3,short param_4,
                 uint param_5,uint param_6)

{
  undefined4 uVar1;
  int iVar2;
  undefined *puVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
  puVar3 = (undefined *)uVar4;
  if (((param_6 & 0xff) != 0) || (iVar2 = FUN_8000b578(uVar1,0x10), iVar2 == 0)) {
    FUN_8000bab0(uVar1,0x10,param_3);
    *(float *)(puVar3 + 0xc) =
         (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - DOUBLE_803de9d0);
    *(short *)(puVar3 + 0x14) = -param_4;
    *puVar3 = 1;
    *(float *)(puVar3 + 4) = FLOAT_803de99c;
  }
  FUN_80286128();
  return;
}

