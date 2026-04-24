// Function: FUN_801ef188
// Entry: 801ef188
// Size: 468 bytes

void FUN_801ef188(uint param_1,int param_2)

{
  int iVar1;
  byte bVar3;
  uint uVar2;
  int local_38;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 auStack_20 [5];
  
  iVar1 = FUN_80036868(param_1,&local_38,(int *)0x0,(uint *)0x0,&uStack_28,&uStack_24,auStack_20);
  if (((iVar1 != 0) && (bVar3 = FUN_8002acfc(param_1), bVar3 == 0)) &&
     (*(short *)(local_38 + 0x46) != 0x119)) {
    FUN_8002ad08(param_1,0xaf,200,0,0,1);
    FUN_80014acc((double)FLOAT_803e6950);
    FUN_8000bb38(0,0x125);
    uVar2 = FUN_80020078(0xf1e);
    if (uVar2 != 0) {
      FUN_8000bb38(param_1,0x491);
    }
    *(undefined2 *)(param_1 + 2) = 4000;
    *(undefined *)(param_2 + 0x65) = 1;
    local_2c = FLOAT_803e690c;
    local_34 = 0;
    local_32 = 0;
    local_30 = 0;
    if (*(short *)(local_38 + 0x46) == 0x9a) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      iVar1 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0xa9,&local_34,0x200001,0xffffffff,0);
        iVar1 = iVar1 + 1;
      } while (iVar1 < 10);
    }
  }
  return;
}

