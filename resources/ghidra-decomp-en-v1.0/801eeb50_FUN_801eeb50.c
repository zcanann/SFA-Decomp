// Function: FUN_801eeb50
// Entry: 801eeb50
// Size: 468 bytes

void FUN_801eeb50(int param_1,int param_2)

{
  int iVar1;
  int local_38;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  undefined auStack40 [4];
  undefined auStack36 [4];
  undefined auStack32 [20];
  
  iVar1 = FUN_80036770(param_1,&local_38,0,0,auStack40,auStack36,auStack32);
  if (((iVar1 != 0) && (iVar1 = FUN_8002ac24(param_1), iVar1 == 0)) &&
     (*(short *)(local_38 + 0x46) != 0x119)) {
    FUN_8002ac30(param_1,0xaf,200,0,0,1);
    FUN_80014aa0((double)FLOAT_803e5cb8);
    FUN_8000bb18(0,0x125);
    iVar1 = FUN_8001ffb4(0xf1e);
    if (iVar1 != 0) {
      FUN_8000bb18(param_1,0x491);
    }
    *(undefined2 *)(param_1 + 2) = 4000;
    *(undefined *)(param_2 + 0x65) = 1;
    local_2c = FLOAT_803e5c74;
    local_34 = 0;
    local_32 = 0;
    local_30 = 0;
    if (*(short *)(local_38 + 0x46) == 0x9a) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0xa8,&local_34,0x200001,0xffffffff,0);
      iVar1 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0xa9,&local_34,0x200001,0xffffffff,0);
        iVar1 = iVar1 + 1;
      } while (iVar1 < 10);
    }
  }
  return;
}

