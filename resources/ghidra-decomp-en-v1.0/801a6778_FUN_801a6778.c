// Function: FUN_801a6778
// Entry: 801a6778
// Size: 972 bytes

void FUN_801a6778(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = FUN_8002b9ec();
  uVar2 = FUN_8002b9ec();
  if (FLOAT_803e44c0 < FLOAT_803ddb28) {
    FUN_80016870(0x34f);
    FLOAT_803ddb28 = FLOAT_803ddb28 - FLOAT_803db414;
    if (FLOAT_803ddb28 < FLOAT_803e44c0) {
      FLOAT_803ddb28 = FLOAT_803e44c0;
    }
  }
  if (*(int *)(param_1 + 0xf4) != 0) {
    FUN_800887f8(0);
    iVar3 = FUN_8001ffb4(0xd47);
    if (iVar3 == 0) {
      iVar3 = FUN_8001ffb4(0xf33);
      if (iVar3 == 0) {
        iVar1 = FUN_8005afac((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x14));
        if (iVar1 == 0x12) {
          FUN_80088c94(7,0);
          if (*(int *)(param_1 + 0xf4) == 2) {
            FUN_80008b74(param_1,uVar2,0x13a,0);
            FUN_80008b74(param_1,uVar2,0x138,0);
            FUN_80008b74(param_1,uVar2,0x139,0);
          }
          else {
            FUN_80008cbc(param_1,uVar2,0x13a,0);
            FUN_80008cbc(param_1,uVar2,0x138,0);
            FUN_80008cbc(param_1,uVar2,0x139,0);
          }
          *(undefined4 *)(param_1 + 0xf8) = 0;
        }
      }
      else {
        FUN_80088c94(7,1);
        if (*(int *)(param_1 + 0xf4) == 2) {
          FUN_80008b74(param_1,uVar2,0x13a,0);
          FUN_80008b74(param_1,uVar2,0x10c,0);
          FUN_80008b74(param_1,uVar2,0x10d,0);
        }
        else {
          FUN_80008cbc(param_1,uVar2,0x13a,0);
          FUN_80008cbc(param_1,uVar2,0x10c,0);
          FUN_80008cbc(param_1,uVar2,0x10d,0);
        }
        *(undefined4 *)(param_1 + 0xf8) = 1;
      }
    }
    else {
      FUN_80088c94(7,1);
      if (*(int *)(param_1 + 0xf4) == 2) {
        FUN_80008b74(param_1,uVar2,0x13a,0);
        FUN_80008b74(param_1,uVar2,0x234,0);
        FUN_80008b74(param_1,uVar2,0x235,0);
      }
      else {
        FUN_80008cbc(param_1,uVar2,0x13a,0);
        FUN_80008cbc(param_1,uVar2,0x234,0);
        FUN_80008cbc(param_1,uVar2,0x235,0);
      }
      *(undefined4 *)(param_1 + 0xf8) = 0;
    }
    FUN_8000a518(0x31,1);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  if ((*(int *)(param_1 + 0xf8) == 0) || (iVar1 = FUN_8001ffb4(0xf33), iVar1 != 0)) {
    if ((*(int *)(param_1 + 0xf8) == 0) && (iVar1 = FUN_8001ffb4(0xf33), iVar1 != 0)) {
      FUN_80088c94(7,1);
      FUN_80008cbc(param_1,uVar2,0x13a,0);
      FUN_80008cbc(param_1,uVar2,0x10c,0);
      FUN_80008cbc(param_1,uVar2,0x10d,0);
      *(undefined4 *)(param_1 + 0xf8) = 1;
    }
  }
  else {
    FUN_80088c94(7,0);
    FUN_80008cbc(param_1,uVar2,0x13a,0);
    FUN_80008cbc(param_1,uVar2,0x138,0);
    FUN_80008cbc(param_1,uVar2,0x139,0);
    *(undefined4 *)(param_1 + 0xf8) = 0;
  }
  FUN_801d7ed4(&DAT_803ddb2c,1,0xffffffff,0xffffffff,0x389,0xd5);
  FUN_801d7ed4(&DAT_803ddb2c,2,0xffffffff,0xffffffff,0xcbb,0xc4);
  return;
}

